"""SQLite triple store with staging layer and confirmation tracking."""

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from ossifikat.schema import Triple, Confirmation, compute_content_hash, compute_confirmation_hash

logger = logging.getLogger(__name__)


class OssifikatStore:
    """Manage a triple store with staging and confirmation workflow."""

    def __init__(self, db_path: str) -> None:
        """Open or create SQLite store and initialize schema."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables and indices if not exists, with migration support."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS triples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                source TEXT,
                staging BOOLEAN DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                content_hash TEXT NOT NULL UNIQUE
            )
            """
        )
        self._migrate_to_content_hash(cursor)

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS confirmations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                triple_hash TEXT NOT NULL,
                confirmed_by TEXT NOT NULL,
                confirmed_at TEXT NOT NULL,
                confirmation_type TEXT NOT NULL,
                confirmation_hash TEXT NOT NULL UNIQUE,
                note TEXT
            )
            """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_subject_predicate ON triples(subject, predicate)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_staging ON triples(staging)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_content_hash ON triples(content_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_confirmations_triple_hash ON confirmations(triple_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_confirmations_type ON confirmations(confirmation_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_confirmations_at ON confirmations(confirmed_at)")

        self._migrate_to_confirmations(cursor)
        self.conn.commit()

    def _migrate_to_content_hash(self, cursor: sqlite3.Cursor) -> None:
        """Migrate existing tables to include content_hash and updated created_at format."""
        cursor.execute("PRAGMA table_info(triples)")
        columns = {row[1] for row in cursor.fetchall()}

        if "content_hash" not in columns:
            logger.info("Migrating: adding content_hash column")
            cursor.execute("ALTER TABLE triples ADD COLUMN content_hash TEXT")
            self.conn.commit()

            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute("SELECT id, subject, predicate, object, source, created_at FROM triples")
            rows = cursor.fetchall()

            for row in rows:
                row_id, subject, predicate, obj, source, created_at = row
                created_at_iso = created_at if isinstance(created_at, str) else now_iso
                content_hash = compute_content_hash(subject, predicate, obj, source, created_at_iso)
                cursor.execute(
                    "UPDATE triples SET content_hash = ?, created_at = ? WHERE id = ?",
                    (content_hash, created_at_iso, row_id)
                )
            self.conn.commit()
            logger.info(f"Migrated {len(rows)} rows with content_hash")

            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_content_hash_unique ON triples(content_hash)")
            self.conn.commit()

    def _migrate_to_confirmations(self, cursor: sqlite3.Cursor) -> None:
        """Migrate existing staging=False triples to confirmation records."""
        migration_marker = "migrate_to_confirmations_v2"

        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='migration_log'"
        )
        if not cursor.fetchone():
            cursor.execute(
                """
                CREATE TABLE migration_log (
                    migration_name TEXT PRIMARY KEY,
                    executed_at TEXT NOT NULL,
                    note TEXT
                )
                """
            )
            self.conn.commit()

        cursor.execute(
            "SELECT executed_at FROM migration_log WHERE migration_name = ?",
            (migration_marker,)
        )
        if cursor.fetchone():
            logger.debug("Migration to confirmations already executed")
            return

        logger.info("Migrating: adding synthetic confirmations for staging=False triples")
        now_iso = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            "SELECT id, content_hash FROM triples WHERE staging = 0"
        )
        rows = cursor.fetchall()

        for row_id, content_hash in rows:
            confirmation_hash = compute_confirmation_hash(
                content_hash, "migration", now_iso, "manual"
            )
            cursor.execute(
                "SELECT confirmation_hash FROM confirmations WHERE confirmation_hash = ?",
                (confirmation_hash,)
            )
            if cursor.fetchone():
                continue

            cursor.execute(
                """
                INSERT INTO confirmations (triple_hash, confirmed_by, confirmed_at, confirmation_type, confirmation_hash, note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (content_hash, "migration", now_iso, "manual", confirmation_hash, "auto-migrated from staging flag")
            )

        self.conn.commit()
        cursor.execute(
            "INSERT INTO migration_log (migration_name, executed_at, note) VALUES (?, ?, ?)",
            (migration_marker, now_iso, f"Migrated {len(rows)} staging=False triples to confirmations")
        )
        self.conn.commit()
        logger.info(f"Migrated {len(rows)} triples to confirmations")

    def add_staging(
        self,
        subject: str,
        predicate: str,
        object: str,
        source: str,
        confidence: float = 1.0,
    ) -> int:
        """Add a new triple to staging. Returns existing id if duplicate hash exists."""
        created_at = datetime.now(timezone.utc).isoformat()
        content_hash = compute_content_hash(subject, predicate, object, source, created_at)

        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM triples WHERE content_hash = ?", (content_hash,))
        existing = cursor.fetchone()

        if existing:
            logger.info(f"Duplicate triple skipped, returning existing id={existing[0]}")
            return existing[0]

        cursor.execute(
            """
            INSERT INTO triples (subject, predicate, object, confidence, source, staging, created_at, content_hash)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (subject, predicate, object, confidence, source, created_at, content_hash),
        )
        self.conn.commit()
        return cursor.lastrowid

    def list_staging(self) -> list[Triple]:
        """Return all staging triples."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM triples WHERE staging = 1 ORDER BY created_at")
        return [self._row_to_triple(row) for row in cursor.fetchall()]

    def _resolve_id_to_hash(self, triple_id_or_hash: Union[int, str]) -> str:
        """Resolve triple ID or hash to content_hash. Raises if not found."""
        cursor = self.conn.cursor()

        if isinstance(triple_id_or_hash, int):
            cursor.execute("SELECT content_hash FROM triples WHERE id = ?", (triple_id_or_hash,))
        else:
            cursor.execute("SELECT content_hash FROM triples WHERE content_hash = ?", (triple_id_or_hash,))

        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Triple not found: {triple_id_or_hash}")
        return row[0]

    def confirm(
        self,
        triple_id_or_hash: Union[int, str],
        confirmed_by: str,
        confirmation_type: str = "manual",
        note: Optional[str] = None,
    ) -> None:
        """Add a confirmation record for a triple. Sets staging=False."""
        content_hash = self._resolve_id_to_hash(triple_id_or_hash)
        confirmed_at = datetime.now(timezone.utc).isoformat()
        confirmation_hash = compute_confirmation_hash(content_hash, confirmed_by, confirmed_at, confirmation_type)

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id FROM confirmations WHERE confirmation_hash = ?",
            (confirmation_hash,)
        )
        if cursor.fetchone():
            logger.info(f"Confirmation already exists, skipping: {confirmation_hash[:8]}...")
            return

        cursor.execute(
            """
            INSERT INTO confirmations (triple_hash, confirmed_by, confirmed_at, confirmation_type, confirmation_hash, note)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (content_hash, confirmed_by, confirmed_at, confirmation_type, confirmation_hash, note)
        )

        cursor.execute(
            "UPDATE triples SET staging = 0, updated_at = CURRENT_TIMESTAMP WHERE content_hash = ?",
            (content_hash,)
        )
        self.conn.commit()

    def get_confirmations(self, triple_id_or_hash: Union[int, str]) -> list[Confirmation]:
        """Get all confirmations for a triple, sorted by confirmed_at."""
        content_hash = self._resolve_id_to_hash(triple_id_or_hash)
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM confirmations WHERE triple_hash = ? ORDER BY confirmed_at",
            (content_hash,)
        )
        return [self._row_to_confirmation(row) for row in cursor.fetchall()]

    def is_confirmed(self, triple_id_or_hash: Union[int, str]) -> bool:
        """Check if a triple has at least one confirmation."""
        content_hash = self._resolve_id_to_hash(triple_id_or_hash)
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT 1 FROM confirmations WHERE triple_hash = ? LIMIT 1",
            (content_hash,)
        )
        return cursor.fetchone() is not None

    def retract(
        self,
        content_hash: str,
        reason: str,
        source: str = "user",
    ) -> Optional[int]:
        """
        Create a retract meta-triple in staging.

        Meta-triple form:
            subject = content_hash (of triple to retract)
            predicate = "retracted_at"
            object = ISO timestamp of retraction
            source = provided source

        Returns: ID of retract triple (in staging), or None if already retracted.
        """
        cursor = self.conn.cursor()

        # Check if triple exists
        cursor.execute("SELECT id FROM triples WHERE content_hash = ?", (content_hash,))
        if not cursor.fetchone():
            raise ValueError(f"Triple not found: {content_hash}")

        # Check if already retracted (confirmed retract exists)
        cursor.execute(
            """
            SELECT t.id FROM triples t
            INNER JOIN confirmations c ON t.content_hash = c.triple_hash
            WHERE t.subject = ? AND t.predicate = ? AND c.triple_hash IS NOT NULL
            LIMIT 1
            """,
            (content_hash, "retracted_at")
        )
        if cursor.fetchone():
            logger.info(f"Triple already retracted: {content_hash[:8]}...")
            return None

        # Create retract meta-triple
        retract_timestamp = datetime.now(timezone.utc).isoformat()
        retract_hash = compute_content_hash(
            content_hash, "retracted_at", retract_timestamp, source, retract_timestamp
        )

        # Check for duplicate retract proposal
        cursor.execute("SELECT id FROM triples WHERE content_hash = ?", (retract_hash,))
        existing = cursor.fetchone()
        if existing:
            logger.info(f"Retract proposal already exists: id={existing[0]}")
            return existing[0]

        # Insert retract meta-triple
        cursor.execute(
            """
            INSERT INTO triples (subject, predicate, object, confidence, source, staging, created_at, content_hash)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (content_hash, "retracted_at", retract_timestamp, 1.0, source, retract_timestamp, retract_hash)
        )
        self.conn.commit()
        retract_id = cursor.lastrowid
        logger.info(f"Retract triple created: id={retract_id}, reason={reason}")

        # Store reason temporarily (can be attached to confirmation later)
        if not hasattr(self, "_pending_retraction_reasons"):
            self._pending_retraction_reasons = {}
        self._pending_retraction_reasons[retract_id] = reason

        return retract_id

    def is_retracted(self, content_hash: str) -> bool:
        """Check if a triple has a confirmed retraction."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT 1 FROM triples t
            INNER JOIN confirmations c ON t.content_hash = c.triple_hash
            WHERE t.subject = ? AND t.predicate = ? AND c.triple_hash IS NOT NULL
            LIMIT 1
            """,
            (content_hash, "retracted_at")
        )
        return cursor.fetchone() is not None

    def get_retraction(self, content_hash: str) -> Optional[Triple]:
        """Get the confirmed retract meta-triple for a triple, or None."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT t.* FROM triples t
            INNER JOIN confirmations c ON t.content_hash = c.triple_hash
            WHERE t.subject = ? AND t.predicate = ? AND c.triple_hash IS NOT NULL
            LIMIT 1
            """,
            (content_hash, "retracted_at")
        )
        row = cursor.fetchone()
        return self._row_to_triple(row) if row else None

    def reject(self, triple_id: int) -> None:
        """Delete a triple completely."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM triples WHERE id = ?", (triple_id,))
        self.conn.commit()

    def query(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        content_hash: Optional[str] = None,
        only_confirmed: bool = True,
        include_retracted: bool = False,
    ) -> list[Triple]:
        """Query triples with optional filters. Excludes retracted triples unless include_retracted=True."""
        conditions = []
        params = []

        if subject is not None:
            conditions.append("t.subject = ?")
            params.append(subject)

        if predicate is not None:
            conditions.append("t.predicate = ?")
            params.append(predicate)

        if content_hash is not None:
            conditions.append("t.content_hash = ?")
            params.append(content_hash)

        # Exclude retracted triples unless explicitly included
        if not include_retracted:
            conditions.append("""
                t.content_hash NOT IN (
                    SELECT tr.subject FROM triples tr
                    INNER JOIN confirmations cr ON tr.content_hash = cr.triple_hash
                    WHERE tr.predicate = 'retracted_at'
                )
            """)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        if only_confirmed:
            query = f"""
                SELECT t.* FROM triples t
                INNER JOIN confirmations c ON t.content_hash = c.triple_hash
                WHERE {where_clause}
                GROUP BY t.id
                ORDER BY t.created_at
            """
        else:
            query = f"""
                SELECT * FROM triples t
                WHERE {where_clause}
                ORDER BY t.created_at
            """

        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return [self._row_to_triple(row) for row in cursor.fetchall()]

    def get_by_hash(self, content_hash: str) -> Optional[Triple]:
        """Get a triple by its content_hash. Returns None if not found."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM triples WHERE content_hash = ?", (content_hash,))
        row = cursor.fetchone()
        return self._row_to_triple(row) if row else None

    def _row_to_triple(self, row: sqlite3.Row) -> Triple:
        """Convert database row to Triple."""
        return Triple(
            id=row["id"],
            subject=row["subject"],
            predicate=row["predicate"],
            object=row["object"],
            confidence=row["confidence"],
            source=row["source"],
            staging=bool(row["staging"]),
            created_at=row["created_at"],
            updated_at=datetime.fromisoformat(row["updated_at"]),
            content_hash=row["content_hash"],
        )

    def _row_to_confirmation(self, row: sqlite3.Row) -> Confirmation:
        """Convert database row to Confirmation."""
        return Confirmation(
            id=row["id"],
            triple_hash=row["triple_hash"],
            confirmed_by=row["confirmed_by"],
            confirmed_at=row["confirmed_at"],
            confirmation_type=row["confirmation_type"],
            confirmation_hash=row["confirmation_hash"],
            note=row["note"],
        )

    def query_at(
        self,
        timestamp: str,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        content_hash: Optional[str] = None,
    ) -> list[Triple]:
        """
        Reconstruct triple state at a specific timestamp.

        - Only includes triples created before timestamp
        - Only includes confirmations from before timestamp
        - Excludes triples retracted before timestamp
        """
        conditions = [
            "t.created_at <= ?",
        ]
        params = [timestamp]

        if subject is not None:
            conditions.append("t.subject = ?")
            params.append(subject)

        if predicate is not None:
            conditions.append("t.predicate = ?")
            params.append(predicate)

        if content_hash is not None:
            conditions.append("t.content_hash = ?")
            params.append(content_hash)

        where_clause = " AND ".join(conditions)

        # Query confirmed triples at time T
        query = f"""
            SELECT DISTINCT t.* FROM triples t
            INNER JOIN confirmations c ON t.content_hash = c.triple_hash
            WHERE {where_clause}
            AND c.confirmed_at <= ?
            AND t.content_hash NOT IN (
                SELECT tr.subject FROM triples tr
                INNER JOIN confirmations cr ON tr.content_hash = cr.triple_hash
                WHERE tr.predicate = 'retracted_at' AND cr.confirmed_at <= ?
            )
            ORDER BY t.created_at
        """

        params.append(timestamp)
        params.append(timestamp)

        cursor = self.conn.cursor()
        cursor.execute(query, params)
        return [self._row_to_triple(row) for row in cursor.fetchall()]

    def close(self) -> None:
        """Close database connection."""
        self.conn.close()
