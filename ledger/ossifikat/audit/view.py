"""Read-only audit view on the store."""

import sqlite3
from pathlib import Path
from typing import Optional

from ossifikat.schema import Triple, Confirmation


class AuditView:
    """Read-only view on the store. Exposes only query methods.

    Audit modules must use this, never OssifikatStore directly.
    """

    def __init__(self, db_path: str) -> None:
        """Open read-only connection to database."""
        self.db_path = Path(db_path)
        # SQLite read-only mode via file URI
        connection_string = f"file:{self.db_path}?mode=ro"
        self.conn = sqlite3.connect(connection_string, uri=True, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def all_triples(self) -> list[Triple]:
        """Get all triples in the store."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM triples ORDER BY created_at")
        return [self._row_to_triple(row) for row in cursor.fetchall()]

    def all_confirmations(self) -> list[Confirmation]:
        """Get all confirmations in the store."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM confirmations ORDER BY confirmed_at")
        return [self._row_to_confirmation(row) for row in cursor.fetchall()]

    def get_triple_by_hash(self, content_hash: str) -> Optional[Triple]:
        """Get a triple by its content_hash. Returns None if not found."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM triples WHERE content_hash = ?", (content_hash,))
        row = cursor.fetchone()
        return self._row_to_triple(row) if row else None

    def is_confirmed(self, content_hash: str) -> bool:
        """Check if a triple has at least one confirmation."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT 1 FROM confirmations WHERE triple_hash = ? LIMIT 1",
            (content_hash,)
        )
        return cursor.fetchone() is not None

    def get_retract_meta_triples(self) -> list[Triple]:
        """Get all triples with predicate='retracted_at' (retract meta-triples)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM triples WHERE predicate = 'retracted_at' ORDER BY created_at"
        )
        return [self._row_to_triple(row) for row in cursor.fetchall()]

    def get_predicates_by_cardinality(self, cardinality: str) -> set[str]:
        """Get all predicates classified with a given cardinality.

        Returns predicate names that have a ratified (confirmed, not retracted)
        has_cardinality triple with the given cardinality value.
        """
        cursor = self.conn.cursor()
        # Get convention triples: has_cardinality with given cardinality
        cursor.execute(
            """
            SELECT DISTINCT t.subject FROM triples t
            INNER JOIN confirmations c ON t.content_hash = c.triple_hash
            WHERE t.predicate = 'has_cardinality'
            AND t.object = ?
            AND t.content_hash NOT IN (
                SELECT tr.subject FROM triples tr
                INNER JOIN confirmations cr ON tr.content_hash = cr.triple_hash
                WHERE tr.predicate = 'retracted_at'
            )
            """,
            (cardinality,)
        )
        return {row[0] for row in cursor.fetchall()}

    def get_functional_predicates(self) -> set[str]:
        """Get predicates classified as functional."""
        return self.get_predicates_by_cardinality("functional")

    def get_predicate_usage(self) -> dict[str, int]:
        """Get usage count per predicate from confirmed, non-retracted triples.

        Returns a dict mapping predicate names to counts.
        Meta-triples (has_cardinality, retracted_at, etc.) count as well
        since they are also predicates that could be classified.
        """
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT t.predicate, COUNT(*) as count FROM triples t
            INNER JOIN confirmations c ON t.content_hash = c.triple_hash
            WHERE t.content_hash NOT IN (
                SELECT tr.subject FROM triples tr
                INNER JOIN confirmations cr ON tr.content_hash = cr.triple_hash
                WHERE tr.predicate = 'retracted_at'
            )
            GROUP BY t.predicate
            """
        )
        return {row[0]: row[1] for row in cursor.fetchall()}

    def _row_to_triple(self, row: sqlite3.Row) -> Triple:
        """Convert database row to Triple."""
        from datetime import datetime
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

    def close(self) -> None:
        """Close database connection."""
        self.conn.close()
