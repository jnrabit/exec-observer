"""Triple schema definition."""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class Triple:
    """A single fact: subject-predicate-object with metadata."""

    id: int
    subject: str
    predicate: str
    object: str
    confidence: float
    source: str
    staging: bool
    created_at: str
    updated_at: datetime
    content_hash: str

    def __repr__(self) -> str:
        status = "staging" if self.staging else "confirmed"
        return (
            f"Triple({self.id}, {self.subject} {self.predicate} {self.object} "
            f"[{status}, conf={self.confidence}, src={self.source}, hash={self.content_hash[:8]}...])"
        )


def compute_content_hash(
    subject: str, predicate: str, object: str, source: str, created_at: str
) -> str:
    """Compute SHA256 content hash for triple. Covers what was claimed, by whom, when."""
    payload = f"{subject}|{predicate}|{object}|{source}|{created_at}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class Confirmation:
    """Record of ratification for a triple."""

    id: int
    triple_hash: str
    confirmed_by: str
    confirmed_at: str
    confirmation_type: str
    confirmation_hash: str
    note: str | None = None

    def __repr__(self) -> str:
        by_type = f"{self.confirmed_by} ({self.confirmation_type})"
        return f"Confirmation(id={self.id}, hash={self.confirmation_hash[:8]}..., at={self.confirmed_at}, by={by_type})"


def compute_confirmation_hash(
    triple_hash: str, confirmed_by: str, confirmed_at: str, confirmation_type: str
) -> str:
    """Compute SHA256 confirmation hash. Makes each ratification append-only."""
    payload = f"{triple_hash}|{confirmed_by}|{confirmed_at}|{confirmation_type}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
