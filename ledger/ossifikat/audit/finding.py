"""Audit finding data structure."""

from dataclasses import dataclass, field


@dataclass
class AuditFinding:
    """Result of an audit check. In-memory object, written to store via CLI caller."""

    audit_type: str  # e.g. "orphan-retract"
    subject: str  # content_hash of affected triple or synthetic identifier
    predicate: str  # e.g. "is_orphan_retract"
    object: str  # human-readable description
    confidence: float  # 0.0–1.0
    details: dict = field(default_factory=dict)  # structured info for debugging

    def __repr__(self) -> str:
        return (
            f"AuditFinding(type={self.audit_type}, confidence={self.confidence:.2f}, "
            f"subject={self.subject[:8]}..., object={self.object[:40]}...)"
        )
