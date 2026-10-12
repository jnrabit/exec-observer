"""Audit check for orphaned retract meta-triples."""

from ossifikat.audit.view import AuditView
from ossifikat.audit.finding import AuditFinding


def find_orphan_retracts(view: AuditView) -> list[AuditFinding]:
    """Find retract meta-triples whose referenced triple doesn't exist.

    A retract triple has predicate='retracted_at' and subject=<content_hash>.
    If no triple with content_hash=<subject> exists, the retract is orphaned.
    """
    findings = []

    for retract_triple in view.get_retract_meta_triples():
        referenced_hash = retract_triple.subject

        if view.get_triple_by_hash(referenced_hash) is None:
            findings.append(
                AuditFinding(
                    audit_type="orphan-retract",
                    subject=retract_triple.content_hash,
                    predicate="is_orphan_retract",
                    object=f"Retract references missing triple {referenced_hash[:12]}...",
                    confidence=1.0,
                    details={
                        "missing_hash": referenced_hash,
                        "retract_triple_hash": retract_triple.content_hash,
                        "retract_created_at": retract_triple.created_at,
                    },
                )
            )

    return findings
