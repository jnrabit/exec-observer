"""Audit check for functional predicate conflicts."""

from collections import defaultdict

from ossifikat.audit.view import AuditView
from ossifikat.audit.finding import AuditFinding


def find_functional_predicate_conflicts(view: AuditView) -> list[AuditFinding]:
    """Find violations of functional predicates.

    A functional predicate can have at most one value per subject.
    This check finds cases where a functional predicate has multiple
    distinct values for the same subject (among confirmed, non-retracted triples).
    """
    findings = []

    # Get functional predicates from conventions
    functional_predicates = view.get_functional_predicates()

    if not functional_predicates:
        # No functional predicates defined, no findings
        return findings

    # Get all confirmed, non-retracted triples
    all_triples = view.all_triples()
    retracted_hashes = {rt.subject for rt in view.get_retract_meta_triples()}

    confirmed_non_retracted = [
        t for t in all_triples
        if view.is_confirmed(t.content_hash)
        and t.content_hash not in retracted_hashes
    ]

    # Group by (subject, predicate) for functional predicates
    conflicts_by_group = defaultdict(lambda: defaultdict(list))

    for triple in confirmed_non_retracted:
        if triple.predicate in functional_predicates:
            group_key = (triple.subject, triple.predicate)
            conflicts_by_group[group_key][triple.object].append(triple)

    # Find groups with multiple distinct values
    for (subject, predicate), value_groups in conflicts_by_group.items():
        if len(value_groups) > 1:
            # Conflict: multiple distinct values for this (subject, predicate)
            conflicting_triples = []
            for value, triples in value_groups.items():
                for triple in triples:
                    conflicting_triples.append(
                        {
                            "object": triple.object,
                            "triple_hash": triple.content_hash,
                            "source": triple.source,
                            "created_at": triple.created_at,
                        }
                    )

            findings.append(
                AuditFinding(
                    audit_type="functional-conflict",
                    subject=f"{subject}::{predicate}",
                    predicate="has_conflict",
                    object=f"Functional predicate '{predicate}' has {len(value_groups)} distinct values for subject '{subject}'",
                    confidence=1.0,
                    details={
                        "conflict_subject": subject,
                        "conflict_predicate": predicate,
                        "conflicting_values": conflicting_triples,
                    },
                )
            )

    return findings
