"""Audit check for unclassified predicates."""

from ossifikat.audit.view import AuditView
from ossifikat.audit.finding import AuditFinding

# Minimum usage count for a predicate to warrant a reminder
MIN_USAGE_THRESHOLD = 3

# System predicates that don't need classification
# - has_cardinality: meta-predicate for conventions, would be circular to classify
# - retracted_at: system predicate for retraction, has special semantics
# - has_conflict: produced by audit checks, doesn't need classification
# - is_orphan_retract: produced by audit checks, doesn't need classification
SYSTEM_PREDICATES = {"has_cardinality", "retracted_at", "has_conflict", "is_orphan_retract"}


def find_unclassified_predicates(view: AuditView) -> list[AuditFinding]:
    """Find predicates that are used frequently but lack cardinality classification.

    This is a reminder check: confidence is low (0.4) because it's not a logical
    inconsistency, but a hint that conventions may be incomplete.
    """
    findings = []

    # Get all predicates and their usage
    predicate_usage = view.get_predicate_usage()

    # Get classified predicates (currently only functional, extensible)
    functional_predicates = view.get_functional_predicates()
    classified_predicates = functional_predicates  # Can extend with other classes

    # Check each predicate
    for predicate_name, usage_count in predicate_usage.items():
        # Skip system predicates
        if predicate_name in SYSTEM_PREDICATES:
            continue

        # Skip already classified predicates
        if predicate_name in classified_predicates:
            continue

        # Skip low-usage predicates
        if usage_count < MIN_USAGE_THRESHOLD:
            continue

        # Found an unclassified high-usage predicate
        findings.append(
            AuditFinding(
                audit_type="unclassified-predicate",
                subject=predicate_name,
                predicate="lacks_cardinality_classification",
                object=f"Predicate '{predicate_name}' is used {usage_count} times but has no cardinality classification",
                confidence=0.4,
                details={
                    "predicate_name": predicate_name,
                    "usage_count": usage_count,
                },
            )
        )

    # Sort by usage count descending (most important first)
    findings.sort(key=lambda f: f.details["usage_count"], reverse=True)

    return findings
