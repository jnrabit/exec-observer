"""Audit infrastructure for Ossifikat.

IMPORTANT: Audit modules MUST NOT import OssifikatStore.
They use AuditView (read-only) exclusively.
Writes happen via the CLI caller, which mediates between
audit output and store ingestion.
"""

from ossifikat.audit.view import AuditView
from ossifikat.audit.finding import AuditFinding
from ossifikat.audit.checks.orphan_retracts import find_orphan_retracts
from ossifikat.audit.checks.functional_conflicts import find_functional_predicate_conflicts
from ossifikat.audit.checks.unclassified_predicates import find_unclassified_predicates

__all__ = [
    "AuditView",
    "AuditFinding",
    "find_orphan_retracts",
    "find_functional_predicate_conflicts",
    "find_unclassified_predicates",
]
