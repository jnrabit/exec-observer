"""CLI for interactive triple review, ingestion, and auditing."""

import getpass

import click

from ossifikat.extractor import QwenExtractor
from ossifikat.store import OssifikatStore
from ossifikat.audit import (
    AuditView,
    find_orphan_retracts,
    find_functional_predicate_conflicts,
    find_unclassified_predicates,
)


@click.group()
def cli() -> None:
    """Ossifikat — Knowledge Triple-Store."""
    pass


@cli.command()
@click.option("--db", default="data/ossifikat.db", help="Database path")
@click.option("--confirmed-by", default=None, help="Confirmer name (default: current user)")
def review(db: str, confirmed_by: str) -> None:
    """Review and confirm staging triples."""
    store = OssifikatStore(db)
    staging = store.list_staging()

    if not staging:
        click.echo("No staging triples.")
        store.close()
        return

    if not confirmed_by:
        confirmed_by = getpass.getuser()

    click.echo(f"Found {len(staging)} staging triple(s).\n")

    for triple in staging:
        click.echo(f"  {triple.subject} {triple.predicate} {triple.object}")
        click.echo(f"  Source: {triple.source} | Confidence: {triple.confidence}")
        click.echo(f"  ID: {triple.id} | Created: {triple.created_at}")

        while True:
            response = click.prompt("  Confirm? [y/n/skip]").lower()
            if response == "y":
                store.confirm(triple.id, confirmed_by=confirmed_by, confirmation_type="manual")
                click.echo("  → Confirmed.\n")
                break
            elif response == "n":
                store.reject(triple.id)
                click.echo("  → Rejected.\n")
                break
            elif response == "skip":
                click.echo("  → Skipped.\n")
                break
            else:
                click.echo("  Invalid input. Try y/n/skip.")

    store.close()
    click.echo("Review complete.")


@cli.command()
@click.option("--db", default="data/ossifikat.db", help="Database path")
@click.option("--source", default="qwen-extractor", help="Triple source name")
@click.option("--model", default="qwen2.5-coder:7b", help="Ollama model")
@click.option("--ollama-url", default="http://localhost:11434", help="Ollama API URL")
def ingest(db: str, source: str, model: str, ollama_url: str) -> None:
    """Extract and ingest triples from stdin text."""
    text = click.get_text_stream("stdin").read()

    if not text.strip():
        click.echo("No input received.", err=True)
        return

    extractor = QwenExtractor(model=model, ollama_url=ollama_url)
    store = OssifikatStore(db)

    ids = extractor.extract_and_stage(text, store, source=source)

    click.echo(f"Ingested {len(ids)} triple(s) into staging.")
    store.close()


@cli.command()
@click.argument("triple_id_or_hash")
@click.option("--db", default="data/ossifikat.db", help="Database path")
def history(triple_id_or_hash: str, db: str) -> None:
    """Show confirmation and retraction history for a triple."""
    store = OssifikatStore(db)

    try:
        triple_id = int(triple_id_or_hash)
        content_hash = store._resolve_id_to_hash(triple_id)
        triple = store.get_by_hash(content_hash)
    except ValueError:
        content_hash = triple_id_or_hash
        triple = store.get_by_hash(content_hash)

    if not triple:
        click.echo(f"Triple not found: {triple_id_or_hash}", err=True)
        store.close()
        return

    click.echo(f"\nTriple {triple.id} (hash: {triple.content_hash[:16]}...)")
    click.echo(f"  {triple.subject} {triple.predicate} {triple.object}")
    click.echo(f"  Source: {triple.source} | Confidence: {triple.confidence}\n")

    confirmations = store.get_confirmations(triple.id)
    if not confirmations:
        click.echo("  (No confirmations yet)")
    else:
        for conf in confirmations:
            click.echo(f"  ✓ confirmed {conf.confirmed_at} by {conf.confirmed_by} ({conf.confirmation_type})")
            if conf.note:
                click.echo(f"      note: {conf.note}")

    retraction = store.get_retraction(triple.content_hash)
    if retraction:
        ret_confirmations = store.get_confirmations(retraction.id)
        if ret_confirmations:
            conf = ret_confirmations[0]
            click.echo(f"\n  ✗ retracted {retraction.object} by {conf.confirmed_by}")
            if conf.note:
                click.echo(f"      reason: {conf.note}")

    click.echo()
    store.close()


@cli.command()
@click.argument("triple_id_or_hash")
@click.option("--db", default="data/ossifikat.db", help="Database path")
@click.option("--reason", required=True, help="Retraction reason")
@click.option("--source", default="user", help="Retraction source")
def retract(triple_id_or_hash: str, db: str, reason: str, source: str) -> None:
    """Create a retraction proposal for a triple."""
    store = OssifikatStore(db)

    try:
        triple_id = int(triple_id_or_hash)
        content_hash = store._resolve_id_to_hash(triple_id)
    except ValueError:
        content_hash = triple_id_or_hash

    try:
        retract_id = store.retract(content_hash, reason=reason, source=source)
        if retract_id:
            click.echo(f"Retraction proposal created (ID: {retract_id})")
            click.echo("Use 'ossifikat review' to confirm the retraction.")
        else:
            click.echo("Triple already retracted.", err=True)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)

    store.close()


@cli.group()
def audit() -> None:
    """Audit the triple store for consistency issues."""
    pass


# Audit type registry
AUDIT_CHECKS = {
    "orphan-retract": find_orphan_retracts,
    "functional-conflict": find_functional_predicate_conflicts,
    "unclassified-predicate": find_unclassified_predicates,
}


@audit.command()
@click.option("--db", default="data/ossifikat.db", help="Database path")
@click.option(
    "--type",
    "audit_type",
    default="orphan-retract",
    type=click.Choice(list(AUDIT_CHECKS.keys()) + ["all"]),
    help="Audit check type",
)
@click.option("--dry-run/--write", default=True, help="Dry-run mode (default) or write findings")
def run(db: str, audit_type: str, dry_run: bool) -> None:
    """Run audit checks on the store."""
    types_to_run = (
        list(AUDIT_CHECKS.keys()) if audit_type == "all" else [audit_type]
    )

    view = AuditView(db)
    all_findings = []

    for audit_check_type in types_to_run:
        click.echo(f"Running audit: {audit_check_type}")
        check_func = AUDIT_CHECKS[audit_check_type]
        findings = check_func(view)
        all_findings.extend(findings)

        click.echo(f"Found {len(findings)} finding(s).")

        if findings:
            click.echo()
            for finding in findings:
                _print_finding(finding)
        else:
            click.echo("No findings. Store is consistent for this check.")
        click.echo()

    view.close()

    if not all_findings:
        click.echo("All checks passed.")
        return

    if dry_run:
        click.echo(
            f"Dry-run mode. {len(all_findings)} finding(s) total. "
            "Use --write to ingest findings as staging triples."
        )
        return

    # Write findings to store
    click.echo(f"Writing {len(all_findings)} finding(s) to staging...")
    store = OssifikatStore(db)

    for finding in all_findings:
        store.add_staging(
            subject=finding.subject,
            predicate=finding.predicate,
            object=finding.object,
            source=f"audit-{finding.audit_type}",
            confidence=finding.confidence,
        )

    store.close()
    click.echo(f"✓ Ingested {len(all_findings)} audit finding(s) into staging.")
    click.echo("Use 'ossifikat review' to confirm or reject them.")


def _print_finding(finding) -> None:
    """Pretty-print an audit finding."""
    click.echo(f"  [{finding.audit_type}] confidence={finding.confidence:.2f}")
    click.echo(f"    {finding.object}")

    # Handle complex details for functional conflicts
    if finding.audit_type == "functional-conflict":
        if "conflicting_values" in finding.details:
            click.echo("    Conflicting values:")
            for val_info in finding.details["conflicting_values"]:
                click.echo(
                    f"      - \"{val_info['object']}\" "
                    f"(source={val_info['source']}, created={val_info['created_at'][:10]})"
                )
                click.echo(f"        hash={val_info['triple_hash'][:12]}...")
    elif finding.details:
        detail_str = ", ".join(
            f"{k}={v[:12]}..." if isinstance(v, str) and len(v) > 12 else f"{k}={v}"
            for k, v in finding.details.items()
        )
        click.echo(f"    Details: {detail_str}")

    click.echo()


if __name__ == "__main__":
    cli()
