"""
CLI entry point for the eval orchestrator.

Invoked as:
    tracelane-eval [OPTIONS]
    tlane eval [OPTIONS]           (delegates here via the tlane CLI)

Options:
    --watch       Live re-run on file change (Braintrust-style)
    --suite TEXT  Run only this suite (pain-points | fault-tolerance | all)
    --id TEXT     Run only the eval with this ID
    --json        Output JSON report instead of rich table
"""

from __future__ import annotations

import asyncio
import sys

import click
from rich.console import Console

from orchestrator.models import EvalSuiteReport
from orchestrator.otel import init_otel
from orchestrator.runner import EvalRunner

console = Console()


@click.command()
@click.option("--watch", is_flag=True, default=False, help="Re-run on file change")
@click.option(
    "--suite",
    default="all",
    type=click.Choice(["pain-points", "fault-tolerance", "deepeval", "ragas", "inspect-ai", "all"]),
    help="Which suite to run",
)
@click.option("--id", "eval_id", default=None, help="Run a single eval by ID")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output JSON report")
@click.option("--otlp-endpoint", default=None, envvar="OTEL_EXPORTER_OTLP_ENDPOINT")
def main(
    watch: bool,
    suite: str,
    eval_id: str | None,
    as_json: bool,
    otlp_endpoint: str | None,
) -> None:
    """Run the Tracelane eval suite."""
    init_otel(otlp_endpoint)

    runner = EvalRunner(emit_spans=otlp_endpoint is not None)

    if watch:
        from orchestrator.watch import WatchMode

        asyncio.run(WatchMode(runner).run())
        return

    report: EvalSuiteReport = asyncio.run(runner.run_suite())

    if as_json:
        click.echo(report.model_dump_json(indent=2))
    else:
        _print_report(report)

    if not report.is_green:
        sys.exit(1)


def _print_report(report: EvalSuiteReport) -> None:
    from rich.table import Table

    colour = "green" if report.is_green else "red"
    console.print(
        f"\n[bold {colour}]{'PASS' if report.is_green else 'FAIL'}[/bold {colour}] "
        f"{report.passed}/{report.total} evals passed "
        f"({report.skipped} skipped, {report.failed} failed, {report.errors} errors)"
    )

    if report.failed > 0 or report.errors > 0:
        table = Table(title="Failures")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("Reason")

        for r in report.results:
            if r.status.value in ("fail", "error"):
                table.add_row(r.id, r.name, r.status.value, r.reason or "")

        console.print(table)

    console.print(f"\nGit: {report.git_sha or 'unknown'} @ {report.branch or 'unknown'}\n")
