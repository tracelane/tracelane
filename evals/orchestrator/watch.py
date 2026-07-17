"""
WatchMode — Braintrust-style live eval updates.

Watches evals/ for file changes and re-runs the affected suite on each
save. Renders a live Rich table to the terminal showing pass/fail/skip
counts and per-eval status in real time.

Usage (via CLI):
    tlane eval --watch
    tracelane-eval --watch
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.live import Live
from rich.table import Table

from orchestrator.models import EvalResult, EvalStatus

if TYPE_CHECKING:
    from orchestrator.runner import EvalRunner

WATCH_DIRS = [
    "evals/pain-points",
    "evals/fault-tolerance",
    "evals/orchestrator",
]

console = Console()


class WatchMode:
    """File-watch loop that re-runs evals on change and renders live output."""

    def __init__(self, runner: EvalRunner) -> None:
        self._runner = runner
        self._results: dict[str, EvalResult] = {}
        self._last_run_at: float = 0.0

    async def run(self) -> None:
        """Block until Ctrl-C, re-running evals on each file change."""
        repo_root = Path(__file__).parents[2]
        watched = [repo_root / d for d in WATCH_DIRS]

        console.print("[bold green]Tracelane eval --watch[/bold green]")
        console.print(f"Watching: {', '.join(WATCH_DIRS)}")
        console.print("Press Ctrl-C to stop.\n")

        # Initial run
        await self._do_run()

        with Live(self._render_table(), refresh_per_second=4, console=console) as live:
            mtimes: dict[Path, float] = {}

            while True:
                changed = False
                for watch_dir in watched:
                    if not watch_dir.exists():
                        continue
                    for path in watch_dir.rglob("*"):
                        if not path.is_file():
                            continue
                        mtime = path.stat().st_mtime
                        if mtimes.get(path) != mtime:
                            mtimes[path] = mtime
                            changed = True

                if changed and time.monotonic() - self._last_run_at > 1.0:
                    await self._do_run()
                    live.update(self._render_table())

                await asyncio.sleep(0.5)

    async def _do_run(self) -> None:
        self._last_run_at = time.monotonic()
        runner = self._runner

        def on_result(r: EvalResult) -> None:
            self._results[r.id] = r

        runner._on_result = on_result
        await runner.run_suite()

    def _render_table(self) -> Table:
        results = list(self._results.values())
        passed = sum(1 for r in results if r.status == EvalStatus.pass_)
        failed = sum(1 for r in results if r.status == EvalStatus.fail)
        skipped = sum(1 for r in results if r.status == EvalStatus.skip)

        table = Table(title=f"Eval suite — {passed} pass  {failed} fail  {skipped} skip")
        table.add_column("ID", style="dim", width=20)
        table.add_column("Name", width=40)
        table.add_column("Status", width=8)
        table.add_column("ms", justify="right", width=6)

        for r in sorted(results, key=lambda x: x.id):
            status_str = {
                EvalStatus.pass_: "[green]PASS[/green]",
                EvalStatus.fail: "[red]FAIL[/red]",
                EvalStatus.skip: "[yellow]SKIP[/yellow]",
                EvalStatus.error: "[red bold]ERR[/red bold]",
            }[r.status]
            table.add_row(r.id[:20], r.name[:40], status_str, str(r.duration_ms))

        return table
