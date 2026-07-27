"""
EvalRunner — unified entrypoint over DeepEval, Ragas, and Inspect AI.

Design goals:
- Single `runner.run_suite()` call runs all three frameworks in order.
- Results are normalized to EvalResult before return.
- No live LLM calls in CI — frameworks are configured to use fixtures.
- Every result is emitted as an OTLP span linked to the agent state graph.
- `runner.run_single(id)` supports selective re-runs for --watch mode.

Framework adapters:
  _run_deepeval()    — metric-level assertions (answer relevancy, faithfulness, …)
  _run_ragas()       — RAG pipeline metrics (context recall, precision, …)
  _run_inspect_ai()  — task-level agent evals (UK AISI pattern)
"""

from __future__ import annotations

import asyncio
import datetime
import subprocess
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import structlog

from orchestrator.models import EvalResult, EvalStatus, EvalSuiteReport
from orchestrator.otel import emit_eval_span

log = structlog.get_logger()

REPO_ROOT = Path(__file__).parents[2]
PAIN_POINTS_DIR = REPO_ROOT / "evals" / "pain-points"
FAULT_TOL_DIR = REPO_ROOT / "evals" / "fault-tolerance"


class EvalRunner:
    """Runs the full eval suite or individual cases across all frameworks."""

    def __init__(
        self,
        *,
        emit_spans: bool = True,
        fixture_mode: bool = True,
        on_result: Callable[[EvalResult], None] | None = None,
    ) -> None:
        self._emit_spans = emit_spans
        self._fixture_mode = fixture_mode
        self._on_result = on_result  # called after each result (used by WatchMode)

    async def run_suite(self) -> EvalSuiteReport:
        """Run all evals and return an aggregated report."""
        suite_id = str(uuid.uuid4())
        started_at = datetime.datetime.utcnow()
        results: list[EvalResult] = []

        log.info("eval_suite.start", suite_id=suite_id)

        # 1. TypeScript pain-point evals (vitest — subprocess)
        results.extend(await self._run_vitest("pain-points"))

        # 2. TypeScript fault-tolerance evals (vitest — subprocess)
        results.extend(await self._run_vitest("fault-tolerance"))

        # 3. DeepEval metric assertions
        results.extend(await self._run_deepeval())

        # 4. Ragas RAG pipeline metrics
        results.extend(await self._run_ragas())

        # 5. Inspect AI task evals
        results.extend(await self._run_inspect_ai())

        finished_at = datetime.datetime.utcnow()

        report = EvalSuiteReport(
            suite_id=suite_id,
            started_at=started_at,
            finished_at=finished_at,
            total=len(results),
            passed=sum(1 for r in results if r.status == EvalStatus.pass_),
            failed=sum(1 for r in results if r.status == EvalStatus.fail),
            skipped=sum(1 for r in results if r.status == EvalStatus.skip),
            errors=sum(1 for r in results if r.status == EvalStatus.error),
            results=results,
            git_sha=_git_sha(),
            branch=_git_branch(),
        )

        log.info(
            "eval_suite.complete",
            suite_id=suite_id,
            passed=report.passed,
            failed=report.failed,
            skipped=report.skipped,
            is_green=report.is_green,
        )
        return report

    async def run_single(self, eval_id: str) -> EvalResult | None:
        """Re-run a single eval by ID. Used by WatchMode on file change."""
        all_results = await self.run_suite()
        return next((r for r in all_results.results if r.id == eval_id), None)

    # ------------------------------------------------------------------
    # Framework adapters
    # ------------------------------------------------------------------

    async def _run_vitest(self, suite: str) -> list[EvalResult]:
        """Run a TypeScript vitest suite via subprocess, parse JSON reporter output."""
        suite_dir = REPO_ROOT / "evals" / suite
        if not suite_dir.exists():
            return []

        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                "pnpm",
                "vitest",
                "run",
                "--reporter=json",
                str(suite_dir),
                cwd=str(REPO_ROOT / "evals"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            # pnpm/node not on PATH in this environment — treat as "framework
            # not installed", matching the graceful-degradation contract of the
            # deepeval/ragas/inspect_ai adapters above. run_suite() must still
            # return a valid EvalSuiteReport (see test_runner_returns_suite_report).
            log.warning("vitest.pnpm_not_found", suite=suite)
            return []
        stdout, _ = await proc.communicate()
        duration_ms = int((time.monotonic() - t0) * 1000)

        results = _parse_vitest_json(stdout.decode(errors="replace"), suite, duration_ms)
        for r in results:
            if self._on_result:
                self._on_result(r)
            if self._emit_spans:
                emit_eval_span(r)
        return results

    async def _run_deepeval(self) -> list[EvalResult]:
        """
        Run DeepEval metric assertions.

        In fixture_mode (CI), uses pre-recorded outputs from orchestrator/fixtures/.
        Returns empty list until fixtures are recorded (Week 7 milestone).
        """
        try:
            from deepeval import evaluate  # noqa: F401
        except ImportError:
            log.warning("deepeval.not_installed")
            return []

        # DeepEval test cases are defined in orchestrator/deepeval_cases.py
        cases_path = Path(__file__).parent / "deepeval_cases.py"
        if not cases_path.exists():
            return []

        return await _run_in_executor(_exec_deepeval_cases, cases_path, self._fixture_mode)

    async def _run_ragas(self) -> list[EvalResult]:
        """
        Run Ragas RAG pipeline metrics.

        Covers: answer_relevancy, faithfulness, context_recall, context_precision.
        Fixture mode uses pre-recorded dataset from orchestrator/fixtures/ragas_dataset.json.
        """
        try:
            from ragas import evaluate as ragas_evaluate  # noqa: F401
        except ImportError:
            log.warning("ragas.not_installed")
            return []

        dataset_path = Path(__file__).parent / "fixtures" / "ragas_dataset.json"
        if not dataset_path.exists():
            return []

        return await _run_in_executor(_exec_ragas_eval, dataset_path)

    async def _run_inspect_ai(self) -> list[EvalResult]:
        """
        Run Inspect AI task evals.

        Tasks defined in orchestrator/inspect_tasks/. Each task is a Python
        file with a @task decorator following the UK AISI pattern.
        """
        try:
            from inspect_ai import eval as inspect_eval  # noqa: F401
        except ImportError:
            log.warning("inspect_ai.not_installed")
            return []

        tasks_dir = Path(__file__).parent / "inspect_tasks"
        if not tasks_dir.exists():
            return []

        return await _run_in_executor(_exec_inspect_tasks, tasks_dir, self._fixture_mode)


# ------------------------------------------------------------------
# Framework exec helpers (blocking — run via executor)
# ------------------------------------------------------------------


def _exec_deepeval_cases(cases_path: Path, fixture_mode: bool) -> list[EvalResult]:
    """Execute deepeval_cases.py and collect results."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("deepeval_cases", cases_path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]

    cases = getattr(mod, "TEST_CASES", [])
    results = []
    for case in cases:
        t0 = time.monotonic()
        try:
            passed = case.run(fixture_mode=fixture_mode)
            status = EvalStatus.pass_ if passed else EvalStatus.fail
        except Exception as exc:
            status = EvalStatus.error
            log.error("deepeval.case_error", name=case.name, exc=str(exc))
        results.append(
            EvalResult(
                id=f"deepeval/{case.name}",
                name=case.name,
                status=status,
                duration_ms=int((time.monotonic() - t0) * 1000),
                framework="deepeval",
            )
        )
    return results


def _exec_ragas_eval(dataset_path: Path) -> list[EvalResult]:
    """Execute ragas evaluation against a fixture dataset."""
    import json

    from datasets import Dataset  # type: ignore[import]
    from ragas import evaluate
    from ragas.metrics import answer_relevancy, context_precision, context_recall, faithfulness

    data = json.loads(dataset_path.read_text())
    dataset = Dataset.from_dict(data)

    t0 = time.monotonic()
    result = evaluate(
        dataset,
        metrics=[faithfulness, answer_relevancy, context_recall, context_precision],
    )
    duration_ms = int((time.monotonic() - t0) * 1000)

    scores = result.to_pandas().mean().to_dict()
    results = []
    for metric_name, score in scores.items():
        threshold = 0.7
        results.append(
            EvalResult(
                id=f"ragas/{metric_name}",
                name=metric_name,
                status=EvalStatus.pass_ if score >= threshold else EvalStatus.fail,
                score=float(score),
                threshold=threshold,
                duration_ms=duration_ms // len(scores),
                framework="ragas",
            )
        )
    return results


def _exec_inspect_tasks(tasks_dir: Path, fixture_mode: bool) -> list[EvalResult]:
    """Execute all Inspect AI tasks in tasks_dir."""
    import importlib.util

    results = []
    for task_file in sorted(tasks_dir.glob("*.py")):
        if task_file.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(task_file.stem, task_file)
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(mod)  # type: ignore[union-attr]

        run_fn = getattr(mod, "run_eval", None)
        if run_fn is None:
            continue

        t0 = time.monotonic()
        try:
            passed = run_fn(fixture_mode=fixture_mode)
            status = EvalStatus.pass_ if passed else EvalStatus.fail
        except Exception as exc:
            status = EvalStatus.error
            log.error("inspect_ai.task_error", task=task_file.stem, exc=str(exc))
        results.append(
            EvalResult(
                id=f"inspect_ai/{task_file.stem}",
                name=task_file.stem,
                status=status,
                duration_ms=int((time.monotonic() - t0) * 1000),
                framework="inspect_ai",
            )
        )
    return results


async def _run_in_executor(fn, *args) -> list[EvalResult]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, *args)


# ------------------------------------------------------------------
# Vitest JSON output parser
# ------------------------------------------------------------------


def _parse_vitest_json(raw: str, suite: str, total_duration_ms: int) -> list[EvalResult]:
    """Parse vitest --reporter=json output into EvalResult list."""
    import json

    results: list[EvalResult] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # vitest output may include non-JSON prefix lines
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        else:
            return results

    test_results = data.get("testResults", [])
    for file_result in test_results:
        file_path = file_result.get("name", "")
        for assertion in file_result.get("assertionResults", []):
            name = " > ".join(
                filter(
                    None,
                    [
                        assertion.get("ancestorTitles", [""])[0],
                        assertion.get("title", ""),
                    ],
                )
            )
            raw_status = assertion.get("status", "failed")
            if raw_status == "passed":
                status = EvalStatus.pass_
            elif raw_status == "pending":
                status = EvalStatus.skip
            else:
                status = EvalStatus.fail

            pain_point_id = _extract_pp_id(file_path)
            # Vitest emits `duration` as a float (sub-ms precision).
            # EvalResult.duration_ms is typed as int and pydantic v2.13+
            # rejects floats with non-zero fractional parts, so round
            # explicitly here.
            results.append(
                EvalResult(
                    id=f"{suite}/{pain_point_id or name}",
                    name=name,
                    status=status,
                    duration_ms=round(assertion.get("duration", 0) or 0),
                    framework="vitest",
                    pain_point_id=pain_point_id,
                )
            )
    return results


def _extract_pp_id(file_path: str) -> str | None:
    """Extract PP-G1, FT-02, etc. from a file path."""
    import re

    m = re.search(r"(PP-[A-Z0-9]+|FT-\d+)", file_path)
    return m.group(1) if m else None


# ------------------------------------------------------------------
# Git helpers
# ------------------------------------------------------------------


def _git_sha() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT),
            text=True,
        ).strip()
    except Exception:
        return None


def _git_branch() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(REPO_ROOT),
            text=True,
        ).strip()
    except Exception:
        return None
