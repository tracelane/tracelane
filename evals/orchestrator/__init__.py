"""
Tracelane eval orchestrator.

Wraps DeepEval, Ragas, and Inspect AI behind a unified API so all three
can be run from a single `tlane eval` command or GitHub Actions job.

Entry points:
  orchestrator.runner  — EvalRunner (run_suite, run_single)
  orchestrator.watch   — WatchMode (live Braintrust-style updates)
  orchestrator.models  — Pydantic schemas (EvalResult, EvalSuiteReport)
  orchestrator.cli     — Click CLI (tracelane-eval command)
"""

from orchestrator.models import EvalResult, EvalStatus, EvalSuiteReport
from orchestrator.runner import EvalRunner

__all__ = ["EvalResult", "EvalRunner", "EvalStatus", "EvalSuiteReport"]
