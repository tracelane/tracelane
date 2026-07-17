"""
Pydantic v2 schemas for eval results.

All three frameworks (DeepEval, Ragas, Inspect AI) emit results that are
normalized into EvalResult before display or OTLP emission.
"""

from __future__ import annotations

import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EvalStatus(StrEnum):
    pass_ = "pass"
    fail = "fail"
    skip = "skip"
    error = "error"


class EvalResult(BaseModel):
    """Single eval case result, framework-agnostic."""

    id: str
    name: str
    status: EvalStatus
    score: float | None = None
    threshold: float | None = None
    duration_ms: int
    framework: str  # "deepeval" | "ragas" | "inspect_ai" | "vitest"
    pain_point_id: str | None = None  # e.g. "PP-G1"
    aft_id: str | None = None  # e.g. "AFT-MCP-RUGPULL-001"
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)


class EvalSuiteReport(BaseModel):
    """Aggregated report from a full eval suite run."""

    suite_id: str
    started_at: datetime.datetime
    finished_at: datetime.datetime
    total: int
    passed: int
    failed: int
    skipped: int
    errors: int
    results: list[EvalResult] = Field(default_factory=list)
    git_sha: str | None = None
    branch: str | None = None

    @property
    def pass_rate(self) -> float:
        """Fraction of non-skipped evals that passed."""
        eligible = self.total - self.skipped
        return self.passed / eligible if eligible > 0 else 0.0

    @property
    def is_green(self) -> bool:
        """True when zero failures and zero errors (skips are allowed)."""
        return self.failed == 0 and self.errors == 0
