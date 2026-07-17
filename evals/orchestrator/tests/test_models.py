"""Tests for EvalResult and EvalSuiteReport models."""

import datetime

from orchestrator.models import EvalResult, EvalStatus, EvalSuiteReport


def _make_result(status: EvalStatus, name: str = "test") -> EvalResult:
    return EvalResult(
        id=f"test/{name}",
        name=name,
        status=status,
        duration_ms=10,
        framework="vitest",
    )


def test_eval_result_pass():
    r = _make_result(EvalStatus.pass_)
    assert r.status == EvalStatus.pass_
    assert r.score is None


def test_eval_result_with_score():
    r = EvalResult(
        id="ragas/faithfulness",
        name="faithfulness",
        status=EvalStatus.pass_,
        score=0.92,
        threshold=0.7,
        duration_ms=500,
        framework="ragas",
    )
    assert r.score == 0.92
    assert r.score >= r.threshold


def test_suite_report_is_green():
    now = datetime.datetime.utcnow()
    report = EvalSuiteReport(
        suite_id="abc",
        started_at=now,
        finished_at=now,
        total=3,
        passed=2,
        failed=0,
        skipped=1,
        errors=0,
        results=[
            _make_result(EvalStatus.pass_, "a"),
            _make_result(EvalStatus.pass_, "b"),
            _make_result(EvalStatus.skip, "c"),
        ],
    )
    assert report.is_green is True
    assert report.pass_rate == 1.0  # 2/2 eligible (skip not counted)


def test_suite_report_not_green():
    now = datetime.datetime.utcnow()
    report = EvalSuiteReport(
        suite_id="xyz",
        started_at=now,
        finished_at=now,
        total=2,
        passed=1,
        failed=1,
        skipped=0,
        errors=0,
        results=[
            _make_result(EvalStatus.pass_, "a"),
            _make_result(EvalStatus.fail, "b"),
        ],
    )
    assert report.is_green is False
    assert report.pass_rate == 0.5


def test_suite_report_pass_rate_zero_eligible():
    now = datetime.datetime.utcnow()
    report = EvalSuiteReport(
        suite_id="empty",
        started_at=now,
        finished_at=now,
        total=0,
        passed=0,
        failed=0,
        skipped=0,
        errors=0,
    )
    assert report.pass_rate == 0.0
