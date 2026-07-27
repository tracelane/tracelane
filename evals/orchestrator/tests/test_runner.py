"""Tests for EvalRunner structural behaviour (no live LLM calls)."""

import pytest

from orchestrator.models import EvalSuiteReport
from orchestrator.runner import EvalRunner, _extract_pp_id, _parse_vitest_json


def test_extract_pp_id():
    assert _extract_pp_id("evals/pain-points/PP-G1.eval.ts") == "PP-G1"
    assert _extract_pp_id("evals/fault-tolerance/FT-02.eval.ts") == "FT-02"
    assert _extract_pp_id("evals/other/random.ts") is None


def test_parse_vitest_json_empty():
    results = _parse_vitest_json("{}", "pain-points", 100)
    assert results == []


def test_parse_vitest_json_pass():
    raw = """{
        "testResults": [{
            "name": "evals/pain-points/PP-G1.eval.ts",
            "assertionResults": [{
                "ancestorTitles": ["PP-G1: Gateway overhead"],
                "title": "gateway adds <10ms overhead",
                "status": "passed",
                "duration": 12
            }]
        }]
    }"""
    results = _parse_vitest_json(raw, "pain-points", 100)
    assert len(results) == 1
    assert results[0].status.value == "pass"
    assert results[0].pain_point_id == "PP-G1"


def test_parse_vitest_json_fail():
    raw = """{
        "testResults": [{
            "name": "evals/pain-points/PP-OP1.eval.ts",
            "assertionResults": [{
                "ancestorTitles": ["PP-OP1: Rate limiting"],
                "title": "rate limiter module exists in gateway",
                "status": "failed",
                "duration": 5
            }]
        }]
    }"""
    results = _parse_vitest_json(raw, "pain-points", 100)
    assert results[0].status.value == "fail"


def test_parse_vitest_json_skip():
    raw = """{
        "testResults": [{
            "name": "evals/fault-tolerance/FT-01.eval.ts",
            "assertionResults": [{
                "ancestorTitles": ["FT-01"],
                "title": "provider failover integration",
                "status": "pending",
                "duration": 0
            }]
        }]
    }"""
    results = _parse_vitest_json(raw, "fault-tolerance", 0)
    assert results[0].status.value == "skip"


@pytest.mark.asyncio
async def test_runner_returns_suite_report():
    """EvalRunner.run_suite() returns an EvalSuiteReport even with no framework installed."""
    runner = EvalRunner(emit_spans=False, fixture_mode=True)
    # vitest subprocess will fail (not in a proper pnpm environment here),
    # but run_suite must still return a valid EvalSuiteReport
    report = await runner.run_suite()
    assert isinstance(report, EvalSuiteReport)
    assert report.total >= 0
    assert report.passed + report.failed + report.skipped + report.errors == report.total


@pytest.mark.asyncio
async def test_run_vitest_degrades_when_pnpm_absent(monkeypatch):
    """_run_vitest() must return [] (not raise) when the pnpm binary is missing —
    same 'framework not installed' contract as the deepeval/ragas/inspect_ai
    adapters. Deterministic regression for the 2026-06-06 CI failure, where pnpm
    was not on PATH in the slimmed python job and create_subprocess_exec raised
    FileNotFoundError out of run_suite(). Forces the error regardless of whether
    pnpm happens to be installed in the test environment."""

    async def _no_pnpm(*_args, **_kwargs):
        raise FileNotFoundError(2, "No such file or directory", "pnpm")

    monkeypatch.setattr("orchestrator.runner.asyncio.create_subprocess_exec", _no_pnpm)
    runner = EvalRunner(emit_spans=False, fixture_mode=True)
    # "pain-points" suite dir exists, so _run_vitest reaches the subprocess call.
    assert await runner._run_vitest("pain-points") == []
