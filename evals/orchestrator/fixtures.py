"""
Recorded LLM response fixtures for offline eval runs.

CI must never make live LLM calls (egress sandbox). All fixtures are
pre-recorded JSON files in orchestrator/fixtures/<name>.json.
Fixture loading raises FixtureMissingError if a fixture is absent, so
evals that need live calls fail loudly in CI rather than silently.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class FixtureMissingError(RuntimeError):
    """Raised when an eval requests a fixture that has not been recorded."""


def load(name: str) -> dict:
    """Load a fixture by name (without .json extension)."""
    path = FIXTURE_DIR / f"{name}.json"
    if not path.exists():
        raise FixtureMissingError(
            f"Fixture '{name}' not found at {path}. "
            "Record it with: python -m orchestrator.fixtures record <name> <prompt>"
        )
    return json.loads(path.read_text())


def save(name: str, data: dict) -> None:
    """Persist a recorded fixture."""
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    path = FIXTURE_DIR / f"{name}.json"
    path.write_text(json.dumps(data, indent=2))


def list_fixtures() -> list[str]:
    """Return all available fixture names."""
    if not FIXTURE_DIR.exists():
        return []
    return [p.stem for p in sorted(FIXTURE_DIR.glob("*.json"))]
