"""Tests for fixture loading / persistence."""

import pytest

from orchestrator.fixtures import FixtureMissingError, load, save


def test_load_missing_fixture_raises():
    with pytest.raises(FixtureMissingError, match="not found"):
        load("definitely_does_not_exist_xyzzy")


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    import orchestrator.fixtures as fix_module

    monkeypatch.setattr(fix_module, "FIXTURE_DIR", tmp_path)
    payload = {"question": "q", "answer": "a", "contexts": ["c1"]}
    save("roundtrip_test", payload)
    loaded = load("roundtrip_test")
    assert loaded == payload


def test_list_fixtures_empty(tmp_path, monkeypatch):
    import orchestrator.fixtures as fix_module

    monkeypatch.setattr(fix_module, "FIXTURE_DIR", tmp_path)
    assert fix_module.list_fixtures() == []
