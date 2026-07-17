"""Breadth coverage across every instrumentation adapter.

These catch the failure modes a per-adapter deep test would miss at scale:
a module that fails to import (top-level vendor import, syntax/typo), or an
`instrument_*` entry point that was renamed or dropped from the public surface.

Adapters import their vendor SDK lazily (inside the instrument function), so
importing every module here does not require `openai`, `anthropic`, etc. to be
installed.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import tracelane
import tracelane.instrumentations as instrumentations_pkg

_MODULE_NAMES = sorted(m.name for m in pkgutil.iter_modules(instrumentations_pkg.__path__))
_INSTRUMENT_EXPORTS = sorted(name for name in tracelane.__all__ if name.startswith("instrument_"))


def test_adapter_inventory_is_substantial() -> None:
    assert len(_MODULE_NAMES) >= 18, _MODULE_NAMES
    assert len(_INSTRUMENT_EXPORTS) >= 18, _INSTRUMENT_EXPORTS


@pytest.mark.parametrize("module_name", _MODULE_NAMES)
def test_instrumentation_module_imports_cleanly(module_name: str) -> None:
    # Must not raise — a broken top-level import is a shipped-SDK regression.
    importlib.import_module(f"tracelane.instrumentations.{module_name}")


@pytest.mark.parametrize("module_name", _MODULE_NAMES)
def test_module_exposes_an_instrument_callable(module_name: str) -> None:
    mod = importlib.import_module(f"tracelane.instrumentations.{module_name}")
    instrument_fns = [
        getattr(mod, n)
        for n in dir(mod)
        if n.startswith("instrument_") and callable(getattr(mod, n))
    ]
    assert instrument_fns, f"{module_name} exposes no instrument_* callable"


@pytest.mark.parametrize("export_name", _INSTRUMENT_EXPORTS)
def test_public_instrument_export_is_callable(export_name: str) -> None:
    fn = getattr(tracelane, export_name)
    assert callable(fn), f"tracelane.{export_name} must be callable"
