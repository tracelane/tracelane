"""Attaching a wrapper to a live object — the one place that knows how.

**Why this module exists (B-312).** Three shipped adapters — langchain,
llamaindex, crewai — could never attach to their own framework, and all three
failed on the same line of pydantic:

    ValueError: "GenericFakeChatModel" object has no field "invoke"

``langchain.BaseChatModel``, ``llama_index.core.llms.LLM`` and ``crewai.Agent``
are all pydantic **v2** ``BaseModel``s, and pydantic v2's ``__setattr__``
refuses any attribute that is not a declared field. Both
``wrapt.wrap_function_wrapper(instance, …)`` and a plain ``obj.method = …``
route through it, so both raise. LangGraph was unaffected only because
``CompiledStateGraph`` is not a pydantic model — which is why the defect looked
like three unrelated bugs instead of one.

``object.__setattr__`` bypasses the pydantic hook. The wrapper lands in the
instance ``__dict__``, and because a plain function is a *non-data* descriptor,
instance lookup wins over the class attribute — so the wrapper is what callers
get. Verified against langchain 1.3.18, llama-index-core 0.14.24 and
crewai 1.15.18.

**Never fails silently.** The adapters this replaces returned early when the
attribute was missing, which is indistinguishable from working — you get no
error, no span, and no way to tell the difference. Every failure here raises.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

_MARKER = "__tracelane_wrapped__"


def already_attached(target: Any, name: str) -> bool:
    """True if ``target.name`` is already a Tracelane wrapper."""
    return getattr(getattr(target, name, None), _MARKER, False) is True


def attach(target: Any, name: str, make_wrapper: Callable[[Any], Any]) -> None:
    """Replace ``target.name`` with ``make_wrapper(original)``.

    Idempotent: attaching twice is a no-op, so instrumenting the same object
    from two call sites does not double-count spans.

    Args:
        target: the live object to instrument.
        name: the method name on it.
        make_wrapper: called with the original bound method, returns the wrapper.

    Raises:
        AttributeError: ``target`` has no attribute ``name`` — the framework
            renamed it, or the wrong object was passed. **Raised, never
            swallowed**: a silent skip here is a capture gap nobody can see.
        TypeError: the attribute exists but cannot be replaced on this object
            (``__slots__`` with no ``__dict__``, or a C extension type).
    """
    original = getattr(target, name, None)
    if original is None:
        raise AttributeError(
            f"{type(target).__name__!r} has no attribute {name!r} — cannot instrument it. "
            f"This usually means the framework renamed the method, or an object of the "
            f"wrong type was passed."
        )

    if already_attached(target, name):
        return

    wrapper = make_wrapper(original)
    # A wrapper that itself refuses attributes still works; it just cannot carry
    # the idempotence marker, so a second attach would re-wrap it.
    with contextlib.suppress(AttributeError):
        wrapper.__tracelane_wrapped__ = True  # type: ignore[attr-defined]

    try:
        setattr(target, name, wrapper)
        return
    except (ValueError, AttributeError, TypeError):
        # pydantic v2 rejects non-field attributes. Go under it.
        pass

    try:
        object.__setattr__(target, name, wrapper)
    except (AttributeError, TypeError) as exc:
        raise TypeError(
            f"cannot instrument {type(target).__name__!r}.{name} — the attribute "
            f"could not be replaced ({exc}). Objects using __slots__ without a "
            f"__dict__, or C extension types, cannot be instrumented this way."
        ) from exc


def require(module: str, extra: str) -> Any:
    """Import ``module`` or raise an ImportError naming the extra to install.

    A missing framework must be a loud, actionable error — not a silent no-op.
    """
    try:
        return __import__(module)
    except ImportError as exc:
        raise ImportError(
            f"{module!r} is not installed, so Tracelane cannot instrument it. "
            f"Install it with:  pip install 'tracelane[{extra}]'"
        ) from exc
