"""B-312 — attaching to an object whose __setattr__ refuses unknown attributes.

langchain's ``BaseChatModel``, llama-index's ``LLM`` and crewai's ``Agent`` are
all pydantic v2 ``BaseModel``s, and pydantic v2 raises ``ValueError`` for any
attribute that is not a declared field. Three shipped adapters attached with
``wrapt.wrap_function_wrapper(instance, …)`` or a plain assignment, so all three
raised and **had never captured a span**.

These tests do NOT import pydantic — pydantic is not an SDK dependency, and a
test that skips when a framework is absent is the fake-green shape (B-169).
``StrictSetattr`` below reproduces the exact refusal with no dependency at all,
so this test always runs and always means something.
"""

from __future__ import annotations

import pytest

from tracelane.instrumentations._attach import already_attached, attach


class StrictSetattr:
    """Refuses unknown attributes, the way pydantic v2's BaseModel does."""

    _fields = ("declared",)

    def __init__(self) -> None:
        object.__setattr__(self, "declared", 1)
        object.__setattr__(self, "calls", 0)

    def __setattr__(self, name: str, value: object) -> None:
        if name not in self._fields:
            raise ValueError(f'"{type(self).__name__}" object has no field "{name}"')
        object.__setattr__(self, name, value)

    def work(self, x: int) -> int:
        object.__setattr__(self, "calls", self.calls + 1)
        return x * 2


def _counting_wrapper(seen: list[str]):
    def make(original):
        def wrapper(*args, **kwargs):
            seen.append("called")
            return original(*args, **kwargs)

        return wrapper

    return make


def test_plain_setattr_is_refused_which_is_the_bug() -> None:
    """The falsifying half: without `attach`, this is exactly how B-312 failed."""
    obj = StrictSetattr()
    with pytest.raises(ValueError, match='has no field "work"'):
        obj.work = lambda x: x  # type: ignore[method-assign]


def test_attach_succeeds_where_plain_setattr_fails() -> None:
    seen: list[str] = []
    obj = StrictSetattr()
    attach(obj, "work", _counting_wrapper(seen))
    assert obj.work(21) == 42, "the wrapper must preserve the original return value"
    assert seen == ["called"], "the wrapper must actually intercept the call"


def test_attach_is_idempotent() -> None:
    """Instrumenting twice must not double-wrap, or spans double-count."""
    seen: list[str] = []
    obj = StrictSetattr()
    attach(obj, "work", _counting_wrapper(seen))
    first = obj.work
    attach(obj, "work", _counting_wrapper(seen))
    assert obj.work is first
    obj.work(1)
    assert seen == ["called"], "a second attach must not add a second layer"
    assert already_attached(obj, "work") is True


def test_missing_attribute_raises_rather_than_no_opping() -> None:
    """The silent `return` is what made four broken adapters look healthy."""
    obj = StrictSetattr()
    with pytest.raises(AttributeError, match="no attribute 'nope'"):
        attach(obj, "nope", _counting_wrapper([]))


def test_uninstrumentable_object_raises_typeerror() -> None:
    """__slots__ with no __dict__ cannot hold a wrapper — say so, do not pretend."""

    class Slotted:
        __slots__ = ()

        def work(self) -> int:
            return 1

    with pytest.raises(TypeError, match="could not be replaced"):
        attach(Slotted(), "work", _counting_wrapper([]))
