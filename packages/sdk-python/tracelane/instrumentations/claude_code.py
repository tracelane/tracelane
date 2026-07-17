"""Claude Code harness instrumentation for Tracelane.

Instruments subprocess invocations of the `claude` CLI to emit OTel spans.
This is the highest-value harness adapter — it lets teams trace their
AI-assisted development sessions through the same observability stack
that monitors their production agents.

The adapter patches subprocess.run and subprocess.Popen to intercept
calls where `claude` appears in the command, without affecting other
subprocess usage.

Example::

    import subprocess
    from tracelane.instrumentations.claude_code import instrument_claude_code

    instrument_claude_code()
    # All subsequent subprocess.run(["claude", ...]) calls emit spans
    result = subprocess.run(["claude", "--print", "help me refactor this"])
"""

from __future__ import annotations

import subprocess
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, StatusCode

_tracer = trace.get_tracer("tracelane.claude-code", "0.1.0")

_PATCHED = False


def instrument_claude_code() -> None:
    """Patch subprocess to emit OTel spans for claude CLI invocations.

    Intercepts subprocess.run calls where the command includes 'claude'.
    Safe to call multiple times — subsequent calls are no-ops.

    Note:
        Only intercepts calls where 'claude' is in the command list or string.
        Other subprocess calls are passed through unmodified.
        Prompt content is never captured — only model flag, exit code, and duration.
    """
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True

    _patch_run()
    _patch_popen()


def _is_claude_command(args: Any) -> bool:
    if isinstance(args, list):
        return bool(args) and "claude" in str(args[0])
    if isinstance(args, str):
        return args.startswith("claude") or " claude " in args
    return False


def _extract_model(args: Any) -> str:
    """Extract the --model flag value from a claude command."""
    items = args if isinstance(args, list) else args.split()
    for i, item in enumerate(items):
        if item == "--model" and i + 1 < len(items):
            return str(items[i + 1])
        if str(item).startswith("--model="):
            return str(item).split("=", 1)[1]
    return "claude-sonnet-4-6"  # default model


def _patch_run() -> None:
    original_run = subprocess.run

    def _patched_run(args: Any, *pargs: Any, **kwargs: Any) -> Any:
        if not _is_claude_command(args):
            return original_run(args, *pargs, **kwargs)

        model = _extract_model(args)
        cmd_len = len(args) if isinstance(args, list) else len(str(args))

        with _tracer.start_as_current_span(
            "claude_code.subprocess.run",
            kind=SpanKind.CLIENT,
            attributes={
                "gen_ai.provider.name": "claude-code",
                "gen_ai.request.model": model,
                "claude_code.command_args_count": cmd_len,
            },
        ) as span:
            try:
                result = original_run(args, *pargs, **kwargs)
                span.set_attribute("claude_code.exit_code", result.returncode)
                span.set_status(
                    StatusCode.OK if result.returncode == 0 else StatusCode.ERROR,
                    "" if result.returncode == 0 else f"exit code {result.returncode}",
                )
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(StatusCode.ERROR, str(exc))
                raise

    subprocess.run = _patched_run  # type: ignore[assignment]


def _patch_popen() -> None:
    OriginalPopen = subprocess.Popen

    class _PatchedPopen(OriginalPopen):  # type: ignore[type-arg]
        def __init__(self, args: Any, *pargs: Any, **kwargs: Any) -> None:
            if _is_claude_command(args):
                model = _extract_model(args)
                self._tracelane_span = _tracer.start_span(
                    "claude_code.subprocess.popen",
                    kind=SpanKind.CLIENT,
                    attributes={
                        "gen_ai.provider.name": "claude-code",
                        "gen_ai.request.model": model,
                    },
                )
            else:
                self._tracelane_span = None
            super().__init__(args, *pargs, **kwargs)

        def wait(self, timeout: Any = None) -> int:
            rc = super().wait(timeout=timeout)
            if self._tracelane_span is not None:
                self._tracelane_span.set_attribute("claude_code.exit_code", rc)
                self._tracelane_span.set_status(StatusCode.OK if rc == 0 else StatusCode.ERROR)
                self._tracelane_span.end()
                self._tracelane_span = None
            return rc

    subprocess.Popen = _PatchedPopen  # type: ignore[assignment]
