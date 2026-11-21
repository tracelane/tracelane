"""Pause, wait for a person's decision, resume. The gateway detects and holds a risky MCP tool
call; this module waits for the answer and retries the identical call. It decides nothing: a
retry without an approved row is held again by the gateway.

    held = is_held(result)                       # HeldCall | None
    decision = wait_for_decision(held, base_url=..., api_key=...)
    # LangGraph node:   langgraph_gate(lambda: call_tool(...))
    # OpenAI Agents:    with_approval(my_tool_fn, base_url=..., api_key=...)

Standard library only; langgraph is imported lazily. Contract: crates/gateway/src/mcp_proxy.rs
(legacy JSON-RPC text), mcp_protected.rs (409 body), mcp_routes.rs (GET /v1/approvals/{id}).
"""

from __future__ import annotations

import asyncio
import functools
import json
import math
import re
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

Decision = Literal["approved", "denied", "expired", "timeout"]
_MAX_BODY = 64 * 1024
_LOOPBACK = ("localhost", "127.0.0.1", "::1")
_TEXT = re.compile(r'approval required "?([0-9a-fA-F-]{36})"?; retry the same call after approval')


class ApprovalError(RuntimeError):
    """The status read was refused (401/403/404) or redirected (3xx). Never carries the API key."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ApprovalNotGranted(RuntimeError):
    def __init__(self, held: HeldCall, decision: str) -> None:
        super().__init__(
            f"approval {decision} {held.approval_id}; the call was not retried".replace("  ", " ")
        )
        self.held, self.decision = held, decision


@dataclass(frozen=True)
class HeldCall:
    approval_id: str
    expires_at: str | None
    kind: Literal["legacy", "protected"]

    @property
    def retry_headers(self) -> dict[str, str]:
        """Selector that can read/consume this approval but never create a new one."""
        return {"x-tracelane-approval-id": self.approval_id}

    def interrupt_payload(self) -> dict[str, Any]:
        return {
            "type": "tracelane.approval_required",
            "approval_id": self.approval_id,
            "expires_at": self.expires_at,
            "kind": self.kind,
        }


def _uid(v: Any) -> str | None:
    try:
        c = str(uuid.UUID(v)) if isinstance(v, str) and len(v) == 36 else None
        return c if c == v.lower() else None
    except ValueError:
        return None


def _get(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else getattr(o, k, None)


def _text(r: Any) -> str | None:
    """Tool-result text of an MCP JSON-RPC result, a CallToolResult object, or a plain string."""
    if isinstance(r, str):
        return r
    r = _get(r, "result") or r
    if _get(r, "isError") is not True:
        return None
    parts = _get(r, "content")
    first = parts[0] if isinstance(parts, list) and parts else None
    t = _get(first, "text") if first is not None else None
    return t if isinstance(t, str) else None


def is_held(result: Any) -> HeldCall | None:
    """Parse the gateway's held answer; None for anything else (never raises)."""
    try:
        if hasattr(result, "status_code") and callable(getattr(result, "json", None)):
            result = result.json()
        if isinstance(result, str):
            if len(result) > _MAX_BODY:
                return None
            if result.lstrip().startswith(("{", "[")):
                result = json.loads(result)
        if isinstance(result, dict) and result.get("error") == "approval_required":
            i = _uid(result.get("approval_id"))
            exp = result.get("expires_at")
            return HeldCall(i, exp if isinstance(exp, str) else None, "protected") if i else None
        m = _TEXT.fullmatch((_text(result) or "").strip())
        i = _uid(m.group(1)) if m else None
        return HeldCall(i, None, "legacy") if i else None
    except (ValueError, TypeError, AttributeError, IndexError):
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:
        return None  # a 3xx surfaces as HTTPError; the Authorization header is never forwarded


_opener = urllib.request.build_opener(_NoRedirect)


def _fetch(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 - scheme checked by caller
    try:
        with _opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read(_MAX_BODY))
    except urllib.error.HTTPError as e:
        try:
            ra = e.headers.get("Retry-After", "")
            return e.code, ({"retry_after": float(ra)} if ra.replace(".", "", 1).isdigit() else {})
        finally:
            e.close()


def _base(base_url: str) -> str:
    u = urlsplit(base_url)
    if not u.hostname or not (
        u.scheme == "https" or (u.scheme == "http" and u.hostname in _LOOPBACK)
    ):
        raise ValueError("base_url must be https (http only for localhost)")
    return base_url.rstrip("/")


def _positive(name: str, v: float) -> None:
    if not isinstance(v, (int, float)) or not math.isfinite(v) or v <= 0:
        raise ValueError(f"{name} must be a finite number > 0")


def wait_for_decision(
    held: HeldCall,
    *,
    base_url: str,
    api_key: str,
    timeout: float = 300.0,
    poll: float = 2.0,
    max_poll: float = 15.0,
    fetch: Callable[..., tuple[int, dict[str, Any]]] = _fetch,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Decision:
    """Poll GET /v1/approvals/{id} with the agent's own key until a terminal status or `timeout`.

    Only an explicit `approved` returns "approved". consumed / unknown terminal => "expired";
    deadline => "timeout" (the approval may still be pending). 401/403/404 raise ApprovalError.
    """
    for n, v in (("timeout", timeout), ("poll", poll), ("max_poll", max_poll)):
        _positive(n, v)
    aid = _uid(held.approval_id)
    if aid is None:
        raise ValueError("held.approval_id is not a UUID")
    url = f"{_base(base_url)}/v1/approvals/{aid}"
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    deadline, wait = clock() + timeout, float(poll)
    while True:
        try:
            code, body = fetch(url, headers, min(10.0, timeout))
        except (urllib.error.URLError, OSError, ValueError):  # InvalidURL is a ValueError subclass
            code, body = 599, {}
        if code in (401, 403, 404) or 300 <= code < 400:
            raise ApprovalError(f"approval status read refused: HTTP {code} for {aid}", code)
        status = body.get("status") if code == 200 and isinstance(body, dict) else None
        if status == "approved":
            return "approved"
        if status == "denied":
            return "denied"
        if status in ("expired", "consumed"):
            return "expired"
        left = deadline - clock()
        if left <= 0:
            return "timeout"
        ra = body.get("retry_after") if isinstance(body, dict) else None
        sleep(min(max(wait, float(ra)) if isinstance(ra, (int, float)) else wait, left))
        wait = min(wait * 1.5, float(max_poll))


async def async_wait_for_decision(held: HeldCall, **kw: Any) -> Decision:
    return await asyncio.to_thread(lambda: wait_for_decision(held, **kw))


def refusal(result: Any) -> str | None:
    """The gateway's own denied/expired/consumed answer to a retried call, else None."""
    try:
        if isinstance(result, dict) and str(result.get("error", "")).startswith("approval_"):
            code = str(result["error"])[9:]
        else:
            m = re.fullmatch(
                r'approval (denied|expired|consumed) "?[0-9a-fA-F-]{36}"?; retry the same call after approval',
                (_text(result) or "").strip(),
            )
            code = m.group(1) if m else ""
    except (ValueError, TypeError, AttributeError, IndexError):
        return None
    return code if code in ("denied", "expired", "consumed") else None


def _lg_interrupt() -> Callable[[Any], Any]:
    from langgraph.types import interrupt  # type: ignore[import-not-found,unused-ignore]  # optional

    return interrupt  # type: ignore[no-any-return,unused-ignore]


def _answer(answer: Any) -> str:
    d = answer.get("decision") if isinstance(answer, dict) else answer
    return d if isinstance(d, str) else "invalid"


def langgraph_gate(
    call: Callable[[], Any], *, interrupt: Callable[[Any], Any] | None = None
) -> Any:
    """Run `call` inside a LangGraph node. If the gateway holds it, `interrupt()` with a typed
    payload; resume with {"decision": "approved"|"denied"|"expired"|"timeout"} (use
    wait_for_decision in your driver). The GATEWAY decides: LangGraph re-runs the node on resume, so
    the first `call()` there is already the retry. An approved row returns the tool result; a denied,
    expired or consumed row raises ApprovalNotGranted; a still-pending row interrupts again and the
    resume value matters only then (only "approved" retries, once). Retry with the same
    Idempotency-Key the first call used (protected tools require it)."""
    result = call()
    held = is_held(result)
    if held is None:
        if (why := refusal(result)) is not None:  # gateway row already denied/expired/consumed
            raise ApprovalNotGranted(HeldCall("", None, "legacy"), why)
        return result
    decision = _answer((interrupt or _lg_interrupt())(held.interrupt_payload()))
    if decision != "approved":
        raise ApprovalNotGranted(held, decision)
    retry = call()
    if (again := is_held(retry)) is not None:
        raise ApprovalNotGranted(again, "pending")
    return retry


def with_approval[R](
    fn: Callable[..., Awaitable[R]],
    *,
    base_url: str,
    api_key: str,
    timeout: float = 300.0,
    poll: float = 2.0,
    wait: Callable[..., Awaitable[Decision]] = async_wait_for_decision,
) -> Callable[..., Awaitable[R | str]]:
    """Wrap an async tool function (e.g. for OpenAI Agents `function_tool`, or an MCP `call_tool`).
    Held => wait; approved => retry the identical call once; anything else => a refusal string
    for the model and no retry."""

    @functools.wraps(fn)
    async def wrapper(*a: Any, **k: Any) -> R | str:
        result = await fn(*a, **k)
        held = is_held(result)
        if held is None:
            return result
        decision = await wait(held, base_url=base_url, api_key=api_key, timeout=timeout, poll=poll)
        if decision != "approved":
            return f"Tracelane approval {decision}: the action was not performed. Do not retry."
        retry = await fn(*a, **k)
        if is_held(retry) is not None:
            return "Tracelane approval pending: the action was not performed. Do not retry."
        return retry

    return wrapper
