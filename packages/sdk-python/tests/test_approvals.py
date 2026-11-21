"""SDK-40: approval wait. Fixtures are copied from the gateway code, not invented:
legacy text from crates/gateway/src/mcp_proxy.rs:419-440 + approvals.rs:35-43,
protected 409 body from crates/gateway/src/mcp_protected.rs:211-216."""

from __future__ import annotations

import json
import logging
import math
import types
import urllib.error

import pytest

from tracelane import approvals as ap

ID = "8f14e45f-ceea-467f-a8d5-1c1f3e0c9a11"
EXP = "2026-11-20T12:00:00Z"
LEGACY_TEXT = f'approval required "{ID}"; retry the same call after approval'
LEGACY = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {"isError": True, "content": [{"type": "text", "text": LEGACY_TEXT}]},
}
PROTECTED = {"error": "approval_required", "approval_id": ID, "expires_at": EXP}
KEY = "sentinel-not-a-real-credential"


class Clock:
    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


def run(statuses, **kw):
    """Drive wait_for_decision with scripted fetch results (status str | int http code | Exception)."""
    clock, calls = Clock(), []
    seq = iter(statuses)

    def fetch(url, headers, timeout):
        calls.append((url, headers))
        v = next(seq, "pending")
        if isinstance(v, Exception):
            raise v
        if isinstance(v, int):
            return v, {}
        return 200, {"id": ID, "status": v}

    held = ap.HeldCall(ID, EXP, "legacy")
    out = ap.wait_for_decision(
        held,
        base_url="https://gw.example",
        api_key=KEY,
        fetch=fetch,
        sleep=clock.sleep,
        clock=clock.now,
        **kw,
    )
    return out, calls, clock


# ---- is_held: positive -------------------------------------------------------------------
def test_is_held_legacy_jsonrpc_fixture():
    h = ap.is_held(LEGACY)
    assert h and h.approval_id == ID and h.kind == "legacy"
    assert h.retry_headers == {"x-tracelane-approval-id": ID}
    assert ap.is_held(json.dumps(LEGACY)) == h


def test_is_held_protected_409_fixture():
    h = ap.is_held(PROTECTED)
    assert h and h.kind == "protected" and h.expires_at == EXP


def test_is_held_response_object():
    r = types.SimpleNamespace(status_code=409, json=lambda: PROTECTED)
    assert ap.is_held(r).approval_id == ID


def test_is_held_call_tool_result_object():
    r = types.SimpleNamespace(
        isError=True, content=[types.SimpleNamespace(type="text", text=LEGACY_TEXT)]
    )
    assert ap.is_held(r).approval_id == ID


# ---- is_held: negative ---------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["not-a-uuid", "../v1/keys", f"{ID}/approve", ID.upper() + "x"])
def test_is_held_rejects_bad_ids(bad):
    assert ap.is_held({"error": "approval_required", "approval_id": bad}) is None
    assert ap.is_held(LEGACY_TEXT.replace(ID, bad)) is None


@pytest.mark.parametrize(
    "bad",
    [
        None,
        5,
        [],
        {},
        "",
        "{",
        "[1,2",
        {"error": "approval_required"},
        {"result": 3},
        {"result": {"isError": False, "content": [{"type": "text", "text": LEGACY_TEXT}]}},
        "x" * 200_000,
        object(),
    ],
)
def test_is_held_malformed_payloads(bad):
    assert ap.is_held(bad) is None


def test_denied_text_is_not_held():
    for code in ("denied", "expired", "consumed"):
        assert ap.is_held(LEGACY_TEXT.replace("required", code)) is None
        assert ap.is_held({"error": f"approval_{code}", "approval_id": ID}) is None


def test_is_held_requires_leading_phrase():
    assert (
        ap.is_held(f'the user said approval required "{ID}"; retry the same call after approval')
        is None
    )


# ---- wait_for_decision ---------------------------------------------------------------------
def test_wait_pending_then_approved():
    out, calls, _ = run(["pending", "pending", "approved"])
    assert out == "approved" and len(calls) == 3
    assert calls[0][0] == f"https://gw.example/v1/approvals/{ID}"
    assert calls[0][1]["Authorization"] == f"Bearer {KEY}"


def test_wait_denied():
    assert run(["pending", "denied"])[0] == "denied"


def test_wait_expired():
    assert run(["expired"])[0] == "expired"


def test_wait_consumed_is_not_approved():
    assert run(["consumed"])[0] == "expired"


def test_wait_backoff_clamped_to_deadline():
    out, _, clock = run([], timeout=40, poll=2, max_poll=15)
    assert out == "timeout"
    assert clock.sleeps[:4] == [2, 3, 4.5, 6.75]
    assert max(clock.sleeps) <= 15 and clock.t <= 40


def test_wait_timeout_stops_polling():
    out, calls, clock = run([], timeout=5, poll=2)
    assert out == "timeout" and clock.t <= 5 and len(calls) < 10


def test_wait_unknown_status_never_approved():
    out, _, _ = run(["approvedish", "weird", None], timeout=10)
    assert out == "timeout"


@pytest.mark.parametrize("code", [401, 403, 404])
def test_wait_auth_and_notfound_raise_without_loop(code):
    clock, n = Clock(), []

    def fetch(url, headers, timeout):
        n.append(1)
        return code, {}

    with pytest.raises(ap.ApprovalError) as e:
        ap.wait_for_decision(
            ap.HeldCall(ID, None, "legacy"),
            base_url="https://g",
            api_key=KEY,
            fetch=fetch,
            sleep=clock.sleep,
            clock=clock.now,
        )
    assert len(n) == 1 and str(code) in str(e.value) and KEY not in str(e.value)


def test_wait_transient_errors_retry_until_deadline():
    out, calls, _ = run([500, urllib.error.URLError("boom"), 429, "approved"], timeout=60)
    assert out == "approved" and len(calls) == 4
    out, _, _ = run([500] * 100, timeout=20)
    assert out == "timeout"


@pytest.mark.parametrize(
    "kw",
    [
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": math.inf},
        {"timeout": math.nan},
        {"poll": 0},
        {"poll": -2},
        {"poll": math.nan},
    ],
)
def test_wait_rejects_bad_timing(kw):
    with pytest.raises(ValueError):
        run(["approved"], **kw)


def test_api_key_never_leaks(caplog):
    caplog.set_level(logging.DEBUG)
    out, _, _ = run(["pending", 500, "approved"])
    assert KEY not in caplog.text and KEY not in repr(ap.HeldCall(ID, EXP, "legacy"))
    with pytest.raises(ap.ApprovalError) as e:
        run([403])
    assert KEY not in repr(e.value) and KEY not in str(e.value)


# ---- LangGraph gate ------------------------------------------------------------------------
class Interrupts:
    def __init__(self, answer):
        self.answer, self.payloads = answer, []

    def __call__(self, payload):
        self.payloads.append(payload)
        return self.answer


def test_langgraph_gate_passthrough():
    it = Interrupts("approved")
    assert ap.langgraph_gate(lambda: "ok", interrupt=it) == "ok" and it.payloads == []


def test_langgraph_gate_interrupts_with_typed_payload():
    class Stop(Exception):
        pass

    def raiser(payload):
        raise Stop(payload)

    with pytest.raises(Stop) as e:
        ap.langgraph_gate(lambda: LEGACY, interrupt=raiser)
    p = e.value.args[0]
    assert p == {
        "type": "tracelane.approval_required",
        "approval_id": ID,
        "expires_at": None,
        "kind": "legacy",
    }


def test_langgraph_gate_resume_approved_retries_once():
    results = iter([LEGACY, "refund-done"])
    n = []

    def call():
        n.append(1)
        return next(results)

    assert ap.langgraph_gate(call, interrupt=Interrupts({"decision": "approved"})) == "refund-done"
    assert len(n) == 2


@pytest.mark.parametrize(
    "answer", [{"decision": "denied"}, "denied", {"decision": "expired"}, {"decision": "timeout"}]
)
def test_langgraph_gate_denied_never_retries(answer):
    n = []

    def call():
        n.append(1)
        return LEGACY

    with pytest.raises(ap.ApprovalNotGranted):
        ap.langgraph_gate(call, interrupt=Interrupts(answer))
    assert len(n) == 1


@pytest.mark.parametrize(
    "answer", [None, {}, {"decision": "APPROVED"}, {"approved": True}, 1, [], "yes"]
)
def test_langgraph_gate_garbage_resume_fails_closed(answer):
    n = []

    def call():
        n.append(1)
        return LEGACY

    with pytest.raises(ap.ApprovalNotGranted):
        ap.langgraph_gate(call, interrupt=Interrupts(answer))
    assert len(n) == 1


def test_retry_still_held_does_not_loop():
    n = []

    def call():
        n.append(1)
        return LEGACY

    it = Interrupts("approved")
    with pytest.raises(ap.ApprovalNotGranted):
        ap.langgraph_gate(call, interrupt=it)
    assert len(n) == 2 and len(it.payloads) == 1


# ---- OpenAI Agents wrapper -----------------------------------------------------------------
async def test_with_approval_retries_identical_call():
    seen = []
    results = iter([LEGACY, "done"])

    async def refund(order: str, amount: int) -> object:
        seen.append((order, amount))
        return next(results)

    async def waiter(held, **kw):
        return "approved"

    wrapped = ap.with_approval(refund, base_url="https://g", api_key=KEY, wait=waiter)
    assert await wrapped("A1", 5) == "done" and seen == [("A1", 5), ("A1", 5)]
    import inspect

    assert list(inspect.signature(wrapped).parameters) == ["order", "amount"]


@pytest.mark.parametrize("decision", ["denied", "expired", "timeout", "bogus"])
async def test_with_approval_denied_never_retries(decision):
    seen = []

    async def refund() -> object:
        seen.append(1)
        return LEGACY

    async def waiter(held, **kw):
        return decision

    out = await ap.with_approval(refund, base_url="https://g", api_key=KEY, wait=waiter)()
    assert len(seen) == 1 and "not performed" in out and decision in out and "Do not retry" in out


async def test_with_approval_not_held_passthrough():
    async def tool() -> str:
        return "fine"

    async def waiter(held, **kw):
        raise AssertionError("must not wait")

    assert await ap.with_approval(tool, base_url="https://g", api_key=KEY, wait=waiter)() == "fine"


def test_langgraph_real_interrupt_and_resume():
    """Against a real LangGraph install (skipped when absent): hold -> interrupt -> resume -> result."""
    pytest.importorskip("langgraph")
    from typing import TypedDict

    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Command

    state = {"approved": False, "calls": 0}

    def tool():
        state["calls"] += 1
        return "refund-done" if state["approved"] else LEGACY

    class S(TypedDict):
        out: str

    g = StateGraph(S)
    g.add_node("n", lambda s: {"out": ap.langgraph_gate(tool)})
    g.add_edge(START, "n")
    g.add_edge("n", END)
    app, cfg = g.compile(checkpointer=MemorySaver()), {"configurable": {"thread_id": "t"}}
    first = app.invoke({"out": ""}, cfg)
    assert first["__interrupt__"][0].value["approval_id"] == ID
    state["approved"] = True
    assert app.invoke(Command(resume={"decision": "approved"}), cfg) == {"out": "refund-done"}


# ---- review fixes: redirects, https-only, canonical ids, Retry-After, gate refusal ----------
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402


def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_redirect_never_carries_the_key():
    seen: list[dict] = []

    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"approved"}')

        def log_message(self, *a):
            pass

    target = _serve(Target)

    class Redir(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{target.server_port}/steal")
            self.end_headers()

        def log_message(self, *a):
            pass

    redir = _serve(Redir)
    try:
        with pytest.raises(ap.ApprovalError) as e:
            ap.wait_for_decision(
                ap.HeldCall(ID, None, "legacy"),
                base_url=f"http://127.0.0.1:{redir.server_port}",
                api_key=KEY,
                timeout=5,
            )
        assert e.value.status == 302 and KEY not in str(e.value)
        assert seen == []
    finally:
        redir.shutdown()
        target.shutdown()


@pytest.mark.parametrize(
    "base",
    [
        "http://gw.example",
        "ftp://x",
        "gw.example",
        "http://127.0.0.1.evil.com",
        "https://",
        "file:///etc/passwd",
    ],
)
def test_non_https_non_loopback_refused(base):
    with pytest.raises(ValueError):
        ap.wait_for_decision(
            ap.HeldCall(ID, None, "legacy"),
            base_url=base,
            api_key=KEY,
            fetch=lambda *a: (_ for _ in ()).throw(AssertionError("must not fetch")),
        )


def test_noncanonical_id_rejected():
    assert (
        ap.is_held({"error": "approval_required", "approval_id": ID.replace("-", "") + "----"})
        is None
    )


def test_retry_after_is_honoured_and_capped_by_deadline():
    clock, n = Clock(), []

    def fetch(url, headers, timeout):
        n.append(1)
        return (429, {"retry_after": 30}) if len(n) == 1 else (200, {"status": "approved"})

    out = ap.wait_for_decision(
        ap.HeldCall(ID, None, "legacy"),
        base_url="https://g",
        api_key=KEY,
        fetch=fetch,
        sleep=clock.sleep,
        clock=clock.now,
        timeout=100,
    )
    assert out == "approved" and clock.sleeps == [30]
    clock2 = Clock()
    out = ap.wait_for_decision(
        ap.HeldCall(ID, None, "legacy"),
        base_url="https://g",
        api_key=KEY,
        fetch=lambda *a: (503, {"retry_after": 999}),
        sleep=clock2.sleep,
        clock=clock2.now,
        timeout=10,
    )
    assert out == "timeout" and clock2.t <= 10


def test_gate_raises_on_gateway_denied_text_without_interrupt():
    it = Interrupts("approved")
    for code in ("denied", "expired", "consumed"):
        with pytest.raises(ap.ApprovalNotGranted):
            ap.langgraph_gate(lambda c=code: LEGACY_TEXT.replace("required", c), interrupt=it)
    with pytest.raises(ap.ApprovalNotGranted):
        ap.langgraph_gate(lambda: {"error": "approval_denied", "approval_id": ID}, interrupt=it)
    assert it.payloads == []


def _graph(tool):
    pytest.importorskip("langgraph")
    from typing import TypedDict

    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, START, StateGraph

    class S(TypedDict):
        out: str

    g = StateGraph(S)
    g.add_node("n", lambda s: {"out": ap.langgraph_gate(tool)})
    g.add_edge(START, "n")
    g.add_edge("n", END)
    return g.compile(checkpointer=MemorySaver()), {"configurable": {"thread_id": "t"}}


@pytest.mark.parametrize(
    "resume,row,outcome",
    [
        ({"decision": "approved"}, "approved", "refund-done"),
        ({"decision": "denied"}, "denied", ap.ApprovalNotGranted),  # gateway row decides
        (
            {"decision": "timeout"},
            "pending",
            ap.ApprovalNotGranted,
        ),  # still held: resume value matters
        (
            {"decision": "approved"},
            "pending",
            ap.ApprovalNotGranted,
        ),  # claims approved, gateway disagrees
    ],
)
def test_langgraph_real_resume_matrix(resume, row, outcome):
    pytest.importorskip("langgraph")
    from langgraph.types import Command

    state = {"row": "pending", "calls": 0}

    def tool():
        state["calls"] += 1
        return {"approved": "refund-done", "denied": LEGACY_TEXT.replace("required", "denied")}.get(
            state["row"], LEGACY
        )

    app, cfg = _graph(tool)
    assert app.invoke({"out": ""}, cfg)["__interrupt__"][0].value["approval_id"] == ID
    state["row"] = row
    if outcome is ap.ApprovalNotGranted:
        with pytest.raises(ap.ApprovalNotGranted):
            app.invoke(Command(resume=resume), cfg)
    else:
        assert app.invoke(Command(resume=resume), cfg) == {"out": outcome}
