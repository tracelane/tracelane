#!/usr/bin/env python3
"""CI guard — #81 span-drop regression (both chat paths).

A trace span MUST be recorded for every dispatched request, including ones a
guardrail content-filters. Two structural invariants protect that:

1. BUFFERED (`buffer_provider_stream`): the span publish (`build_gateway_span`)
   must come BEFORE the response-side guardrail seam's `content_filter_response`
   return. Otherwise a blocked buffered response returns 200 and silently drops
   its span.

2. STREAMING (`provider_stream_to_sse`): the span is published by a
   `StreamFinalizer` whose `impl Drop` runs the finalization — so it is reached
   on EVERY way the stream can end, INCLUDING the one that is not a termination
   at all: the client hanging up, which drops the generator mid-yield.

   **B-375 (2026-09-12).** Until then this invariant read "the span publish must
   come AFTER the `loop { }` closes", and the code satisfied it — and lost the
   span, the meter event and the key spend on every client cancellation, because
   post-loop code runs when the loop *terminates*, not when the generator is
   *dropped*. The guard now asserts the shape that survives a drop:
     (a) `provider_stream_to_sse` constructs a `StreamFinalizer` BEFORE its loop
         and calls `.finish()` AFTER it;
     (b) `impl Drop for StreamFinalizer` exists and reaches `self.run(`;
     (c) `StreamFinalizer::run` is where `build_gateway_span(` lives, so both
         `finish()` and `drop()` reach the same publish.
   A `build_gateway_span(` back inside `provider_stream_to_sse` is refused: it
   would mean the publish moved back to a place a cancellation never reaches.

3. DISPATCH (`chat_completions_handler`) — **B-375 (b), 2026-09-12.** The prod
   proof for B-375 found the half the finalizer cannot cover: a client that hangs
   up while the provider is still being AWAITED drops the handler future before
   the `StreamFinalizer` exists (its first probe, cut at 1.5 s against a 1.25 s
   time-to-first-chunk, recorded NOTHING) — and every non-streaming request is
   assembled inside one `.await`. So a `DispatchGuard` is armed BEFORE
   `dispatch_with_retry(` and disarmed only where a span is recorded.

   **B-385 (2026-09-12) moved the arm.** The guard is now armed by the admission
   pipeline (`admission.rs`, `fn run`) the moment the ledger row exists — which
   also covers the BYOK lookup and the guardrail verdict, two awaits a cancel
   used to fall through silently — and reaches the handler inside `Admitted`:
     (d) `admission.rs::run` calls `DispatchGuard::arm(` AFTER `audit_chain.publish(`;
     (d') the handler binds `dispatch_guard` (from `Admitted`) BEFORE the first
         `dispatch_with_retry(`, and never arms one itself — a second guard on
         the same request would record the cancellation twice;
     (e) the streaming branch HANDS the guard INTO `provider_stream_to_sse(`
         (`Some(dispatch_guard)`) and never disarms it itself; inside the
         generator the handover is disarmed AFTER the `StreamFinalizer` is
         constructed. *Security review M-4, 2026-09-12:* the earlier rule
         ("disarm BEFORE the call") left a window — the finalizer is built on
         the body's FIRST POLL, so a client that hung up between the handler's
         return and that poll was recorded by nothing. An early disarm before
         the call is now REFUSED, and so is a generator that takes the handover
         and never disarms it (every completed stream would also record a
         cancellation);
     (f) the buffered branch disarms it AFTER `buffer_provider_stream(` returns.
   A pipeline that never arms, a handler with no guard, one that arms its own,
   or one disarmed before dispatch, is refused.

**B-385 §2d (2026-09-12) split `server.rs` into `server/*.rs`.** The three
functions this guard reads now live in three files — `server/buffered.rs`,
`server/stream.rs`, `server/chat.rs` — so it reads `server.rs` PLUS every file
under `server/` as ONE source, in that order. That is deliberately the widest
set rather than three named files: a function moved to a new sibling is still
found, and a function that vanishes from all of them is still refused. The
`fn_body` extractor is per-function and each file closes its own items at
column 0, so concatenation changes nothing it measures.

Runs in milliseconds, no infra — complements the e2e GC-TRACE-LOOP live-eval
gate (which exercises both the buffered and streaming paths against a real
ephemeral stack).

Exit codes:
    0 — all three invariants hold
    1 — at least one invariant is violated (or a guarded fn vanished)
    2 — --selftest failed, or an unrecognised argument was passed

Falsify it:  python3 scripts/ci/check-span-publish-ordering.py --selftest
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO / "crates/gateway/src/server.rs"
SRC_DIR = REPO / "crates/gateway/src/server"
ADMISSION = REPO / "crates/gateway/src/admission.rs"


def server_lines() -> list[str]:
    """`server.rs` followed by every `server/*.rs`, as one line list.

    B-385 §2d: the handler, the SSE generator and the buffered assembly are
    three files now. Read them all, sorted, so the guard cannot be satisfied
    by moving a function into a file it does not read.
    """
    out = SRC.read_text().splitlines()
    for p in sorted(SRC_DIR.glob("*.rs")):
        out.extend(p.read_text().splitlines())
    return out


def fn_body(lines: list[str], name: str) -> list[str] | None:
    """Lines of `fn <name>`'s body, or None when the fn is gone."""
    start = next(
        (i for i, ln in enumerate(lines) if re.search(rf"\bfn\s+{name}\b", ln)), None
    )
    if start is None:
        return None
    # The body ends at the fn's own closing brace at column 0. It used to end at
    # the NEXT top-level `fn`, which let an intervening `struct`/`impl` block
    # (B-375's `StreamFinalizer`, whose methods are indented) bleed into the
    # previous fn's body and be read as part of it.
    end = next(
        (j + 1 for j in range(start + 1, len(lines)) if lines[j].rstrip() == "}"),
        next(
            (
                j
                for j in range(start + 1, len(lines))
                if re.match(r"^(async\s+)?fn\s", lines[j])
            ),
            len(lines),
        ),
    )
    return lines[start:end]


def check(lines: list[str], admission: list[str]) -> list[str]:
    """Return every ordering violation found in `server.rs` + `server/*.rs` + `admission.rs`."""
    errors: list[str] = []

    # 1) Buffered: span publish before the content-filter block return.
    buf = fn_body(lines, "buffer_provider_stream")
    if buf is None:
        errors.append(
            "could not find `fn buffer_provider_stream` in server.rs or server/*.rs"
        )
    else:
        b_span = next(
            (k for k, ln in enumerate(buf) if "build_gateway_span(" in ln), None
        )
        b_cf = next(
            (k for k, ln in enumerate(buf) if "content_filter_response(" in ln), None
        )
        if b_span is None:
            errors.append(
                "buffer_provider_stream: no `build_gateway_span(` — the flight recorder is off."
            )
        elif b_cf is not None and b_span > b_cf:
            errors.append(
                f"buffer_provider_stream: span (`build_gateway_span` at +{b_span}) is AFTER the "
                f"content_filter_response block return (at +{b_cf}). A blocked response drops its span — "
                "publish the span BEFORE the response-side guardrail seam."
            )

    # 2) Streaming: span publish after the stream `loop { ... }` closes.
    strm = fn_body(lines, "provider_stream_to_sse")
    if strm is None:
        errors.append(
            "could not find `fn provider_stream_to_sse` in server.rs or server/*.rs"
        )
    else:
        s_loop = next(
            (k for k, ln in enumerate(strm) if re.search(r"\bloop\s*\{", ln)), None
        )
        s_ctor = next(
            (k for k, ln in enumerate(strm) if re.search(r"StreamFinalizer\s*\{", ln)),
            None,
        )
        s_finish = next(
            (k for k, ln in enumerate(strm) if re.search(r"\.finish\(\)", ln)), None
        )
        s_inline_span = next(
            (k for k, ln in enumerate(strm) if "build_gateway_span(" in ln), None
        )
        if s_inline_span is not None:
            errors.append(
                f"provider_stream_to_sse: `build_gateway_span(` at +{s_inline_span} is back INSIDE "
                "the generator. Code there runs only when the loop TERMINATES — a client that "
                "hangs up drops the generator and never reaches it (B-375). The span must be "
                "built in `StreamFinalizer::run`, which `Drop` also reaches."
            )
        if s_ctor is None:
            errors.append(
                "provider_stream_to_sse: no `StreamFinalizer { .. }` constructed — the streaming "
                "span has no Drop-finalized owner, so a client cancellation records nothing (B-375)."
            )
        elif s_loop is not None and s_ctor > s_loop:
            errors.append(
                f"provider_stream_to_sse: `StreamFinalizer` is constructed at +{s_ctor}, AFTER the "
                f"loop at +{s_loop}. A cancellation during the loop then has nothing to finalize."
            )
        s_handover_disarm = next(
            (
                k
                for k, ln in enumerate(strm)
                if "handover" in ln and ".disarm()" in "".join(strm[k : k + 3])
            ),
            None,
        )
        if s_handover_disarm is None:
            errors.append(
                "provider_stream_to_sse: the `handover` dispatch guard is never disarmed — "
                "every completed stream would ALSO record a `client_cancelled` span (M-4)."
            )
        elif s_ctor is not None and s_handover_disarm < s_ctor:
            errors.append(
                f"provider_stream_to_sse: the handover is disarmed at +{s_handover_disarm}, BEFORE "
                f"the `StreamFinalizer` at +{s_ctor} — a drop between the two records nothing."
            )
        if s_finish is None:
            errors.append(
                "provider_stream_to_sse: no `.finish()` after the loop — a completed stream would "
                "be finalized only by Drop, which cannot tell completion from cancellation."
            )
        elif s_loop is not None:
            depth = 0
            loop_close = None
            for k in range(s_loop, len(strm)):
                depth += strm[k].count("{") - strm[k].count("}")
                if k > s_loop and depth <= 0:
                    loop_close = k
                    break
            if loop_close is not None and s_finish < loop_close:
                errors.append(
                    f"provider_stream_to_sse: `.finish()` at +{s_finish} is INSIDE the stream loop "
                    f"(closes at +{loop_close}). It must run once, after the loop."
                )

    # (b) + (c): the finalizer's Drop reaches run(), and run() is where the span is built.
    drop_start = next(
        (
            i
            for i, ln in enumerate(lines)
            if re.search(r"impl\s+Drop\s+for\s+StreamFinalizer", ln)
        ),
        None,
    )
    if drop_start is None:
        errors.append(
            "no `impl Drop for StreamFinalizer` — a cancelled stream would record nothing (B-375)."
        )
    else:
        drop_body = lines[drop_start : drop_start + 12]
        if not any("self.run(" in ln for ln in drop_body):
            errors.append(
                "`impl Drop for StreamFinalizer` does not call `self.run(` — Drop is decorative."
            )
    run_impl = fn_body(lines, "run")
    # `fn run` is a common name; find the one that follows the StreamFinalizer impl.
    impl_start = next(
        (i for i, ln in enumerate(lines) if re.search(r"impl\s+StreamFinalizer\b", ln)),
        None,
    )
    if impl_start is None:
        errors.append(
            "no `impl StreamFinalizer` block — nothing finalizes the stream (B-375)."
        )
    else:
        impl_lines = lines[impl_start:]
        run_here = next(
            (k for k, ln in enumerate(impl_lines) if re.search(r"\bfn\s+run\b", ln)),
            None,
        )
        if run_here is None:
            errors.append(
                "`impl StreamFinalizer` has no `fn run` — Drop has nothing to call."
            )
        else:
            body = fn_body(impl_lines[run_here:], "run") or []
            if not any("build_gateway_span(" in ln for ln in body):
                errors.append(
                    "`StreamFinalizer::run` does not call `build_gateway_span(` — streaming spans "
                    "are not recorded on either exit."
                )
    del run_impl

    # 3) Dispatch: the DispatchGuard brackets the provider await (B-375 b), and
    #    since B-385 it is ARMED by the admission pipeline the moment the ledger
    #    row exists.
    run_body = fn_body(admission, "run")
    if run_body is None:
        errors.append("could not find `fn run` in admission.rs — the pipeline is gone")
    else:
        a_publish = next(
            (k for k, ln in enumerate(run_body) if "audit_chain.publish(" in ln), None
        )
        a_arm = next(
            (k for k, ln in enumerate(run_body) if "DispatchGuard::arm(" in ln), None
        )
        if a_publish is None:
            errors.append(
                "admission.rs::run: no `audit_chain.publish(` — the ledger row is not "
                "published by the pipeline."
            )
        if a_arm is None:
            errors.append(
                "admission.rs::run: no `DispatchGuard::arm(` — nothing records a client "
                "that hangs up after the ledger row exists (B-375 b / B-385)."
            )
        elif a_publish is not None and a_arm < a_publish:
            errors.append(
                f"admission.rs::run: `DispatchGuard::arm(` at +{a_arm} is BEFORE the ledger "
                f"publish at +{a_publish} — a refused request would record a cancellation."
            )

    hdl = fn_body(lines, "chat_completions_handler")
    if hdl is None:
        errors.append(
            "could not find `fn chat_completions_handler` in server.rs or server/*.rs"
        )
    else:
        h_bind = next((k for k, ln in enumerate(hdl) if "dispatch_guard" in ln), None)
        h_self_arm = next(
            (k for k, ln in enumerate(hdl) if "DispatchGuard::arm(" in ln), None
        )
        h_dispatch = next(
            (k for k, ln in enumerate(hdl) if "dispatch_with_retry(" in ln), None
        )
        h_sse = next(
            (k for k, ln in enumerate(hdl) if "provider_stream_to_sse(" in ln), None
        )
        h_buf = next(
            (k for k, ln in enumerate(hdl) if "buffer_provider_stream(" in ln), None
        )
        disarms = [k for k, ln in enumerate(hdl) if "dispatch_guard.disarm()" in ln]
        if h_self_arm is not None:
            errors.append(
                "chat_completions_handler: arms its OWN `DispatchGuard::arm(` — since B-385 "
                "the guard is armed by admission and arrives inside `Admitted`; a second "
                "guard records the same cancellation twice."
            )
        if h_bind is None:
            errors.append(
                "chat_completions_handler: no `dispatch_guard` — a client that hangs up "
                "while the provider is awaited records nothing (B-375 b)."
            )
        else:
            if h_dispatch is not None and h_bind > h_dispatch:
                errors.append(
                    f"chat_completions_handler: `dispatch_guard` is first bound at +{h_bind}, "
                    f"AFTER `dispatch_with_retry(` at +{h_dispatch} — the await it exists to "
                    "cover runs unguarded."
                )

            # A disarm between the binding and dispatch is fine ONLY on a path
            # that then `return`s (the semantic-cache hit records its own span
            # and leaves); a disarm that falls through to the dispatch guards
            # nothing.
            def _returns_right_after(k: int) -> bool:
                return any("return" in ln for ln in hdl[k + 1 : k + 4])

            if h_dispatch is not None and any(
                h_bind < d < h_dispatch and not _returns_right_after(d) for d in disarms
            ):
                errors.append(
                    "chat_completions_handler: `dispatch_guard.disarm()` runs BEFORE "
                    "`dispatch_with_retry(` on a path that continues to it — disarmed for "
                    "the await it exists to cover."
                )
            if h_sse is not None:
                # (e) the guard rides INTO the generator; the call carries
                # `Some(dispatch_guard)` within a few lines of the call.
                call_window = "".join(hdl[h_sse : h_sse + 40])
                if "Some(dispatch_guard)" not in call_window:
                    errors.append(
                        "chat_completions_handler: the streaming branch calls "
                        "`provider_stream_to_sse(` without handing it `Some(dispatch_guard)` — a "
                        "client that hangs up before the body's first poll is recorded by nothing (M-4)."
                    )
                if any(
                    h_dispatch is not None and h_dispatch < d < h_sse for d in disarms
                ):
                    errors.append(
                        "chat_completions_handler: `dispatch_guard.disarm()` BEFORE "
                        "`provider_stream_to_sse(` — the finalizer does not exist until the "
                        "body's first poll, so that window is unrecorded (M-4)."
                    )
            if h_buf is not None and not any(d > h_buf for d in disarms):
                errors.append(
                    "chat_completions_handler: no `dispatch_guard.disarm()` after "
                    "`buffer_provider_stream(` — every completed buffered request would ALSO "
                    "record a `client_cancelled` span."
                )

    return errors


# --------------------------------------------------------------------------
# selftest
#
# The guard reads source and reports on its structure, so every case is a
# planted `server.rs`-shaped text fed to check() in memory: nothing is written, and
# the working tree cannot be disturbed. Each planted defect is a real one —
# the buffered-after-filter ordering IS the #81 span drop, and the span-inside-
# the-loop shape is how the streaming path lost spans on a mid-stream Block.
# --------------------------------------------------------------------------

_GOOD_BUFFERED = """\
async fn buffer_provider_stream(ctx: &Ctx, s: Stream) -> Result<Response> {
    let body = collect(s).await?;
    let span = build_gateway_span(ctx, &body);
    publish(span);
    if let Some(block) = guard.check(&body) {
        return content_filter_response(block);
    }
    Ok(body.into_response())
}
"""

_BAD_BUFFERED = """\
async fn buffer_provider_stream(ctx: &Ctx, s: Stream) -> Result<Response> {
    let body = collect(s).await?;
    if let Some(block) = guard.check(&body) {
        return content_filter_response(block);
    }
    let span = build_gateway_span(ctx, &body);
    publish(span);
    Ok(body.into_response())
}
"""

_NOSPAN_BUFFERED = """\
async fn buffer_provider_stream(ctx: &Ctx, s: Stream) -> Result<Response> {
    let body = collect(s).await?;
    if let Some(block) = guard.check(&body) {
        return content_filter_response(block);
    }
    Ok(body.into_response())
}
"""

_FINALIZER = """\
struct StreamFinalizer { acc: String, finished: bool }
impl StreamFinalizer {
    fn finish(mut self) { self.finished = true; self.run(false); }
    fn run(&mut self, cancelled: bool) {
        let span = build_gateway_span(ctx, &self.acc);
        publish(span);
    }
}
impl Drop for StreamFinalizer {
    fn drop(&mut self) { if !self.finished { self.run(true); } }
}
"""

_GOOD_STREAMING = (
    _FINALIZER
    + """\
fn provider_stream_to_sse(ctx: &Ctx, s: Stream, handover: Option<DispatchGuard>) -> Response {
    let mut fin = StreamFinalizer { acc: String::new(), finished: false };
    if let Some(mut guard) = handover {
        guard.disarm();
    }
    loop {
        let chunk = match s.next().await {
            Some(c) => c,
            None => break,
        };
        fin.acc.push_str(&chunk);
    }
    fin.finish();
    sse.into_response()
}
"""
)

# The handover is disarmed BEFORE the finalizer exists (the M-4 window).
_STREAMING_DISARMS_BEFORE_FINALIZER = _GOOD_STREAMING.replace(
    "    let mut fin = StreamFinalizer { acc: String::new(), finished: false };\n"
    "    if let Some(mut guard) = handover {\n        guard.disarm();\n    }\n",
    "    if let Some(mut guard) = handover {\n        guard.disarm();\n    }\n"
    "    let mut fin = StreamFinalizer { acc: String::new(), finished: false };\n",
)

# The generator takes the handover and never disarms it.
_STREAMING_NEVER_DISARMS_HANDOVER = _GOOD_STREAMING.replace(
    "    if let Some(mut guard) = handover {\n        guard.disarm();\n    }\n", ""
)

# The pre-B-375 shape: span after the loop, no finalizer. It satisfied the OLD
# invariant and lost every cancelled stream. It must be refused now.
_PRE_B375_STREAMING = """\
fn provider_stream_to_sse(ctx: &Ctx, s: Stream) -> Response {
    let mut acc = String::new();
    loop {
        let chunk = match s.next().await {
            Some(c) => c,
            None => break,
        };
        acc.push_str(&chunk);
    }
    let span = build_gateway_span(ctx, &acc);
    publish(span);
    sse.into_response()
}
"""

_BAD_STREAMING = (
    _FINALIZER
    + """\
fn provider_stream_to_sse(ctx: &Ctx, s: Stream) -> Response {
    let mut fin = StreamFinalizer { acc: String::new(), finished: false };
    loop {
        let chunk = match s.next().await {
            Some(c) => c,
            None => break,
        };
        fin.acc.push_str(&chunk);
        fin.finish();
    }
    sse.into_response()
}
"""
)

_NOSPAN_STREAMING = (
    _FINALIZER
    + """\
fn provider_stream_to_sse(ctx: &Ctx, s: Stream) -> Response {
    let mut acc = String::new();
    loop {
        let chunk = match s.next().await {
            Some(c) => c,
            None => break,
        };
        acc.push_str(&chunk);
    }
    sse.into_response()
}
"""
)

_DECORATIVE_DROP = _GOOD_STREAMING.replace(
    "fn drop(&mut self) { if !self.finished { self.run(true); } }",
    "fn drop(&mut self) { /* forgot to finalize */ }",
)

_RUN_WITHOUT_SPAN = _GOOD_STREAMING.replace(
    "        let span = build_gateway_span(ctx, &self.acc);\n        publish(span);\n",
    "        // publish moved elsewhere\n",
)

# The admission pipeline, B-385: the guard is armed AFTER the ledger publish.
_GOOD_ADMISSION = """\
async fn run<R: Route>(state: &AppState, body: R::Body) -> Result<Admitted<R>, Refusal> {
    let parsed = R::parse(body)?;
    if let Err(err) = state.audit_chain.publish(audit_event).await {
        return Err(Refusal::AuditUnavailable);
    }
    let dispatch_guard = DispatchGuard::arm(state, tenant_id, trace_id);
    Ok(Admitted { parsed, dispatch_guard })
}
"""

# Armed before the row exists: a refused request would record a cancellation.
_ADMISSION_ARMS_BEFORE_PUBLISH = """\
async fn run<R: Route>(state: &AppState, body: R::Body) -> Result<Admitted<R>, Refusal> {
    let dispatch_guard = DispatchGuard::arm(state, tenant_id, trace_id);
    let parsed = R::parse(body)?;
    if let Err(err) = state.audit_chain.publish(audit_event).await {
        return Err(Refusal::AuditUnavailable);
    }
    Ok(Admitted { parsed, dispatch_guard })
}
"""

_ADMISSION_NEVER_ARMS = """\
async fn run<R: Route>(state: &AppState, body: R::Body) -> Result<Admitted<R>, Refusal> {
    let parsed = R::parse(body)?;
    if let Err(err) = state.audit_chain.publish(audit_event).await {
        return Err(Refusal::AuditUnavailable);
    }
    Ok(Admitted { parsed })
}
"""

# (name, source, substring the verdict must contain — None means "must pass")
_GOOD_HANDLER = """\
pub(crate) async fn chat_completions_handler(state: State, body: Json) -> Response {
    let admitted = match crate::admission::admit::<Chat>(&state, &headers, body).await {
        Ok(a) => a,
        Err(refusal) => return Chat::refuse(refusal),
    };
    let crate::admission::Admitted { parsed, mut dispatch_guard, .. } = admitted;
    if let Some(hit) = cache_hit {
        dispatch_guard.disarm();
        return hit.into_response();
    }
    let provider_result = dispatch_with_retry(&state.providers, &req, &key, &model, tenant_id).await;
    if is_streaming {
        let sse = provider_stream_to_sse(provider_stream, completion_id, Some(dispatch_guard));
        Sse::new(sse).into_response()
    } else {
        let resp = buffer_provider_stream(provider_stream, &model, &state).await;
        dispatch_guard.disarm();
        resp.into_response()
    }
}
"""

# No guard at all: the pre-B-375(b) shape.
_HANDLER_NO_GUARD = (
    _GOOD_HANDLER.replace(
        "    let crate::admission::Admitted { parsed, mut dispatch_guard, .. } = admitted;\n",
        "    let crate::admission::Admitted { parsed, .. } = admitted;\n",
    )
    .replace("        dispatch_guard.disarm();\n", "")
    .replace(", Some(dispatch_guard))", ")")
)

# The handler arms a SECOND guard beside the one admission handed it.
_HANDLER_ARMS_ITSELF = _GOOD_HANDLER.replace(
    "    let crate::admission::Admitted { parsed, mut dispatch_guard, .. } = admitted;\n",
    "    let crate::admission::Admitted { parsed, .. } = admitted;\n"
    "    let mut dispatch_guard = DispatchGuard::arm(&state, tenant_id, trace_id);\n",
)

# Disarmed BEFORE the await it exists to cover.
_HANDLER_DISARMED_EARLY = _GOOD_HANDLER.replace(
    "    let provider_result = dispatch_with_retry(",
    "    dispatch_guard.disarm();\n    let provider_result = dispatch_with_retry(",
)

# The OLD streaming shape: disarmed before the call, nothing handed over (M-4).
_HANDLER_STREAMING_DISARMS_EARLY = _GOOD_HANDLER.replace(
    "        let sse = provider_stream_to_sse(provider_stream, completion_id, Some(dispatch_guard));\n",
    "        dispatch_guard.disarm();\n"
    "        let sse = provider_stream_to_sse(provider_stream, completion_id);\n",
)

# Buffered branch never disarms: every completed request also records a cancel.
_HANDLER_BUFFERED_NEVER_DISARMS = _GOOD_HANDLER.replace(
    "        let resp = buffer_provider_stream(provider_stream, &model, &state).await;\n"
    "        dispatch_guard.disarm();\n",
    "        let resp = buffer_provider_stream(provider_stream, &model, &state).await;\n",
)

SELFTEST_CASES: list[tuple[str, str, str, str | None]] = [
    (
        "clean_all_paths",
        _GOOD_BUFFERED + _GOOD_STREAMING + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        None,
    ),
    (
        "streaming_branch_that_disarms_before_the_call_is_refused (M-4)",
        _GOOD_BUFFERED + _GOOD_STREAMING + _HANDLER_STREAMING_DISARMS_EARLY,
        _GOOD_ADMISSION,
        "without handing it `Some(dispatch_guard)`",
    ),
    (
        "generator_that_disarms_the_handover_before_the_finalizer_is_refused (M-4)",
        _GOOD_BUFFERED + _STREAMING_DISARMS_BEFORE_FINALIZER + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "BEFORE the `StreamFinalizer`",
    ),
    (
        "generator_that_never_disarms_the_handover_is_refused (M-4)",
        _GOOD_BUFFERED + _STREAMING_NEVER_DISARMS_HANDOVER + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "never disarmed",
    ),
    (
        "admission_that_arms_before_the_publish_is_refused",
        _GOOD_BUFFERED + _GOOD_STREAMING + _GOOD_HANDLER,
        _ADMISSION_ARMS_BEFORE_PUBLISH,
        "is BEFORE the ledger publish",
    ),
    (
        "admission_that_never_arms_is_refused",
        _GOOD_BUFFERED + _GOOD_STREAMING + _GOOD_HANDLER,
        _ADMISSION_NEVER_ARMS,
        "admission.rs::run: no `DispatchGuard::arm(`",
    ),
    (
        "admission_run_deleted",
        _GOOD_BUFFERED + _GOOD_STREAMING + _GOOD_HANDLER,
        "",
        "could not find `fn run` in admission.rs",
    ),
    (
        "handler_that_arms_its_own_guard_is_refused",
        _GOOD_BUFFERED + _GOOD_STREAMING + _HANDLER_ARMS_ITSELF,
        _GOOD_ADMISSION,
        "arms its OWN",
    ),
    (
        "handler_without_dispatch_guard_is_refused",
        _GOOD_BUFFERED + _GOOD_STREAMING + _HANDLER_NO_GUARD,
        _GOOD_ADMISSION,
        "no `dispatch_guard`",
    ),
    (
        "handler_disarmed_before_dispatch_is_refused",
        _GOOD_BUFFERED + _GOOD_STREAMING + _HANDLER_DISARMED_EARLY,
        _GOOD_ADMISSION,
        "disarmed for the await it exists to cover",
    ),
    (
        "handler_buffered_branch_never_disarms_is_refused",
        _GOOD_BUFFERED + _GOOD_STREAMING + _HANDLER_BUFFERED_NEVER_DISARMS,
        _GOOD_ADMISSION,
        "no `dispatch_guard.disarm()` after",
    ),
    (
        "handler_fn_deleted",
        _GOOD_BUFFERED + _GOOD_STREAMING,
        _GOOD_ADMISSION,
        "could not find `fn chat_completions_handler`",
    ),
    (
        "buffered_span_after_content_filter",
        _BAD_BUFFERED + _GOOD_STREAMING + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "is AFTER the content_filter_response",
    ),
    (
        "buffered_span_missing",
        _NOSPAN_BUFFERED + _GOOD_STREAMING + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "the flight recorder is off",
    ),
    (
        "streaming_finish_inside_loop",
        _GOOD_BUFFERED + _BAD_STREAMING + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "is INSIDE the stream loop",
    ),
    (
        "streaming_no_finalizer_constructed",
        _GOOD_BUFFERED + _NOSPAN_STREAMING + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "no `StreamFinalizer { .. }` constructed",
    ),
    (
        "pre_b375_shape_span_after_loop_is_refused",
        _GOOD_BUFFERED + _PRE_B375_STREAMING + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "back INSIDE the generator",
    ),
    (
        "decorative_drop_is_refused",
        _GOOD_BUFFERED + _DECORATIVE_DROP + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "Drop is decorative",
    ),
    (
        "run_without_span_is_refused",
        _GOOD_BUFFERED + _RUN_WITHOUT_SPAN + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "does not call `build_gateway_span(`",
    ),
    (
        "buffered_fn_deleted",
        _GOOD_STREAMING + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "could not find `fn buffer_provider_stream`",
    ),
    (
        "streaming_fn_deleted",
        _GOOD_BUFFERED + _GOOD_HANDLER,
        _GOOD_ADMISSION,
        "could not find `fn provider_stream_to_sse`",
    ),
]


def selftest() -> int:
    failures = 0
    for name, src, adm, expect in SELFTEST_CASES:
        errors = check(src.splitlines(), adm.splitlines())
        if expect is None:
            ok = not errors
            detail = "clean input passes" if ok else f"unexpected: {errors}"
        else:
            ok = any(expect in e for e in errors)
            detail = (
                f"blocked on {expect!r}"
                if ok
                else f"NOT blocked; got {errors or 'no errors'}"
            )
        print(f"  {'✓' if ok else '✗'} {name}: {detail}")
        if not ok:
            failures += 1

    if failures:
        print(f"\nselftest FAILED — {failures}/{len(SELFTEST_CASES)} case(s).")
        return 2
    print(
        f"\n{len(SELFTEST_CASES)} cases: the guard blocks the #81 orderings and passes "
        "the correct one."
    )
    print("selftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="#81 span-drop ordering guard for crates/gateway/src/server.rs + server/*.rs"
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant the #81 orderings and prove the guard blocks them",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    errors = check(server_lines(), ADMISSION.read_text().splitlines())
    if errors:
        sys.stderr.write("FAIL: #81 span-drop regression —\n")
        for e in errors:
            sys.stderr.write("  - " + e + "\n")
        return 1

    print(
        "OK: buffered span before the content-filter block; streaming span Drop-finalized "
        "(StreamFinalizer::run reached from both finish() and Drop); DispatchGuard armed by "
        "admission after the ledger publish and disarmed at every span site"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
