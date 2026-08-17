#!/usr/bin/env python3
"""CI guard — #81 span-drop regression (both chat paths).

A trace span MUST be recorded for every dispatched request, including ones a
guardrail content-filters. Two structural invariants protect that:

1. BUFFERED (`buffer_provider_stream`): the span publish (`build_gateway_span`)
   must come BEFORE the response-side guardrail seam's `content_filter_response`
   return. Otherwise a blocked buffered response returns 200 and silently drops
   its span.

2. STREAMING (`provider_stream_to_sse`): the span publish must come AFTER the
   `loop { ... }` closes, so it is reached on EVERY termination (Done, a
   mid-stream content-filter Block `break`, stream-end, or a provider error) —
   not only on the Done happy path.

Runs in milliseconds, no infra — complements the e2e GC-TRACE-LOOP live-eval
gate (which exercises both the buffered and streaming paths against a real
ephemeral stack).

Exit codes:
    0 — both invariants hold
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


def fn_body(lines: list[str], name: str) -> list[str] | None:
    """Lines of `fn <name>`'s body, or None when the fn is gone."""
    start = next(
        (i for i, ln in enumerate(lines) if re.search(rf"\bfn\s+{name}\b", ln)), None
    )
    if start is None:
        return None
    end = next(
        (
            j
            for j in range(start + 1, len(lines))
            if re.match(r"^(async\s+)?fn\s", lines[j])
        ),
        len(lines),
    )
    return lines[start:end]


def check(lines: list[str]) -> list[str]:
    """Return every ordering violation found in `server.rs`'s lines."""
    errors: list[str] = []

    # 1) Buffered: span publish before the content-filter block return.
    buf = fn_body(lines, "buffer_provider_stream")
    if buf is None:
        errors.append("could not find `fn buffer_provider_stream` in server.rs")
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
        errors.append("could not find `fn provider_stream_to_sse` in server.rs")
    else:
        s_loop = next(
            (k for k, ln in enumerate(strm) if re.search(r"\bloop\s*\{", ln)), None
        )
        s_span = next(
            (k for k, ln in enumerate(strm) if "build_gateway_span(" in ln), None
        )
        if s_span is None:
            errors.append(
                "provider_stream_to_sse: no `build_gateway_span(` — streaming spans are not recorded."
            )
        elif s_loop is not None:
            depth = 0
            loop_close = None
            for k in range(s_loop, len(strm)):
                depth += strm[k].count("{") - strm[k].count("}")
                if k > s_loop and depth <= 0:
                    loop_close = k
                    break
            if loop_close is not None and s_span < loop_close:
                errors.append(
                    f"provider_stream_to_sse: span (`build_gateway_span` at +{s_span}) is INSIDE the "
                    f"stream loop (closes at +{loop_close}). A mid-stream content-filter Block / error / "
                    "stream-end `break` would skip it — publish the span AFTER the loop."
                )

    return errors


# --------------------------------------------------------------------------
# selftest
#
# The guard reads ONE file and reports on its structure, so every case is a
# planted `server.rs` shape fed to check() in memory: nothing is written, and
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

_GOOD_STREAMING = """\
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

_BAD_STREAMING = """\
fn provider_stream_to_sse(ctx: &Ctx, s: Stream) -> Response {
    let mut acc = String::new();
    loop {
        let chunk = match s.next().await {
            Some(c) => c,
            None => break,
        };
        acc.push_str(&chunk);
        let span = build_gateway_span(ctx, &acc);
        publish(span);
    }
    sse.into_response()
}
"""

_NOSPAN_STREAMING = """\
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

# (name, source, substring the verdict must contain — None means "must pass")
SELFTEST_CASES: list[tuple[str, str, str | None]] = [
    (
        "clean_both_paths",
        _GOOD_BUFFERED + _GOOD_STREAMING,
        None,
    ),
    (
        "buffered_span_after_content_filter",
        _BAD_BUFFERED + _GOOD_STREAMING,
        "is AFTER the content_filter_response",
    ),
    (
        "buffered_span_missing",
        _NOSPAN_BUFFERED + _GOOD_STREAMING,
        "the flight recorder is off",
    ),
    (
        "streaming_span_inside_loop",
        _GOOD_BUFFERED + _BAD_STREAMING,
        "is INSIDE the stream loop",
    ),
    (
        "streaming_span_missing",
        _GOOD_BUFFERED + _NOSPAN_STREAMING,
        "streaming spans are not recorded",
    ),
    (
        "buffered_fn_deleted",
        _GOOD_STREAMING,
        "could not find `fn buffer_provider_stream`",
    ),
    (
        "streaming_fn_deleted",
        _GOOD_BUFFERED,
        "could not find `fn provider_stream_to_sse`",
    ),
]


def selftest() -> int:
    failures = 0
    for name, src, expect in SELFTEST_CASES:
        errors = check(src.splitlines())
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
        description="#81 span-drop ordering guard for crates/gateway/src/server.rs"
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant the #81 orderings and prove the guard blocks them",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    errors = check(SRC.read_text().splitlines())
    if errors:
        sys.stderr.write("FAIL: #81 span-drop regression —\n")
        for e in errors:
            sys.stderr.write("  - " + e + "\n")
        return 1

    print(
        "OK: buffered span before the content-filter block; streaming span after the stream loop"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
