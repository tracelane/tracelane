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
"""

import re
import sys
import pathlib

SRC = pathlib.Path("crates/gateway/src/server.rs")
lines = SRC.read_text().splitlines()


def fn_body(name):
    start = next(
        (i for i, ln in enumerate(lines) if re.search(rf"\bfn\s+{name}\b", ln)), None
    )
    if start is None:
        sys.exit(f"FAIL: could not find `fn {name}` in server.rs")
    end = next(
        (
            j
            for j in range(start + 1, len(lines))
            if re.match(r"^(async\s+)?fn\s", lines[j])
        ),
        len(lines),
    )
    return lines[start:end]


errors = []

# 1) Buffered: span publish before the content-filter block return.
buf = fn_body("buffer_provider_stream")
b_span = next((k for k, ln in enumerate(buf) if "build_gateway_span(" in ln), None)
b_cf = next((k for k, ln in enumerate(buf) if "content_filter_response(" in ln), None)
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
strm = fn_body("provider_stream_to_sse")
s_loop = next((k for k, ln in enumerate(strm) if re.search(r"\bloop\s*\{", ln)), None)
s_span = next((k for k, ln in enumerate(strm) if "build_gateway_span(" in ln), None)
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

if errors:
    sys.stderr.write("FAIL: #81 span-drop regression —\n")
    for e in errors:
        sys.stderr.write("  - " + e + "\n")
    sys.exit(1)

print(
    "OK: buffered span before the content-filter block; streaming span after the stream loop"
)
