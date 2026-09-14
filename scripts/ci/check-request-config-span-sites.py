#!/usr/bin/env python3
"""GWY-48: every gateway span site that records a proxied request must apply the
request configuration — all FOUR of them.

WHY THIS EXISTS — the spec named this as the build's single most likely defect,
and named it before the code was written:

    "`RequestConfig` MUST reach all four, including SSE. … if streaming spans
     carry no `gen_ai_request_max_tokens`, then OBS-52's 'missing max_tokens'
     check fires on EVERY streamed request, and a detector that flags the absence
     of its own instrumentation is worse than no detector."

The streaming site is the one at risk: before GWY-48, `provider_stream_to_sse`
took no request-content parameter at all, so it is the only site where wiring
this in meant a new function argument rather than one more line beside an
existing `captured_input.apply(...)`. A future refactor that drops the argument
compiles clean, passes every unit test (they all exercise `apply` directly), and
silently produces half-instrumented spans.

WHAT THIS CAN AND CANNOT DO, printed in its own output because a guard that
implies more than it checks is worse than none:

  CAN:    prove an `apply` call is PRESENT at each of the four named span sites,
          and that the count has not silently dropped.
  CANNOT: prove it is reached at runtime, that its argument is the right one, or
          that the attributes land in ClickHouse. That half is the prod proof
          (`specs/GWY-48-request-config-on-spans.md` §9, proofs 1 and 5).

USAGE
  check-request-config-span-sites.py             # check the tree
  check-request-config-span-sites.py --selftest  # prove it BLOCKS a dropped site
EXIT 0 clean · 1 a span site lost its request-config apply · 2 bad usage
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# file -> (how many `RequestConfig`-shaped applies must be present, what they are)
#
# B-385 §2d (2026-09-12) split `server.rs` by concern, so the three OpenAI-shaped
# sites are three files now — one apply each, and a file that loses its ONE is a
# site that lost its request configuration. Listing them per file rather than
# summing across `server/*.rs` is deliberate: a sum of three would still pass if
# one site were duplicated and another deleted.
SITES = {
    "crates/gateway/src/server/chat.rs": (1, "the semantic-cache hit"),
    "crates/gateway/src/server/buffered.rs": (1, "the buffered response"),
    "crates/gateway/src/server/stream.rs": (1, "the streaming/SSE finalizer"),
    "crates/gateway/src/anthropic_messages.rs": (
        1,
        "the Anthropic-native POST /v1/messages span",
    ),
}

# `request_config.apply(...)`, `request_config.clone().apply(...)`,
# `ctx.request_config.apply(...)` — any receiver path ending in the field name.
APPLY_RE = re.compile(r"\brequest_config(?:\s*\.\s*clone\(\))?\s*\.\s*apply\s*\(")


def scan(text: str) -> int:
    return len(APPLY_RE.findall(text))


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for rel, (want, what) in SITES.items():
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel}: MISSING — the span sites live here")
            continue
        got = scan(path.read_text(encoding="utf-8"))
        if got < want:
            problems.append(
                f"{rel}: {got} request-config apply site(s), expected {want} "
                f"({what}). A span site lost its request configuration — "
                f"OBS-52 will mis-flag every request on that path."
            )
    return problems


def selftest() -> int:
    """Plant the exact regression and prove it BLOCKS, then prove a clean tree passes."""
    ok = True
    with tempfile.TemporaryDirectory() as td:
        fake = Path(td)
        for rel, (want, _) in SITES.items():
            p = fake / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("request_config.apply(&mut span.attributes);\n" * want)

        if check(fake):
            print("SELFTEST FAIL: a complete tree was reported as broken")
            ok = False
        else:
            print("selftest: a complete tree PASSES ✓")

        # The regression: the streaming site is dropped.
        server = fake / "crates/gateway/src/server/stream.rs"
        server.write_text("// no apply here\n")
        problems = check(fake)
        if problems and "server/stream.rs" in problems[0]:
            print("selftest: a DROPPED streaming apply BLOCKS ✓")
        else:
            print("SELFTEST FAIL: a dropped span site did not block")
            ok = False

        # And the file vanishing entirely.
        server.unlink()
        if any("MISSING" in p for p in check(fake)):
            print("selftest: a MISSING span file BLOCKS ✓")
        else:
            print("SELFTEST FAIL: a missing span file did not block")
            ok = False

    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        if argv[1] == "--selftest":
            return selftest()
        print(__doc__)
        return 2

    problems = check(ROOT)
    if problems:
        print("GWY-48 span-site guard: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1

    total = sum(w for w, _ in SITES.values())
    print(
        f"GWY-48 span-site guard: clean — {total} request-config apply sites present.\n"
        "  Proves PRESENCE only. That they are reached at runtime, with the right\n"
        "  argument, is the prod proof's job (specs/GWY-48 §9, proofs 1 and 5)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
