#!/usr/bin/env python3
"""No `info!` on a per-request path. Repetition belongs in a counter, not a log line.

WHY. At 5,000 rps one 200-byte line per request is ~86 GB/day — an outage, on a single
un-replicated volume that also holds the ClickHouse data and the tamper-evident ledger.
And volume arrives before traffic does: on a NEAR-IDLE box, ClickHouse's own `text_log` at
upstream's default `trace` level produced 78.6 MiB/day, 66% of all disk growth (O1).

The sharper failure is not size, it is uselessness. Ingest's tenant-config resolver
emitted a `warn!` PER RESOLVE for three weeks — ~300,000 identical lines — and told nobody
anything. The information content of line 300,000 is zero; that it was STILL HAPPENING was
the whole story, and no log line can express duration. `crates/shared/src/degradation.rs`
is the right medium: count + first_seen + last_seen, one rate-limited WARN on entering the
state. Logs do not alert; counters do. (`.claude/rules/logging.md`, TRAPS §16.)

WHAT IT CHECKS. For each named per-request function below, the body is extracted by brace
matching and scanned for `info!`. An occurrence must be on the ALLOWLIST with a written
reason, or it fails.

HONEST LIMIT — read before trusting a pass. This reads the NAMED function bodies only. An
`info!` reached through a helper the handler calls is INVISIBLE to it, and so is one added
to a per-request path not listed in HOT_PATHS. It also cannot judge whether a call is
genuinely per-request or conditional on a rare transition — that is what the allowlist
reason is for, and a human reads it. This closes the obvious hole, not the class.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# (file, function) pairs that run per request / per span.
HOT_PATHS = [
    ("crates/gateway/src/server.rs", "chat_completions_handler"),
    ("crates/gateway/src/server.rs", "embeddings_handler"),
    ("crates/gateway/src/server.rs", "spawn_span_publish"),
    ("crates/ingest/src/clickhouse_writer.rs", "flush"),
]

# An `info!` that is a genuine STATE TRANSITION rather than a per-request event.
# Each entry must carry the reason; the reason is the control, not the entry.
ALLOWLIST = {
    (
        "crates/gateway/src/server.rs",
        "chat_completions_handler",
        "tracelane.failover.cross_provider.activated=true",
    ): (
        "Cross-provider failover ACTIVATING is a routing state transition, not a "
        "per-request event — it fires when the primary starts failing, not when a "
        "request arrives. Rare by construction; if it were per-request the breaker "
        "would already be open."
    ),
}

RE_INFO = re.compile(r"\binfo!\s*\(")


def extract_fn(src: str, fn: str) -> tuple[str, int] | None:
    """Body of `fn` by brace matching. Returns (body, start_line) or None."""
    m = re.search(rf"(?m)^\s*(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(fn)}\s*[(<]", src)
    if not m:
        return None
    i = src.index("{", m.start())
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return src[i : j + 1], src[: m.start()].count("\n") + 1


def scan(src: str, rel: str, fn: str) -> list[str]:
    got = extract_fn(src, fn)
    if got is None:
        # A renamed/removed hot-path fn must be LOUD — silently checking nothing is how
        # a guard becomes decorative.
        return [
            f"{rel}: hot-path fn `{fn}` NOT FOUND — update HOT_PATHS or the guard is checking nothing"
        ]
    body, start = got
    hits: list[str] = []
    for m in RE_INFO.finditer(body):
        line_in_body = body[: m.start()].count("\n")
        # The marker string is what identifies an allowlisted call.
        window = body[m.start() : m.start() + 600]
        allowed = any(k[0] == rel and k[1] == fn and k[2] in window for k in ALLOWLIST)
        if not allowed:
            hits.append(
                f"{rel}:{start + line_in_body}: `info!` inside per-request fn `{fn}` — "
                f"INFO is lifecycle and state TRANSITIONS only"
            )
    return hits


def check() -> tuple[int, list[str]]:
    findings, n = [], 0
    for rel, fn in HOT_PATHS:
        p = ROOT / rel
        if not p.exists():
            findings.append(f"{rel}: file not found (HOT_PATHS is stale)")
            continue
        n += 1
        findings.extend(scan(p.read_text(encoding="utf-8"), rel, fn))
    return n, findings


def selftest() -> int:
    clean = 'async fn h(a: u8) {\n    tracing::warn!("x");\n    do_work();\n}\n'
    assert not scan(clean, "f.rs", "h"), "selftest: a clean handler must PASS"
    print("✓ selftest: a handler with no info! passes")

    dirty = 'async fn h(a: u8) {\n    tracing::info!("per request");\n}\n'
    hits = scan(dirty, "f.rs", "h")
    assert len(hits) == 1 and "per-request fn" in hits[0], f"got {hits}"
    print("✓ selftest: an info! inside a per-request fn is CAUGHT")

    # Brace matching must not stop at a nested block.
    nested = 'async fn h() {\n    if x {\n        let s = 1;\n    }\n    tracing::info!("late");\n}\n'
    assert scan(nested, "f.rs", "h"), "selftest: must scan past nested braces"
    print("✓ selftest: nested blocks do not truncate the scan")

    # An info! OUTSIDE the function must not fire — scoping, not repo-wide grep.
    outside = (
        'fn other() {\n    tracing::info!("fine");\n}\nasync fn h() {\n    ok();\n}\n'
    )
    assert not scan(outside, "f.rs", "h"), "selftest: only the named fn is in scope"
    print("✓ selftest: info! outside the named fn is ignored (scoped)")

    # A missing hot-path fn must be LOUD, not silently green.
    hits = scan("fn unrelated() {}\n", "f.rs", "gone")
    assert hits and "NOT FOUND" in hits[0], f"got {hits}"
    print(
        "✓ selftest: a renamed/removed hot-path fn FAILS rather than checking nothing"
    )

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="per-request INFO logging gate")
    ap.add_argument("--selftest", action="store_true", help="prove the gate blocks")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    n, findings = check()
    for f in findings:
        print(f"FAIL {f}")
    if findings:
        print(
            "\nINFO is lifecycle and state TRANSITIONS only. At 5,000 rps one 200-byte\n"
            "line per request is ~86 GB/day. A REPEATING condition gets a COUNTER, not a\n"
            "line per occurrence — crates/shared/src/degradation.rs records count +\n"
            "first_seen + last_seen and emits ONE rate-limited WARN. Logs do not alert.\n"
            "If this call really is a rare state transition, add it to ALLOWLIST WITH THE\n"
            "REASON. See .claude/rules/logging.md."
        )
        return 1
    print(f"hot-path logging: {n} per-request fn(s) checked, no unallowlisted info!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
