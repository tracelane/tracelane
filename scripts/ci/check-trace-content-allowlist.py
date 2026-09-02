#!/usr/bin/env python3
"""The GWY-45 content-capture allowlist may name ONLY the internal tenant.

WHY THIS EXISTS — a retention precondition that would otherwise be prose.

GWY-45 captures customer prompt text into the span's `attributes` blob. Content
placed there inherits the GLOBAL row TTL and **cannot be expired separately**,
because `spans.attributes` is a single `String` column.

THE TTL IS **365 DAYS**, NOT 90 — corrected 2026-08-22. This docstring said
"GLOBAL 90-day row TTL ... verified against prod, not assumed", and it was wrong
by 4x, inside a guard claiming to have checked. Asked at the widest scope the
server offers (`system.tables.create_table_query` on the live prod ClickHouse):
`spans` carries `TTL toDate(start_time) + toIntervalDay(365)`. The 90 belongs to
`guardrail_verdicts`. The CONCLUSION is unchanged and in fact stronger — a year
of customer prompt text on one un-replicated box is a bigger retention promise
than a quarter — but a wrong number in the rationale is how the next reader
recomputes the wrong risk, and "verified against prod" made it unfalsifiable by
anyone who trusted it. Content-specific retention therefore needs dedicated
columns with a ClickHouse column-level TTL, which is deliberately NOT built for
v1: for our own synthetic dogfood traffic it would be speculative work.

That makes "do not add a customer tenant until the 30-day column TTL exists" a
PRECONDITION. This repo has just spent a session proving that a precondition
written as prose does not survive — `docs/reference/TRAPS.md` §40 is about the
author of a guard reintroducing the very defect it guards, 48 hours later, with
a confident comment saying it did not apply. So the precondition is a check.

WHAT IT ALLOWS, and why exactly one id:
  the internal dogfood/canary tenant, whose traffic is a fixed 15-prompt array
  we wrote (`/opt/tracelane/dogfood/dogfood.sh`). Nobody's private text.

TO ADD A REAL TENANT you must first land the dedicated-column + 30-day column
TTL work, then widen `ALLOWED` here in the same change. Editing this list on its
own is the thing the guard exists to stop, and reviewers should treat a lone
change to `ALLOWED` as the finding.

USAGE
  check-trace-content-allowlist.py            # scan the shipped prod config
  check-trace-content-allowlist.py --selftest # prove it BLOCKS
EXIT 0 clean · 1 a non-internal tenant is allowlisted · 2 bad usage
"""

from __future__ import annotations

import pathlib
import re
import sys

CONFIG = pathlib.Path("infra/prod/tracelane.yaml")

# The internal dogfood/canary tenant. Everything else requires the retention work.
ALLOWED = {"a4037bef-e786-44e3-bfb6-88c93ba9d381"}

_BLOCK = re.compile(r"^trace_content:\s*$", re.MULTILINE)
_TENANTS = re.compile(r"^\s+tenants:\s*(.+?)\s*$", re.MULTILINE)


def offenders(text: str) -> list[str]:
    """Tenant ids present in a `trace_content:` block that are not internal."""
    m = _BLOCK.search(text)
    if not m:
        return []  # no block => capture is off entirely => nothing to police
    # Only look at the lines belonging to that block: stop at the next
    # zero-indent key, or EOF.
    rest = text[m.end() :]
    end = re.search(r"^\S", rest, re.MULTILINE)
    block = rest[: end.start()] if end else rest

    tm = _TENANTS.search(block)
    if not tm:
        return []  # a block with no tenants: the parser itself refuses this
    raw = tm.group(1).split("#", 1)[0]
    ids = [t.strip() for t in raw.split(",") if t.strip()]
    return [t for t in ids if t not in ALLOWED]


def selftest() -> int:
    internal = next(iter(ALLOWED))
    cases = [
        ("", [], "no block at all => nothing to police"),
        (
            f"trace_content:\n  tenants: {internal}\n",
            [],
            "the internal tenant alone is fine",
        ),
        (
            f"trace_content:\n  tenants: {internal}  # dogfood\n",
            [],
            "a trailing comment must not be read as a tenant",
        ),
        (
            "trace_content:\n  tenants: 11111111-2222-3333-4444-555555555555\n",
            ["11111111-2222-3333-4444-555555555555"],
            "A CUSTOMER TENANT MUST BLOCK — this is the whole point",
        ),
        (
            f"trace_content:\n  tenants: {internal}, 99999999-8888-7777-6666-555555555555\n",
            ["99999999-8888-7777-6666-555555555555"],
            "smuggling one in beside the internal id must still block",
        ),
        (
            f"models:\n  a: b/c\ntrace_content:\n  tenants: {internal}\nfailover:\n  chain: x\n",
            [],
            "the block must be located correctly among other blocks",
        ),
    ]
    for text, expected, why in cases:
        got = offenders(text)
        if got != expected:
            print(f"SELFTEST FAILED — {why}\n  expected {expected}, got {got}")
            return 1
    print(
        f"SELFTEST PASSED — {len(cases)} cases: a customer tenant BLOCKS (alone and "
        "smuggled), the internal one does not, and a trailing comment is not a tenant."
    )
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print(__doc__)
        return 2
    if not CONFIG.exists():
        print(f"✗ {CONFIG} does not exist — cannot determine, which is not a pass")
        return 2
    bad = offenders(CONFIG.read_text(encoding="utf-8"))
    if bad:
        print(f"✗ non-internal tenant(s) allowlisted for content capture in {CONFIG}:")
        for t in bad:
            print(f"    {t}")
        print(
            "\n  Capturing a customer's prompt text requires content-specific\n"
            "  retention FIRST: dedicated columns with a 30-day ClickHouse column\n"
            "  TTL. Content in `attributes` inherits the global 365-day row TTL\n"
            "  cannot be expired separately — `spans.attributes` is one String\n"
            "  column. Land that work, then widen ALLOWED in the same change."
        )
        return 1
    print(f"OK — {CONFIG} allowlists no tenant beyond the internal one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
