#!/usr/bin/env python3
"""Coverage guard for scripts/proofs/read-route-smoke.sh — B-336.

WHY THIS EXISTS. Gateway `d1ed7d30` answered 502 to ANY read request
carrying `until=` on five /v1 routes, and the five existing deploy proofs
never sent that parameter, so nothing caught it before a customer did.
scripts/proofs/read-route-smoke.sh is the fix; this is what stops it from
rotting the way every route-list ratchet in this repo rots — a route added
to `trace_reads.rs::routes()` (the read-route family that produced B-336)
without a matching line in the smoke script's table.

WHAT IT PARSES. Every literal `.route("/v1/...", get(...))` registration in:
  - crates/gateway/src/server.rs        (the one direct GET /v1 route it
                                          registers itself: /v1/auth/whoami)
  - crates/gateway/src/trace_reads.rs   (routes(), merged into the gateway
                                          by server.rs — the B-336 surface)
against every `check_route "GET /v1/..."` / `skip_line "GET /v1/..."` line in
scripts/proofs/read-route-smoke.sh's route table. A route missing from the
table fails, unless it is named in EXEMPT with a reason (e.g. streaming/SSE,
which a one-shot buffered-JSON assertion cannot cover).

Both source files are scanned ONLY up to their first `#[cfg(test)]` — the
same technique `the_embeddings_route_is_mounted_unconditionally` in
server.rs already uses ("this literal does not match itself"). Without it, a
route string quoted inside a test fixture or assertion (server.rs has one at
`both_methods_on_v1_traces_coexist`) would count as a real, mounted route.

--selftest plants a missing-route violation (a temp copy of the smoke
table with one route deleted) and proves the guard catches it, plus the
EXEMPT and test-prefix-exclusion directions. Unknown flags exit 2
(argparse's default).

Exit 0 + "OK — N routes, all covered" on success. Exit 1 on any gap.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERVER_RS = REPO / "crates/gateway/src/server.rs"
TRACE_READS_RS = REPO / "crates/gateway/src/trace_reads.rs"
SMOKE_SH = REPO / "scripts/proofs/read-route-smoke.sh"

TEST_MARKER = "#[cfg(test)]"

# route -> reason a route registered in source is allowed to be ABSENT from
# the smoke table. Empty by design: every route trace_reads.rs / server.rs
# register today is a plain request/JSON-response handler the table covers.
# A future streaming/SSE GET /v1 route belongs here, not deleted from
# discovery — the point is that its absence is a DECISION, on record, not a
# guard that quietly stopped looking.
EXEMPT: dict[str, str] = {}

ROUTE_RE = re.compile(r'\.route\(\s*"(?P<path>/v1/[^"]+)"\s*,\s*get\(', re.DOTALL)
CHECK_RE = re.compile(r'check_route\s+"GET\s+(?P<path>/v1/[^"]+)"')
SKIP_RE = re.compile(r'skip_line\s+"GET\s+(?P<path>/v1/[^"]+)"')


def non_test_prefix(text: str) -> str:
    i = text.find(TEST_MARKER)
    return text if i == -1 else text[:i]


def find_registered_routes(path: Path) -> set[str]:
    if not path.exists():
        return set()
    text = non_test_prefix(path.read_text(encoding="utf-8", errors="replace"))
    return {m.group("path") for m in ROUTE_RE.finditer(text)}


def find_smoke_table(path: Path) -> set[str]:
    if not path.exists():
        return set()
    text = path.read_text(encoding="utf-8", errors="replace")
    covered = {m.group("path") for m in CHECK_RE.finditer(text)}
    covered |= {m.group("path") for m in SKIP_RE.finditer(text)}
    return covered


def run(server_rs: Path, trace_reads_rs: Path, smoke_sh: Path) -> list[str]:
    found = find_registered_routes(server_rs) | find_registered_routes(trace_reads_rs)
    if not found:
        return [
            (
                f"found ZERO GET /v1 routes in {server_rs} or {trace_reads_rs} — "
                "the discovery regex broke, not that the read-route surface "
                "shrank to nothing."
            )
        ]
    covered = find_smoke_table(smoke_sh)
    missing = sorted(r for r in found - covered if r not in EXEMPT)
    failures = []
    for r in missing:
        failures.append(
            f"{r} is a registered GET /v1 route with no matching `check_route` "
            f'or `skip_line "GET {r}"` line in '
            f"{smoke_sh.relative_to(REPO) if smoke_sh.is_relative_to(REPO) else smoke_sh} "
            f"— add it to the smoke table, or add {r!r} to EXEMPT with a reason."
        )
    return failures


def selftest() -> int:
    ok = True
    with tempfile.TemporaryDirectory() as td_str:
        td = Path(td_str)
        server = td / "server.rs"
        server.write_text('.route("/v1/auth/whoami", get(whoami_handler))\n')

        reads = td / "trace_reads.rs"
        reads.write_text(
            "pub fn routes() -> Router<TraceReadState> {\n"
            "    Router::new()\n"
            '        .route("/v1/traces", get(list_traces_handler))\n'
            '        .route("/v1/slo", get(slo_handler))\n'
            "        .route(\n"
            '            "/v1/query/latency-breakdown",\n'
            "            get(latency_breakdown_handler),\n"
            "        )\n"
            "}\n"
        )

        good = td / "smoke_good.sh"
        good.write_text(
            'check_route "GET /v1/auth/whoami" "$G/v1/auth/whoami" "$BODY" 0\n'
            'check_route "GET /v1/traces" "$G/v1/traces?x" "$BODY" 0\n'
            'check_route "GET /v1/slo" "$G/v1/slo?x" "$BODY" 0\n'
            'check_route "GET /v1/query/latency-breakdown" '
            '"$G/v1/query/latency-breakdown?x" "$BODY" 0\n'
        )

        # 1. A complete table must PASS.
        fails = run(server, reads, good)
        if fails:
            print(f"SELFTEST FAIL: a complete table was flagged: {fails}")
            ok = False

        # 2. THE PLANTED VIOLATION — one route (/v1/slo) deleted from the
        #    table — must be CAUGHT.
        bad = td / "smoke_bad.sh"
        bad.write_text(
            'check_route "GET /v1/auth/whoami" "$G/v1/auth/whoami" "$BODY" 0\n'
            'check_route "GET /v1/traces" "$G/v1/traces?x" "$BODY" 0\n'
            'check_route "GET /v1/query/latency-breakdown" '
            '"$G/v1/query/latency-breakdown?x" "$BODY" 0\n'
        )
        fails = run(server, reads, bad)
        if not any("/v1/slo" in f for f in fails):
            print("SELFTEST FAIL: did not catch the deleted /v1/slo row")
            ok = False

        # 3. A route-shaped literal that exists ONLY past `#[cfg(test)]` must
        #    NOT be discovered as a real route — else a fixture or assertion
        #    string (server.rs has exactly this shape in
        #    both_methods_on_v1_traces_coexist) would wrongly demand smoke
        #    coverage for something that was never actually mounted.
        phantom = td / "trace_reads_phantom.rs"
        phantom.write_text(
            reads.read_text()
            + "\n#[cfg(test)]\nmod tests {\n"
            + "    fn f() {\n"
            + '        let _ = Router::new().route("/v1/costs", get(cost_breakdown_handler));\n'
            + "    }\n"
            + "}\n"
        )
        fails = run(server, phantom, good)
        if any("/v1/costs" in f for f in fails):
            print(
                "SELFTEST FAIL: a route quoted only past #[cfg(test)] was "
                "discovered as real and demanded of the smoke table"
            )
            ok = False

        # 4. An EXEMPT route with a reason, absent from the table, must NOT
        #    fail the guard.
        exempt_reads = td / "trace_reads_exempt.rs"
        base = reads.read_text().rstrip()
        assert base.endswith("}")
        exempt_reads.write_text(
            base[:-1] + '        .route("/v1/query/stream", get(stream_handler))\n}\n'
        )
        EXEMPT["/v1/query/stream"] = "selftest: SSE, no buffered JSON body to assert"
        try:
            fails = run(server, exempt_reads, good)
        finally:
            del EXEMPT["/v1/query/stream"]
        if any("/v1/query/stream" in f for f in fails):
            print("SELFTEST FAIL: an EXEMPT route was still demanded of the table")
            ok = False

    print("selftest: PASS" if ok else "selftest: FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()  # an unknown flag -> argparse.error() -> exit 2
    if args.selftest:
        return selftest()

    failures = run(SERVER_RS, TRACE_READS_RS, SMOKE_SH)
    if failures:
        print("\nFAIL: read-route smoke coverage\n")
        for f in failures:
            print(f"  - {f}")
        return 1

    found = find_registered_routes(SERVER_RS) | find_registered_routes(TRACE_READS_RS)
    print(f"OK — {len(found)} routes, all covered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
