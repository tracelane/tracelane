#!/usr/bin/env python3
"""Concurrent gateway fan-out budget for dashboard surfaces.

WHY THIS EXISTS (2026-08-05, runbooks/RCA-dashboard-fanout-tail-latency.md):
`/dashboard` issued EIGHT gateway subrequests inside one `Promise.all`. That
resolves at the SLOWEST member, so the page sampled a heavy-tailed wide-area
link eight times and waited for the worst draw — 6s+ on every load, while the
gateway itself answered in 0.9ms on-node. Pages making 2-5 calls were fine.

The defect was invisible to every existing gate: the bench suite measures
GATEWAY latency (4.6ms p99, green throughout) and nothing measures latency from
where a customer stands. So the guard cannot be "is the page fast" — it has to
be the structural quantity that caused it: **how many gateway calls does one
render fire concurrently**.

Fan-out is a design decision, not an addition. Past the budget the correct move
is ONE aggregate endpoint served on-node (where each call costs 0.9ms), not an
Nth parallel call from the edge.

Exit 1 on violation. `--selftest` plants violations and asserts they are caught.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCAN_ROOTS = [REPO / "apps/web/app", REPO / "apps/web/components"]

# Default budget for any surface. Chosen from measurement, not taste: at 2-5
# concurrent calls the reported surfaces were fine; the one at 8 was not.
DEFAULT_BUDGET = 5

# Helpers that reach the gateway over the network. Anything that (transitively)
# performs a gateway fetch belongs here — the cost being counted is a WAN round
# trip, not a function call.
GATEWAY_CALLS = [
    "gatewayGet",
    "gatewayGetOrNull",
    "gatewayGetText",
    "gatewayPost",
    "fetchGatewayStats",
    "fetchLatencyBreakdown",
    "fetchGuardrailStats",
]
CALL_RE = re.compile(r"\b(" + "|".join(GATEWAY_CALLS) + r")\s*[<(]")

# Surfaces permitted above the budget, PINNED TO AN EXACT COUNT. A pinned count
# (not a bare exemption) is what makes this a ratchet: an allowlisted file that
# grows another call still fails. Shrink the number when the surface improves.
ALLOWLIST: dict[str, tuple[int, str]] = {
    "apps/web/app/dashboard/page.tsx": (
        8,
        (
            "RCA-dashboard-fanout-tail-latency: known 8-way fan-out. Mitigated "
            "by Smart Placement (Worker runs beside the origin, so the hops are "
            "short) and per-request auth memoization. The real fix is a single "
            "/v1/dashboard aggregate endpoint. Do NOT raise this number."
        ),
    ),
}


def find_concurrent_blocks(src: str) -> list[tuple[int, str]]:
    """Return (start_line, body) for every Promise.all([...]) / allSettled."""
    out: list[tuple[int, str]] = []
    for m in re.finditer(r"Promise\.(all|allSettled)\s*\(\s*\[", src):
        i = m.end() - 1  # at the '['
        depth = 0
        for j in range(i, len(src)):
            c = src[j]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    out.append((src.count("\n", 0, m.start()) + 1, src[i : j + 1]))
                    break
    return out


def scan_file(path: Path) -> tuple[int, int]:
    """Return (max concurrent gateway calls, line of the worst block)."""
    src = path.read_text(encoding="utf-8", errors="replace")
    worst, worst_line = 0, 0
    for line, body in find_concurrent_blocks(src):
        n = len(CALL_RE.findall(body))
        if n > worst:
            worst, worst_line = n, line
    return worst, worst_line


def iter_sources(roots: list[Path]):
    for root in roots:
        if not root.exists():
            continue
        for p in sorted(root.rglob("*.tsx")):
            if "node_modules" in p.parts:
                continue
            yield p


def run(roots: list[Path], repo: Path, quiet: bool = False) -> list[str]:
    failures: list[str] = []
    findings: list[tuple[str, int, int]] = []
    for p in iter_sources(roots):
        n, line = scan_file(p)
        if n == 0:
            continue
        rel = p.relative_to(repo).as_posix()
        findings.append((rel, n, line))

        pinned = ALLOWLIST.get(rel)
        if pinned is not None:
            allowed = pinned[0]
            if n > allowed:
                failures.append(
                    f"{rel}:{line} — {n} concurrent gateway calls, allowlisted at "
                    f"EXACTLY {allowed}. The allowlist is a ratchet: it records a "
                    f"known offender, it does not license growth. Collapse these "
                    f"into one aggregate endpoint."
                )
            continue

        if n > DEFAULT_BUDGET:
            failures.append(
                f"{rel}:{line} — {n} concurrent gateway calls exceeds the budget "
                f"of {DEFAULT_BUDGET}. Promise.all resolves at the SLOWEST member, "
                f"so this samples the wide-area tail {n} times per render. Serve "
                f"it from ONE aggregate endpoint instead of adding a parallel "
                f"call. See runbooks/RCA-dashboard-fanout-tail-latency.md."
            )

    if not quiet and findings:
        print("  concurrent gateway fan-out by surface:")
        for rel, n, line in sorted(findings, key=lambda x: -x[1]):
            pin = ALLOWLIST.get(rel)
            tag = f"  (allowlisted at {pin[0]})" if pin else ""
            flag = "  <-- OVER BUDGET" if (not pin and n > DEFAULT_BUDGET) else ""
            print(f"    {n:>2}  {rel}:{line}{tag}{flag}")
    return failures


# The one module that owns outbound gateway calls. Every fetch here crosses the
# wide-area link, so every one needs a ceiling.
GATEWAY_MODULE = REPO / "apps/web/lib/gateway.ts"
TIMEOUT_TOKEN = "AbortSignal.timeout"


def check_timeouts(module: Path) -> list[str]:
    """Every fetch in the gateway seam must carry an abort timeout.

    Amplifier #2 of the /dashboard incident: `lib/gateway.ts` had NO timeout on
    any seam, so a single stalled subrequest held the page open indefinitely.
    Fixed by hand — but nothing stopped a fourth seam being added without one,
    which is how the same defect comes back wearing a different function name.
    """
    if not module.exists():
        return []
    src = module.read_text(encoding="utf-8", errors="replace")
    try:
        label = module.relative_to(REPO).as_posix()
    except ValueError:
        label = module.name  # selftest fixtures live outside the repo
    out: list[str] = []
    for m in re.finditer(r"\bfetch\s*\(", src):
        line = src.count("\n", 0, m.start()) + 1
        # Match the call's OWN parentheses rather than scanning a fixed window.
        # A fixed window is what made the first version of this check report a
        # false positive on gatewayGet: the `signal:` line sits past a long
        # explanatory comment and fell outside the window. Balanced matching has
        # no such blind spot.
        i = m.end() - 1  # at the '('
        depth = 0
        args = ""
        for j in range(i, len(src)):
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
                if depth == 0:
                    args = src[i : j + 1]
                    break
        if TIMEOUT_TOKEN not in args:
            out.append(
                f"{label}:{line} — fetch() with no {TIMEOUT_TOKEN}(). Every "
                f"gateway seam crosses the wide-area link; without a ceiling one "
                f"stall holds the whole page open. See "
                f"runbooks/RCA-dashboard-fanout-tail-latency.md."
            )
    return out


def selftest() -> int:
    """Plant violations and assert the guard reports them."""
    ok = True
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "app"
        (root / "bad").mkdir(parents=True)
        (root / "good").mkdir(parents=True)

        # 6 concurrent calls — one over the budget.
        calls = ",\n".join(f"gatewayGet<T{i}>('/v1/x{i}')" for i in range(6))
        (root / "bad" / "page.tsx").write_text(
            f"const [a,b,c,d,e,f] = await Promise.all([\n{calls}\n]);\n"
        )
        # 5 concurrent — exactly at budget, must pass.
        calls5 = ",\n".join(f"gatewayGet<T{i}>('/v1/x{i}')" for i in range(5))
        (root / "good" / "page.tsx").write_text(
            f"const r = await Promise.all([\n{calls5}\n]);\n"
        )
        # 9 SEQUENTIAL calls, no Promise.all — must NOT fire. Sequential awaits
        # are a different (and separately bad) shape; this guard is about the
        # concurrent tail-sampling defect and must not cry wolf on them.
        seq = "\n".join(
            f"const v{i} = await gatewayGet<T>('/v1/y{i}');" for i in range(9)
        )
        (root / "good" / "seq.tsx").write_text(seq + "\n")

        fails = run([root], Path(td), quiet=True)
        joined = " ".join(fails)

        if not any("bad/page.tsx" in f for f in fails):
            print("SELFTEST FAIL: did not catch the 6-call over-budget fan-out")
            ok = False
        if "good/page.tsx" in joined:
            print("SELFTEST FAIL: flagged a surface sitting exactly at budget")
            ok = False
        if "seq.tsx" in joined:
            print("SELFTEST FAIL: flagged sequential awaits (not concurrent fan-out)")
            ok = False

        # The ratchet: an allowlisted file that grows must still fail.
        rel = next(iter(ALLOWLIST))
        allowed = ALLOWLIST[rel][0]
        grow = Path(td) / "app" / "grow"
        grow.mkdir(parents=True)
        big = ",\n".join(f"gatewayGet<T{i}>('/v1/z{i}')" for i in range(allowed + 1))
        (grow / "page.tsx").write_text(f"await Promise.all([\n{big}\n]);\n")
        saved = dict(ALLOWLIST)
        ALLOWLIST.clear()
        ALLOWLIST["app/grow/page.tsx"] = (allowed, "selftest")
        grew = run([Path(td) / "app"], Path(td), quiet=True)
        ALLOWLIST.clear()
        ALLOWLIST.update(saved)
        if not any("grow/page.tsx" in f for f in grew):
            print("SELFTEST FAIL: allowlist did not ratchet — growth went uncaught")
            ok = False

        # Timeout check: a seam without a ceiling must be caught, one with it
        # must not. Both directions, so the check cannot pass vacuously.
        bare = Path(td) / "bare.ts"
        bare.write_text(
            "const r = await fetch(`${base}${path}`, {\n"
            '\t\t\theaders: { authorization: "x" },\n'
            '\t\t\tcache: "no-store",\n'
            "\t\t});\n"
        )
        if not check_timeouts(bare):
            print("SELFTEST FAIL: did not catch a fetch() with no abort timeout")
            ok = False
        guarded = Path(td) / "guarded.ts"
        guarded.write_text(
            "const r = await fetch(`${base}${path}`, {\n"
            '\t\t\tcache: "no-store",\n'
            "\t\t\tsignal: AbortSignal.timeout(10_000),\n"
            "\t\t});\n"
        )
        if check_timeouts(guarded):
            print("SELFTEST FAIL: flagged a fetch that DOES carry a timeout")
            ok = False

    print("selftest: PASS" if ok else "selftest: FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    failures = run(SCAN_ROOTS, REPO)
    failures += check_timeouts(GATEWAY_MODULE)
    if failures:
        print("\nFAIL: gateway call discipline\n")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        "OK — no surface exceeds its concurrent gateway fan-out budget, and "
        "every gateway fetch seam carries an abort timeout."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
