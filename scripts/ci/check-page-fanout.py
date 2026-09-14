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

SUSPENSE FORM (B-343, 2026-09-05): `Promise.all([...])` is not
the only way to fire N concurrent gateway calls from one render. `apps/web/app/
dashboards/[id]/page.tsx` renders each dashboard tile as its own `<Suspense>`
boundary wrapping an `async` server component that calls a gateway fetcher —
React streams those concurrently, so a 12-tile dashboard is 12 concurrent
gateway calls the `Promise.all` scan reports as ZERO. That is the
`guard-filetype-blindspot` class: green because unmeasured, not because safe.

THE RULE for the Suspense form (documented here because there is no fixed
literal to grep, unlike `Promise.all([...])`):
  1. Find a `<Suspense>` boundary whose direct child is a component defined in
     the same file as `async function Name(...)`.
  2. That component counts as a concurrent gateway call IF its body calls a
     known fetcher — the same `GATEWAY_CALLS` list used for the `Promise.all`
     scan, plus `fetchTileData` (`@/lib/metrics/tiles`), plus anything
     imported from `@/lib/metrics/fetch` or `@/lib/gateway`.
  3. A Suspense-wrapped fetching component rendered inside a `.map(...)` call
     fires once PER ITEM — the count is the length of a runtime array, which
     this static guard cannot know. So the default is **N = unbounded**,
     which always exceeds the budget and fails the file.
  4. The ONE way to earn a finite count instead of unbounded: a concurrency
     limiter — `makeLimiter(N)` (`apps/web/lib/metrics/tile-support.ts`) —
     assigned to a variable that is VISIBLY referenced inside the `.map(...)`
     body (passed as a prop, called directly). The reported count is then the
     limiter's own cap, exactly like the pinned `Promise.all` allowlist below
     — a real ceiling enforced in code, not an unmeasured guess. No limiter
     variable in scope of the map body means no credit — the guard does not
     chase a limiter through prop-drilling or a second module.
  `dashboards/[id]/page.tsx` passes rule 4: `makeLimiter(8)` at page.tsx:74 is
  assigned to `run` and `run` is threaded into every mapped `<TileContainer>`,
  so the file is allowlisted below at the true, code-enforced number: 8 — not
  the 0 the old scan reported, and not an unbounded guess either.

Exit 1 on violation. `--selftest` plants violations (including an unbounded
mapped Suspense fan-out with no limiter) and asserts they are caught.
"""

from __future__ import annotations

import argparse
import math
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
    # `apps/web/lib/metrics/fetch.ts` (DSH-11) — every windowed read, by name.
    "fetchSloRows",
    "fetchSloSummary",
    "fetchSloModels",
    "fetchSloTimeseries",
    "fetchGatewayStatsFor",
    "fetchCostBreakdownFor",
    "fetchLatencyBreakdownFor",
    "fetchToolAnalyticsFor",
    "fetchGuardrailStatsFor",
    "fetchGuardrailVerdictsFor",
    "fetchSignaturesFor",
    "fetchTraceCountFor",
    "fetchSessionsFor",
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
    "apps/web/app/dashboards/[id]/page.tsx": (
        8,
        (
            "B-343: per-tile Suspense fan-out (up to 12 tiles), bounded by "
            "makeLimiter(8) at page.tsx:74 — `run` is threaded into every "
            "mapped <TileContainer>, so at most 8 tile fetches are ever "
            "in flight regardless of tile count. The pinned number IS the "
            "limiter's own cap, not a guess. Raise this only if the limiter's "
            "own argument changes; the guard's Suspense-form detector reads "
            "that argument, so the two cannot drift silently."
        ),
    ),
}

# The fetcher import surfaces the Suspense-form detector looks for, beyond the
# named GATEWAY_CALLS list (B-343 rule 2).
SUSPENSE_FETCHER_MODULES = ("@/lib/metrics/fetch", "@/lib/gateway")
SUSPENSE_EXTRA_FETCHERS = ("fetchTileData",)

LIMITER_CALL_RE = re.compile(r"\bmakeLimiter\s*\(\s*(\d+)\s*\)")


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


def _balanced(src: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    """Return the index of the char CLOSING the bracket opened at open_idx."""
    depth = 0
    for j in range(open_idx, len(src)):
        if src[j] == open_ch:
            depth += 1
        elif src[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j
    return len(src) - 1


def _function_bodies(src: str) -> dict[str, str]:
    """Map `async function Name(` definitions to their `{ ... }` body text.

    The params are balanced first (`params_end`), THEN the body's opening `{`
    is sought — a destructured/typed TS param like `{ id }: { id: string }`
    contains braces of its own, and finding the first bare `{` after the name
    (without skipping past the parameter list) grabs a param brace instead of
    the function body, desyncing every brace match after it.
    """
    out: dict[str, str] = {}
    for m in re.finditer(r"\basync function\s+([A-Za-z0-9_]+)\s*\(", src):
        params_open = m.end() - 1  # at the '('
        params_end = _balanced(src, params_open, "(", ")")
        brace = src.find("{", params_end + 1)
        if brace == -1:
            continue
        end = _balanced(src, brace, "{", "}")
        out[m.group(1)] = src[brace : end + 1]
    return out


def _fetcher_names(src: str) -> set[str]:
    """Fetcher identifiers this file could call: GATEWAY_CALLS + fetchTileData +
    anything imported from the two Suspense-form fetcher modules (rule 2)."""
    names = set(GATEWAY_CALLS) | set(SUSPENSE_EXTRA_FETCHERS)
    for mod in SUSPENSE_FETCHER_MODULES:
        for m in re.finditer(
            r'import\s*\{([^}]*)\}\s*from\s*["\']' + re.escape(mod) + r'["\']', src
        ):
            for raw in m.group(1).split(","):
                name = raw.split(" as ")[-1].strip()
                if name:
                    names.add(name)
    return names


def find_suspense_map_fanout(src: str) -> list[tuple[int, str, float]]:
    """Suspense-form fan-out (B-343): a `<Suspense>` wrapping an async fetching
    component, rendered inside a `.map(...)` callback. See the module docstring
    for the numbered rule this implements. Returns (line, component, count)
    where count is an int (a visibly-applied `makeLimiter(N)` cap) or
    `math.inf` (mapped, fetching, and NO limiter in scope — unbounded)."""
    fetchers = _fetcher_names(src)
    bodies = _function_bodies(src)

    def calls_fetcher(body: str) -> bool:
        # `\s*[<(]` mirrors CALL_RE: a TS generic call reads `gatewayGet<T>(...)`,
        # so the name is followed by `<`, not directly by `(`.
        return any(
            re.search(r"\b" + re.escape(fn) + r"\s*[<(]", body) for fn in fetchers
        )

    # Pre-index every `const X = makeLimiter(N)` so a map body's limiter usage
    # can be resolved back to its numeric cap (rule 4).
    limiter_caps: list[tuple[int, str, int]] = []  # (pos, var_name, cap)
    for lm in LIMITER_CALL_RE.finditer(src):
        assign = re.search(
            r"(?:const|let)\s+([A-Za-z0-9_]+)\s*=\s*" + re.escape(lm.group(0)), src
        )
        if assign:
            limiter_caps.append((lm.start(), assign.group(1), int(lm.group(1))))

    out: list[tuple[int, str, float]] = []
    for mm in re.finditer(r"\.map\s*\(", src):
        open_idx = mm.end() - 1
        close_idx = _balanced(src, open_idx, "(", ")")
        map_body = src[open_idx : close_idx + 1]
        if "<Suspense" not in map_body:
            continue

        fetching_comp = None
        for comp in re.findall(r"<([A-Z][A-Za-z0-9_]*)\b", map_body):
            body = bodies.get(comp)
            if body and calls_fetcher(body):
                fetching_comp = comp
                break
        if fetching_comp is None:
            continue  # a Suspense in a .map that renders no fetching component

        # Rule 4: a limiter defined before this .map AND referenced inside its
        # body earns the pinned cap instead of "unbounded".
        cap: float = math.inf
        for pos, var, n in limiter_caps:
            if pos < mm.start() and re.search(r"\b" + re.escape(var) + r"\b", map_body):
                cap = n
                break

        line = src.count("\n", 0, mm.start()) + 1
        out.append((line, fetching_comp, cap))
    return out


def scan_file(path: Path) -> tuple[float, int]:
    """Return (max concurrent gateway calls, line of the worst block).

    "Max" ranges over BOTH fan-out forms this file can contain: literal
    `Promise.all([...])` blocks and per-tile `<Suspense>` fan-out (B-343). The
    count is `float` because the Suspense form can report `math.inf`
    (unbounded, mapped, no limiter) — always the worst possible reading.
    """
    src = path.read_text(encoding="utf-8", errors="replace")
    worst: float = 0
    worst_line = 0
    for line, body in find_concurrent_blocks(src):
        n = len(CALL_RE.findall(body))
        if n > worst:
            worst, worst_line = n, line
    for line, _name, n in find_suspense_map_fanout(src):
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


def _fmt_n(n: float) -> str:
    return "unbounded" if n == math.inf else str(int(n))


def run(roots: list[Path], repo: Path, quiet: bool = False) -> list[str]:
    failures: list[str] = []
    findings: list[tuple[str, float, int]] = []
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
                    f"{rel}:{line} — {_fmt_n(n)} concurrent gateway calls, "
                    f"allowlisted at EXACTLY {allowed}. The allowlist is a "
                    f"ratchet: it records a known offender, it does not license "
                    f"growth. Collapse these into one aggregate endpoint."
                )
            continue

        if n == math.inf:
            failures.append(
                f"{rel}:{line} — UNBOUNDED concurrent gateway fan-out: a "
                f"<Suspense> boundary renders an async component that calls a "
                f"gateway fetcher inside a `.map(...)`, with no `makeLimiter(N)` "
                f"visibly bounding it. The count scales with a runtime array's "
                f"length, so every item added widens the tail-latency sample by "
                f"one. Bound it with a limiter (see "
                f"apps/web/lib/metrics/tile-support.ts `makeLimiter`) or collapse "
                f"it into one aggregate endpoint."
            )
        elif n > DEFAULT_BUDGET:
            failures.append(
                f"{rel}:{line} — {_fmt_n(n)} concurrent gateway calls exceeds "
                f"the budget of {DEFAULT_BUDGET}. Promise.all resolves at the "
                f"SLOWEST member, so this samples the wide-area tail {_fmt_n(n)} "
                f"times per render. Serve it from ONE aggregate endpoint instead "
                f"of adding a parallel call. See "
                f"runbooks/RCA-dashboard-fanout-tail-latency.md."
            )

    if not quiet and findings:
        print("  concurrent gateway fan-out by surface:")
        for rel, n, line in sorted(findings, key=lambda x: -x[1]):
            pin = ALLOWLIST.get(rel)
            tag = f"  (allowlisted at {pin[0]})" if pin else ""
            flag = "  <-- OVER BUDGET" if (not pin and n > DEFAULT_BUDGET) else ""
            print(f"    {_fmt_n(n):>9}  {rel}:{line}{tag}{flag}")
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

        # B-343: Suspense-form fan-out. A component fetching under <Suspense>
        # inside a `.map(...)` with NO limiter must be UNBOUNDED and REFUSED —
        # the defect the guard was blind to (12 tiles reported as 0 calls).
        (root / "susp_bad").mkdir(parents=True)
        (root / "susp_bad" / "page.tsx").write_text(
            "async function Tile({ id }: { id: string }) {\n"
            "  const data = await gatewayGet<T>(`/v1/x${id}`);\n"
            "  return <div>{data}</div>;\n"
            "}\n\n"
            "export default function Page({ tiles }: { tiles: Item[] }) {\n"
            "  return (\n"
            "    <div>\n"
            "      {tiles.map((t) => (\n"
            "        <Suspense key={t.id} fallback={<Skeleton />}>\n"
            "          <Tile id={t.id} />\n"
            "        </Suspense>\n"
            "      ))}\n"
            "    </div>\n"
            "  );\n"
            "}\n"
        )
        # The same shape, but a `makeLimiter(N)` is defined and visibly threaded
        # into the mapped component — must earn the pinned cap, not "unbounded",
        # and (at 4, under the default budget of 5) must PASS.
        (root / "susp_good").mkdir(parents=True)
        (root / "susp_good" / "page.tsx").write_text(
            "const run = makeLimiter(4);\n\n"
            "async function Tile({ id, run }: { id: string; run: Limiter }) {\n"
            "  return run(() => gatewayGet<T>(`/v1/x${id}`));\n"
            "}\n\n"
            "export default function Page({ tiles }: { tiles: Item[] }) {\n"
            "  return (\n"
            "    <div>\n"
            "      {tiles.map((t) => (\n"
            "        <Suspense key={t.id} fallback={<Skeleton />}>\n"
            "          <Tile id={t.id} run={run} />\n"
            "        </Suspense>\n"
            "      ))}\n"
            "    </div>\n"
            "  );\n"
            "}\n"
        )

        susp_fails = run([root / "susp_bad", root / "susp_good"], Path(td), quiet=True)
        susp_joined = " ".join(susp_fails)
        if not any("susp_bad/page.tsx" in f and "UNBOUNDED" in f for f in susp_fails):
            print(
                "SELFTEST FAIL: did not catch the unbounded mapped Suspense "
                "fan-out (no limiter)"
            )
            ok = False
        if "susp_good/page.tsx" in susp_joined:
            print(
                "SELFTEST FAIL: flagged a mapped Suspense fan-out that a "
                "visibly-applied makeLimiter(4) bounds under budget"
            )
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
