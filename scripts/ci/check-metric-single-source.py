#!/usr/bin/env python3
"""Every windowed metric comes from ONE place — `apps/web/lib/metrics/` (DSH-11 §3c).

WHY THIS EXISTS. The 2026-09-02 inventory (`specs/metrics-renovation-inventory.md`)
found the dashboard, /slo and /gateway each computing their own window and bucket
(`Math.max(1, Math.round(bucketMs / 3_600_000))` inlined at three sites), eight
drill-throughs that dropped the window, and two numbers labelled the same on one
screen that came from two different tables. A rule saying "use the shared layer"
is what allowed that; this is the gate.

THREE RULES, each with a planted violation in `--selftest`:

  1. NO WINDOWED GATEWAY URL OUTSIDE `apps/web/lib/metrics/`. A page or component
     that builds `/v1/slo…`, `/v1/gateway/stats`, `/v1/costs`, `/v1/guardrails/*`,
     `/v1/query/latency-breakdown|tool-analytics|signatures`, `/v1/sessions` or
     `/v1/traces/count` — or carries `hours=`/`bucket=` for one — is computing a
     window on its own.
  2. NO WINDOW ARITHMETIC IN PAGES OR COMPONENTS. `rangeToHours(`, `rangeBucketMs(`,
     `rangeSince(`, a literal `3_600_000`/`86_400_000` multiplied into a `Date.now()`,
     or `bucketMs / 3_600_000` — the three sites above, by shape.
  3. THE REGISTRY IS ONE LABEL, ONE DEFINITION. `lib/metrics/registry.ts` may not
     carry two ids with one label, nor one id twice.

RATCHET, NOT EXEMPTION. The pages that still compute their own window are
allowlisted BY EXACT COUNT in `LEGACY` while they migrate; a file that gains a
violation fails, and the list is deleted when it reaches zero. This is the same
shape `check-page-fanout.py` uses and for the same reason: a bare exemption is a
hole, a pinned count is a countdown.

HONEST LIMIT. This matches CONSTRUCTIONS (a URL literal, a helper name, a numeric
shape). A page that hides the arithmetic behind a helper with a new name is
invisible to rules 1–2; rule 3 and `lib/metrics/consistency.test.ts` are the
other half, and review is the rest.

USAGE
  check-metric-single-source.py             # scan
  check-metric-single-source.py --selftest  # prove each rule BLOCKS and clean passes
  check-metric-single-source.py --list      # print every hit, allowlisted or not
EXIT 0 clean · 1 violation · 2 usage / selftest failed
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = Path("apps/web")
METRICS_DIR = WEB / "lib" / "metrics"
SCAN_DIRS = [WEB / "app", WEB / "components", WEB / "lib"]
SKIP_PARTS = {"node_modules", ".next", ".open-next", "__tests__", "__mocks__"}

WINDOWED_ROUTES = (
    r"/v1/slo(?:/summary|/models|/timeseries)?"
    r"|/v1/gateway/stats|/v1/costs"
    r"|/v1/guardrails/(?:stats|verdicts)"
    r"|/v1/query/(?:latency-breakdown|tool-analytics|signatures)"
    r"|/v1/sessions|/v1/traces/count"
)
RE_URL = re.compile(r"[\"'`](?:" + WINDOWED_ROUTES + r")(?:[?\"'`]|\s*\$\{)")
RE_ARITH = re.compile(
    r"\brangeToHours\s*\(|\brangeBucketMs\s*\(|\brangeSince\s*\("
    r"|bucketMs\s*/\s*3_600_000"
    r"|Date\.now\(\)\s*-\s*[A-Za-z_(][^;\n]*\*\s*(?:3_600_000|86_400_000)"
    r"|(?:3_600_000|86_400_000)\s*\)?\s*\.toISOString"
)
# Any position on the line, not only line-start: the shape is `label: "…"` whether
# the entry is one field per line (the real registry) or inline (the selftest stub).
# The lookbehind keeps `signature_id:` from reading as an `id:`.
RE_LABEL = re.compile(r"(?<![A-Za-z_])label:\s*\"([^\"]+)\"")
RE_ID = re.compile(r"(?<![A-Za-z_])id:\s*\"([^\"]+)\"")

# file -> (exact hit count, why). Shrink when a page migrates; delete at zero.
# Pinned 2026-09-02 from the scan the day the guard landed — the pre-DSH-11 state.
_MIGRATING = "pre-DSH-11 window computation; migrates to lib/metrics in the page batch"
LEGACY: dict[str, tuple[int, str]] = {
    "apps/web/app/audit/page.tsx": (
        1,
        'the ledger view deliberately has NO range control (forces "all"; audit/page.tsx:285) and keeps its own since/until export mapping — not a metric surface of the shared layer',
    ),
}


def iter_files(root: Path):
    for d in SCAN_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if f.suffix not in {".ts", ".tsx"}:
                continue
            if any(p in SKIP_PARTS for p in f.parts):
                continue
            if ".test." in f.name or ".spec." in f.name:
                continue
            rel = f.relative_to(root)
            if str(rel).startswith(str(METRICS_DIR)):
                continue
            yield rel, f


def scan(root: Path) -> dict[str, list[tuple[int, str, str]]]:
    """rel path -> [(line, rule, excerpt)]."""
    hits: dict[str, list[tuple[int, str, str]]] = {}
    for rel, f in iter_files(root):
        text = f.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith(("//", "*")):
                continue
            if RE_URL.search(line):
                hits.setdefault(str(rel), []).append((i, "windowed-url", s[:100]))
            elif (
                RE_ARITH.search(line)
                and str(rel).startswith("apps/web/app")
                or (
                    RE_ARITH.search(line) and str(rel).startswith("apps/web/components")
                )
            ):
                hits.setdefault(str(rel), []).append((i, "window-arith", s[:100]))
    return hits


def registry_problems(root: Path) -> list[str]:
    reg = root / METRICS_DIR / "registry.ts"
    if not reg.is_file():
        return [f"{METRICS_DIR}/registry.ts is missing"]
    text = reg.read_text(encoding="utf-8")
    out: list[str] = []
    seen_labels: dict[str, int] = {}
    for m in RE_LABEL.finditer(text):
        seen_labels[m.group(1)] = seen_labels.get(m.group(1), 0) + 1
    for label, n in seen_labels.items():
        if n > 1:
            out.append(
                f'registry: label "{label}" is defined {n} times — one label, one definition'
            )
    seen_ids: dict[str, int] = {}
    for m in RE_ID.finditer(text):
        seen_ids[m.group(1)] = seen_ids.get(m.group(1), 0) + 1
    for mid, n in seen_ids.items():
        if n > 1:
            out.append(f'registry: id "{mid}" is defined {n} times')
    return out


def run(
    root: Path,
    legacy: dict[str, tuple[int, str]],
    list_all: bool = False,
    quiet: bool = False,
) -> int:
    hits = scan(root)
    problems = registry_problems(root)
    for rel, rows in sorted(hits.items()):
        allowed = legacy.get(rel)
        if list_all:
            for ln, rule, ex in rows:
                print(f"  {rel}:{ln} [{rule}] {ex}")
        if allowed is None:
            for ln, rule, ex in rows:
                problems.append(f"{rel}:{ln} [{rule}] {ex}")
        elif len(rows) != allowed[0]:
            problems.append(
                f"{rel}: {len(rows)} window computation(s), allowlist pins exactly {allowed[0]} — "
                f"{'a new one was added' if len(rows) > allowed[0] else 'shrink the pin to ' + str(len(rows))}"
            )
    for rel, (n, _why) in legacy.items():
        if rel not in hits and n > 0:
            problems.append(
                f"{rel}: allowlisted for {n} but has none left — delete its LEGACY entry"
            )
    if not quiet:
        print("== metric single-source guard (DSH-11 §3c) ==")
        print(
            f"scanned {sum(1 for _ in iter_files(root))} files; {len(hits)} carry a window computation, {len(legacy)} allowlisted by exact count"
        )
    if problems:
        if not quiet:
            for p in problems:
                print(f"  ✗ {p}")
            print(
                "FAIL — a window, a bucket or a windowed gateway URL is computed outside apps/web/lib/metrics/,"
            )
            print(
                "       or the registry defines one label twice. Route it through lib/metrics (see specs/metrics-renovation.md §3c)."
            )
        return 1
    if not quiet:
        print(
            "OK — every windowed read goes through lib/metrics; the registry is one label, one definition."
        )
    return 0


REGISTRY_STUB = """export const METRICS = {
\ta: { id: "a", label: "LLM calls", kind: "count" },
\tb: { id: "b", label: "Error rate", kind: "percent" },
} as const;
"""


def _tree(td: Path, page: str, registry: str = REGISTRY_STUB) -> Path:
    if td.exists():
        shutil.rmtree(td)
    (td / METRICS_DIR).mkdir(parents=True)
    (td / METRICS_DIR / "registry.ts").write_text(registry, encoding="utf-8")
    (td / WEB / "app" / "x").mkdir(parents=True)
    (td / WEB / "app" / "x" / "page.tsx").write_text(page, encoding="utf-8")
    return td


def selftest() -> int:
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        td = Path(tmp) / "t"
        clean = 'import { fetchSloSummary } from "@/lib/metrics/fetch";\nexport default async function P() { return <div>{await fetchSloSummary(r)}</div>; }\n'
        _tree(td, clean)
        rc = run(td, {}, quiet=True)
        print(
            f"selftest: clean page passes ........................... {'OK' if rc == 0 else 'FAIL'}"
        )
        ok &= rc == 0

        _tree(
            td,
            "const rows = await gatewayGet<SloRow[]>(`/v1/slo?hours=${hours}&bucket=${b}`);\n",
        )
        rc = run(td, {}, quiet=True)
        print(
            f"selftest: page-local windowed URL blocks (rule 1) ..... {'OK' if rc == 1 else 'FAIL'}"
        )
        ok &= rc == 1

        _tree(
            td,
            "const hours = rangeToHours(range);\nconst b = Math.max(1, Math.round(bucketMs / 3_600_000));\n",
        )
        rc = run(td, {}, quiet=True)
        print(
            f"selftest: page-local window arithmetic blocks (rule 2)  {'OK' if rc == 1 else 'FAIL'}"
        )
        ok &= rc == 1

        _tree(
            td,
            clean,
            REGISTRY_STUB.replace('label: "Error rate"', 'label: "LLM calls"'),
        )
        rc = run(td, {}, quiet=True)
        print(
            f"selftest: duplicate registry label blocks (rule 3) .... {'OK' if rc == 1 else 'FAIL'}"
        )
        ok &= rc == 1

        _tree(td, "const hours = rangeToHours(range);\nconst s = rangeSince(range);\n")
        rc = run(td, {"apps/web/app/x/page.tsx": (2, "test")}, quiet=True)
        print(
            f"selftest: an exact-count allowlist passes ............. {'OK' if rc == 0 else 'FAIL'}"
        )
        ok &= rc == 0
        rc = run(td, {"apps/web/app/x/page.tsx": (1, "test")}, quiet=True)
        print(
            f"selftest: growing past the pin blocks (the ratchet) ... {'OK' if rc == 1 else 'FAIL'}"
        )
        ok &= rc == 1
    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 2


def main() -> int:
    allowed = {"--selftest", "--list"}
    unknown = [a for a in sys.argv[1:] if a not in allowed]
    if unknown:
        print(f"unknown option: {' '.join(unknown)}", file=sys.stderr)
        print(
            "usage: check-metric-single-source.py [--selftest | --list]",
            file=sys.stderr,
        )
        return 2
    if "--selftest" in sys.argv:
        return selftest()
    return run(ROOT, LEGACY, list_all="--list" in sys.argv)


if __name__ == "__main__":
    sys.exit(main())
