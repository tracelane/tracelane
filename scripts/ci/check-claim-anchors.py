#!/usr/bin/env python3
"""Claim -> code-anchor gate.

THE TERMINATING PASS. Every customer-facing claim in the export set is either
anchored to code that PROVES it, or it is struck / marked roadmap. Exhaustive by
construction: a claim is anchored or it is not, so no new *class* can hide behind it.

WHY THIS STORES PROBES, NOT `file:line`
---------------------------------------
The obvious design — record `claim -> file:line` — rots on contact. Five of six
`file:line` citations in docs/guides/architecture.md were already wrong when checked
on 2026-08-07, and one pointed at a `#[deprecated]` second-preimage-vulnerable
function. A ledger of hundreds of line numbers decays faster than anyone re-reads it,
and a decayed anchor is WORSE than none: it looks like proof.

So an anchor here is a RE-EVALUABLE PREDICATE, not a coordinate. The gate re-runs it
every time. An anchor that stops holding fails the build instead of quietly rotting.

REACHABILITY IS A SEPARATE AXIS
-------------------------------
Anchoring proves code EXISTS. It does not prove the code RUNS. Both of these have a
perfectly good anchor and are still false as customer claims:
  * the PR6 PromptGuard sidecar: `PROMPT_GUARD_URL` appears in NO compose file
  * the R2 cold tier: `crates/ingest/src/main.rs:350` does `drop(r2_tx)` — the writer
    channel is dropped, so nothing is ever written
That is why every row carries `reachability`. `dormant` and `unreachable` may not be
stated in the present tense to a customer, however good the anchor.

CLAIMS THAT CANNOT HAVE A CODE ANCHOR
-------------------------------------
Prices live in Polar, not our repo. Regulatory status, a competitor's behaviour, a
subprocessor's certification, an uptime target and a roadmap item have no code that
could prove them. "No anchor -> strike" would delete true, necessary sentences. Those
rows take kind `external` and MUST name a non-code evidence source, or `roadmap`,
which forbids present-tense phrasing.

Usage:
    check-claim-anchors.py             # verify every anchor still holds
    check-claim-anchors.py --coverage  # how much of the export set is anchored
    check-claim-anchors.py --selftest  # prove a broken anchor blocks
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs" / "inventory" / "CLAIM_ANCHORS.json"

VERDICTS = {
    "TRUE-ANCHORED",
    "STRUCK-NO-ANCHOR",
    "BUILD-STATE-UNBUILT",
    "EXTERNAL",
    "ROADMAP",
}
REACHABILITY = {"live", "dormant", "unreachable", "n/a"}


def sh(cmd: list[str]) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, check=False)
    return r.returncode, r.stdout


def eval_probe(anchor: dict) -> tuple[bool, str]:
    """Re-evaluate an anchor. Returns (holds, observed)."""
    kind = anchor.get("kind")

    if kind in ("external", "roadmap", "none"):
        return True, kind

    if kind == "symbol":
        # the named symbol must exist in the named file
        f = ROOT / anchor["file"]
        if not f.is_file():
            return False, f"file missing: {anchor['file']}"
        txt = f.read_text(encoding="utf-8", errors="replace")
        found = anchor["symbol"] in txt
        return found, "found" if found else f"symbol absent: {anchor['symbol']}"

    if kind == "count":
        # count matches of a pattern across a glob, compare to an assertion
        pat = re.compile(anchor["pattern"])
        n = 0
        for p in ROOT.glob(anchor["glob"]):
            if p.is_file():
                n += len(pat.findall(p.read_text(encoding="utf-8", errors="replace")))
        return _assert_num(n, anchor["assert"]), str(n)

    if kind == "files":
        n = len([p for p in ROOT.glob(anchor["glob"]) if p.is_file()])
        return _assert_num(n, anchor["assert"]), str(n)

    if kind == "absent":
        # the claim depends on something NOT existing (e.g. "no Helm chart ships")
        hits = [str(p) for p in ROOT.glob(anchor["glob"]) if p.is_file()]
        return not hits, "absent" if not hits else f"unexpectedly present: {hits[:3]}"

    return False, f"unknown anchor kind: {kind}"


def _assert_num(n: int, expr: str) -> bool:
    m = re.fullmatch(r"(>=|<=|==|>|<)\s*(\d+)", expr.strip())
    if not m:
        return False
    op, want = m.group(1), int(m.group(2))
    return {
        ">=": n >= want,
        "<=": n <= want,
        "==": n == want,
        ">": n > want,
        "<": n < want,
    }[op]


def load() -> list[dict]:
    if not LEDGER.is_file():
        return []
    return json.loads(LEDGER.read_text(encoding="utf-8")).get("claims", [])


def verify(rows: list[dict]) -> int:
    bad = 0
    by_verdict: dict[str, int] = {}
    for r in rows:
        v = r.get("verdict", "?")
        by_verdict[v] = by_verdict.get(v, 0) + 1

        if v not in VERDICTS:
            print(f"BAD VERDICT {v!r} — {r.get('claim')!r}")
            bad += 1
            continue
        if r.get("reachability") not in REACHABILITY:
            print(f"BAD REACHABILITY {r.get('reachability')!r} — {r.get('claim')!r}")
            bad += 1
            continue

        # A claim stated in the present tense must be BOTH anchored and live.
        if v == "TRUE-ANCHORED" and r["reachability"] not in ("live", "n/a"):
            print(
                f"NOT LIVE — {r['claim']!r} ({r['doc']})\n"
                f"    anchored but reachability={r['reachability']}: code exists, "
                f"does not run. Must not be stated in the present tense."
            )
            bad += 1
            continue

        if v == "EXTERNAL" and not r.get("anchor", {}).get("evidence"):
            print(
                f"EXTERNAL with no named evidence source — {r['claim']!r} ({r['doc']})"
            )
            bad += 1
            continue

        holds, observed = eval_probe(r.get("anchor", {}))
        if not holds:
            print(
                f"ANCHOR BROKEN — {r['claim']!r}\n    {r['doc']}\n    observed: {observed}"
            )
            bad += 1

    print(
        "\nledger:",
        ", ".join(f"{k}={v}" for k, v in sorted(by_verdict.items())) or "(empty)",
    )
    if bad:
        print(f"FAIL — {bad} claim(s) whose anchor no longer holds.")
        return 1
    print("OK — every recorded claim's anchor still holds.")
    print("NOTE: this proves the RECORDED claims are anchored. Coverage of the export")
    print("      set is a separate number — run --coverage.")
    return 0


def coverage(rows: list[dict]) -> int:
    docs = {r["doc"].split(":")[0] for r in rows}
    spec = __import__("importlib.util", fromlist=["util"]).spec_from_file_location(
        "clsgate", ROOT / "scripts" / "ci" / "check-doc-classification.py"
    )
    mod = __import__("importlib.util", fromlist=["util"]).module_from_spec(spec)
    spec.loader.exec_module(mod)
    allow, deny = mod.parse_allow(), mod.parse_deny()
    _, out = sh(["git", "ls-files", "-z"])
    exported = [
        p
        for p in out.split("\0")
        if p and p.endswith((".md", ".mdx", ".mdc")) and mod.is_exported(p, allow, deny)
    ]
    print(f"claims recorded:        {len(rows)}")
    print(f"docs with >=1 claim:    {len(docs)} of {len(exported)} exported")
    missing = sorted(set(exported) - docs)
    print(f"docs with NO claim row: {len(missing)}")
    for m in missing[:15]:
        print(f"    {m}")
    if len(missing) > 15:
        print(f"    ... +{len(missing) - 15} more")
    print("\nThe pass TERMINATES when this number is 0 and verify() is green.")
    return 0


def selftest() -> int:
    print("selftest: an anchor that no longer holds must FAIL ...")
    rows = [
        {
            "claim": "a symbol that does not exist",
            "doc": "fake.md:1",
            "verdict": "TRUE-ANCHORED",
            "reachability": "live",
            "anchor": {
                "kind": "symbol",
                "file": "crates/gateway/src/server.rs",
                "symbol": "this_symbol_does_not_exist_xyzzy",
            },
        }
    ]
    if verify(rows) == 0:
        print("  FAIL: a broken anchor did not block")
        return 1
    print("  OK: broken anchor blocked\n")

    print("selftest: anchored-but-DORMANT must FAIL if stated present-tense ...")
    rows = [
        {
            "claim": "R2 cold tier is live",
            "doc": "fake.md:2",
            "verdict": "TRUE-ANCHORED",
            "reachability": "dormant",
            "anchor": {
                "kind": "symbol",
                "file": "crates/ingest/src/main.rs",
                "symbol": "r2_tx",
            },
        }
    ]
    if verify(rows) == 0:
        print("  FAIL: a dormant claim passed as TRUE-ANCHORED")
        return 1
    print("  OK: dormant-but-anchored blocked\n")

    print("selftest: a holding anchor must PASS ...")
    rows = [
        {
            "claim": "the gateway mounts chat completions",
            "doc": "fake.md:3",
            "verdict": "TRUE-ANCHORED",
            "reachability": "live",
            "anchor": {
                "kind": "symbol",
                "file": "crates/gateway/src/server.rs",
                "symbol": "/v1/chat/completions",
            },
        }
    ]
    if verify(rows) != 0:
        print("  FAIL: a good anchor was rejected")
        return 1
    print("  OK: good anchor passed")
    print("\nselftest PASSED.")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    rows = load()
    if "--coverage" in sys.argv:
        return coverage(rows)
    if not rows:
        print(f"no ledger at {LEDGER.relative_to(ROOT)} — nothing anchored yet")
        return 1
    return verify(rows)


if __name__ == "__main__":
    raise SystemExit(main())
