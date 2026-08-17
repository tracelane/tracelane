#!/usr/bin/env python3
"""Every committed `TRACELANE_R2_ENDPOINT` must carry the `.eu.` jurisdiction segment.

WHY (2026-08-09). Cloudflare R2 endpoints are JURISDICTION-SCOPED. Our bucket
(`tracelane-traces`) lives in the `eu` jurisdiction, so the account-default endpoint
`<account>.r2.cloudflarestorage.com` returns **AccessDenied for both list AND put** —
indistinguishable from a bad credential. The correct host is
`<account>.eu.r2.cloudflarestorage.com`.

**THIRD INSTANCE OF THE SAME TRAP.** It has now cost us three different ways:
  1. A FALSE REPORT — `GET /r2/buckets` is jurisdiction-scoped and defaults to `default`,
     so a bucket listing came back empty and was reported as "the bucket does not exist".
     The bucket existed, in `eu`.
  2. A CONFIG DEFECT — prod's `TRACELANE_R2_ENDPOINT` carried the default-jurisdiction
     host. Latent only because PLT-38's cold tier is dormant; it would have failed the
     moment anyone wired it.
  3. A CREDENTIAL DEAD END — probing the backup destination returned AccessDenied on
     LIST *and* PUT, which reads exactly like a revoked or read-only key. The key was
     fine the whole time.

The propagation path was documentation: an internal ops tracker printed the
default-jurisdiction form, and prod was configured from it. So the guard checks COMMITTED
TEXT — that is where the wrong value is learned.

HONEST LIMIT — read before trusting a pass. This checks committed files. It CANNOT see
the value actually set on the production host, which is the one that matters; that lives
in `infra/prod/.env` (untracked, correctly). Verifying prod means reading the value back
from the RUNNING container (`docker inspect`, never the env file — B-187) and probing the
bucket. This guard stops the repo *teaching* the wrong value; it does not stop someone
typing it. It also hard-codes `eu` because that is where our single bucket is — a
multi-jurisdiction future needs a different check, not a wider regex.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Our bucket's jurisdiction. One bucket, one jurisdiction — see the honest limit.
REQUIRED_SEGMENT = ".eu."

# Any assignment or inline mention of the endpoint variable with a concrete host.
RE_ENDPOINT = re.compile(
    r"TRACELANE_R2_ENDPOINT\s*=\s*\"?(https://[^\s\"'`]+r2\.cloudflarestorage\.com)"
)

# This guard's own source and docstring quote the bad form on purpose, to explain it.
SELF = "scripts/ci/check-r2-endpoint-jurisdiction.py"


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout
    return [p for p in out.split("\n") if p]


def scan_text(rel: str, text: str) -> list[str]:
    hits: list[str] = []
    for i, line in enumerate(text.split("\n"), 1):
        m = RE_ENDPOINT.search(line)
        if not m:
            continue
        url = m.group(1)
        if REQUIRED_SEGMENT not in url:
            hits.append(
                f"{rel}:{i}: {url} — missing the `{REQUIRED_SEGMENT}` jurisdiction segment"
            )
    return hits


def check() -> tuple[int, list[str]]:
    findings: list[str] = []
    scanned = 0
    for rel in tracked():
        if rel == SELF:
            continue
        p = ROOT / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "TRACELANE_R2_ENDPOINT" not in text:
            continue
        scanned += 1
        findings.extend(scan_text(rel, text))
    return scanned, findings


def selftest() -> int:
    good = "TRACELANE_R2_ENDPOINT=https://abc123.eu.r2.cloudflarestorage.com\n"
    bad = "TRACELANE_R2_ENDPOINT=https://abc123.r2.cloudflarestorage.com\n"

    assert not scan_text("x.md", good), "selftest: the eu form must PASS"
    print("✓ selftest: the `.eu.` form passes")

    hits = scan_text("x.md", bad)
    assert len(hits) == 1 and "missing" in hits[0], f"got {hits}"
    print("✓ selftest: the account-default form is CAUGHT (the real prod defect)")

    # Quoted / shell forms must still be seen.
    assert scan_text(
        "x.sh", 'export TRACELANE_R2_ENDPOINT="https://a.r2.cloudflarestorage.com"'
    )
    print("✓ selftest: quoted and exported forms are caught")

    # A placeholder host still has to carry the jurisdiction — that is the exact line
    # in the internal ops tracker that taught prod the wrong value.
    assert scan_text(
        "d.md", "TRACELANE_R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com"
    )
    print("✓ selftest: a <placeholder> host is checked too (the propagation path)")
    assert not scan_text(
        "d.md", "TRACELANE_R2_ENDPOINT=https://<account-id>.eu.r2.cloudflarestorage.com"
    )
    print("✓ selftest: the corrected placeholder passes")

    # Unrelated text must not fire — a guard that fires on correct code gets disabled.
    assert not scan_text("x.rs", "// endpoints are always *.r2.cloudflarestorage.com")
    assert not scan_text("x.md", "some prose about R2")
    print("✓ selftest: prose mentioning the host does NOT fire (no false positives)")

    assert scan_text("x.md", "") == []
    print("✓ selftest: empty input yields zero findings (no false coverage)")

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="R2 endpoint jurisdiction gate")
    ap.add_argument("--selftest", action="store_true", help="prove the gate blocks")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    scanned, findings = check()
    for f in findings:
        print(f"FAIL {f}")
    if findings:
        print(
            "\nR2 endpoints are JURISDICTION-SCOPED. Our bucket lives in `eu`, so the\n"
            "account-default host returns AccessDenied for BOTH list and put — which reads\n"
            "exactly like a bad credential and has already cost us three separate\n"
            "misdiagnoses. Use https://<account>.eu.r2.cloudflarestorage.com.\n\n"
            "This guard checks COMMITTED TEXT. The value actually set on the prod host is\n"
            "not visible here — verify that by reading it back from the RUNNING container\n"
            "and probing the bucket."
        )
        return 1
    print(f"R2 endpoint jurisdiction: clean ({scanned} file(s) mention the endpoint)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
