#!/usr/bin/env python3
"""Fail if a third-party processor is ENABLED in config but ABSENT from the legal tables.

A sub-processor table is a contractual disclosure. It goes stale the moment someone
wires up a vendor and forgets the paperwork — and nothing about a green build would
say so. This guard ties the two together: if the tracked configuration turns a vendor
on, the disclosure must land in the SAME change.

WHY THIS EXISTS (2026-08-08). Auditing the legal files against the live system found
`docs/legal/dpa.md` and `privacy-policy.md` still naming Singapore for a control plane
that had moved to Frankfurt weeks earlier. Same audit found **PostHog** genuinely wired
in `crates/gateway/src/kill_switch.rs` (feature flags, fail-safe when unconfigured) but
absent from both sub-processor tables. It is dormant today — `POSTHOG_PROJECT_API_KEY`
is unset in production, so it fails safe and no data leaves — which is exactly why it
would have been missed the day someone set the key.

THE SIGNAL. Production `.env` is not in the repo, so this cannot read it. What it CAN
read is the tracked configuration that turns a vendor on: an env var appearing in a
compose file, `.env.example`, a deploy script, or a workflow. That is the reviewable
moment, and it is the one this guard gates.

Each entry says: "if this env var shows up in tracked CONFIG, these files must mention
this vendor." Source files that merely *implement* the integration are exempt — the
Rust module that reads the key is not evidence the key is set.

Sigstore Rekor is deliberately NOT listed. It receives a Merkle root — a hash, never a
payload — so there is no personal-data processing to disclose. That reasoning lives in
`apps/docs/security.mdx`; see the note there before adding it here.

Exit 1 naming the vendor and the missing file; 0 when clean.
  --selftest  plants an enabling config line and proves the guard BLOCKS.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# vendor -> (env vars that ENABLE it, files that must disclose it, display name)
VENDORS = {
    "posthog": (
        ("POSTHOG_PROJECT_API_KEY", "POSTHOG_HOST"),
        ("docs/legal/privacy-policy.md", "docs/legal/dpa.md"),
        "PostHog",
    ),
}

# Where an env var appearing means "this vendor is being turned on". Source trees are
# NOT here: implementing the integration is not the same as enabling it.
CONFIG_SUFFIXES = (".yml", ".yaml", ".env", ".example", ".sh", ".toml", ".json", ".tf")
CONFIG_DIR_HINTS = ("infra/", "scripts/deploy/", ".github/workflows/", "docker")
# This guard necessarily contains the literal var names; never scan itself.
SELF = "scripts/ci/check-subprocessor-disclosure.py"

# Every flag this script implements. A guard that silently IGNORES an unknown flag
# runs the ordinary check and exits 0 — so `--selftesst` (typo) reports PASS while no
# selftest ran, and the `--selftest` result proves nothing. Enforced by
# scripts/ci/check-guard-selftests.py.
KNOWN_FLAGS = {"--selftest"}
USAGE = "usage: check-subprocessor-disclosure.py [--selftest]"


def reject_unknown_flags(argv: list[str]) -> None:
    """Exit 2 on any option this script does not implement."""
    unknown = [a for a in argv if a.startswith("-") and a not in KNOWN_FLAGS]
    if unknown:
        print(f"unknown option: {' '.join(unknown)}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [p for p in out.splitlines() if p]


def is_config(path: str) -> bool:
    if path == SELF:
        return False
    if path.endswith(CONFIG_SUFFIXES):
        return True
    return any(h in path for h in CONFIG_DIR_HINTS)


def check(files: list[str], root: Path) -> list[str]:
    problems: list[str] = []
    for vendor, (env_vars, must_disclose, display) in VENDORS.items():
        alternation = "|".join(env_vars)
        pattern = re.compile(rf"^\s*[-#]?\s*(?:{alternation})\s*[=:]", re.MULTILINE)
        enabling: list[str] = []
        for rel in files:
            if not is_config(rel):
                continue
            fp = root / rel
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if pattern.search(text):
                enabling.append(rel)
        if not enabling:
            continue
        for doc in must_disclose:
            dp = root / doc
            body = (
                dp.read_text(encoding="utf-8", errors="ignore") if dp.exists() else ""
            )
            if vendor not in body.lower():
                problems.append(
                    f"{display} is enabled by {enabling[0]} but is not disclosed in {doc}.\n"
                    f"    A sub-processor table is a contractual disclosure — it lands in the "
                    f"SAME commit that turns the vendor on, not later."
                )
    return problems


def selftest() -> int:
    print("selftest: plant an enabling config line, prove the guard BLOCKS")
    files = tracked_files()
    if check(files, ROOT):
        print(
            "  ✗ baseline is already failing — fix the real finding first",
            file=sys.stderr,
        )
        return 1
    print("  ✓ baseline clean")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # Minimal tree: an enabling compose file + the two legal docs WITHOUT the vendor.
        (tmp / "infra" / "prod").mkdir(parents=True)
        (tmp / "docs" / "legal").mkdir(parents=True)
        (tmp / "infra" / "prod" / "docker-compose.yml").write_text(
            "services:\n  gateway:\n    environment:\n      POSTHOG_PROJECT_API_KEY: phc_x\n",
            encoding="utf-8",
        )
        for doc in ("privacy-policy.md", "dpa.md"):
            (tmp / "docs" / "legal" / doc).write_text(
                "| Hetzner | Compute | EU |\n", encoding="utf-8"
            )
        planted = [
            "infra/prod/docker-compose.yml",
            "docs/legal/privacy-policy.md",
            "docs/legal/dpa.md",
        ]

        found = check(planted, tmp)
        if len(found) != 2:
            print(
                f"  ✗ expected 2 findings (one per legal file), got {len(found)}",
                file=sys.stderr,
            )
            return 1
        print("  ✓ BLOCKS when enabled-but-undisclosed, naming both legal files")

        # And it must PASS once disclosed — a guard that always fires is not a guard.
        for doc in ("privacy-policy.md", "dpa.md"):
            (tmp / "docs" / "legal" / doc).write_text(
                "| PostHog | Feature flags | Provider-managed |\n", encoding="utf-8"
            )
        if check(planted, tmp):
            print(
                "  ✗ still fires after disclosure — not discriminating", file=sys.stderr
            )
            return 1
        print("  ✓ passes once disclosed")

    print("selftest: PASSED — observed blocking and passing")
    return 0


def main() -> int:
    reject_unknown_flags(sys.argv[1:])
    if "--selftest" in sys.argv:
        return selftest()
    problems = check(tracked_files(), ROOT)
    if problems:
        print("Undisclosed sub-processor:", file=sys.stderr)
        for p in problems:
            print(f"  ✗ {p}", file=sys.stderr)
        return 1
    print(
        "sub-processor disclosure: OK — no vendor is enabled in config without disclosure"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
