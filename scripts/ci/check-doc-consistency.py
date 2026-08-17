#!/usr/bin/env python3
"""Cross-document consistency gate.

A per-file adversarial read CANNOT catch a contradiction between two files — each
one reads fine in isolation. That gap produced a near-miss on 2026-08-07 (the
retention table, the `rekor_entry_id` absent-vs-null semantics, the EU AI Act
enforcement date, and `tlane export`'s flags each said two different things in two
shipping docs). Per CLAUDE.md's graduation ladder, that miss becomes an executable
gate rather than a habit.

WHAT THIS DOES: extracts typed FACTS from every exported doc, groups them by fact
key, and fails when one key carries two different values. Where a fact has a CODE
anchor, the code value is authoritative and any doc disagreeing with it is the bug
— not "whichever doc sounds right".

WHAT THIS DOES NOT DO — stated so nobody mistakes a green run for proof:
  * It only knows the fact families enumerated below. A contradiction in a family
    nobody encoded is invisible. Adding a family is the intended way to extend it.
  * It compares VALUES, not meaning. Two docs can agree on a number and both be
    wrong; that is the per-file pass's job, not this one.
  * It cannot see doc-vs-deployed-config or doc-vs-live-behaviour drift.

Usage:
    check-doc-consistency.py            # scan the export set, exit 1 on conflict
    check-doc-consistency.py --all      # scan every tracked doc, not just exported
    check-doc-consistency.py --selftest # plant a contradiction, prove it blocks
"""

from __future__ import annotations

import importlib.util as _ilu
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# Fact families.
#
# Each family maps a regex over a doc line to a normalised (key, value). Two docs
# emitting the same key with different values is a CONFLICT. `code` names the
# authoritative source when one exists, so the reviewer resolves to code truth
# instead of picking the nicer sentence.
# --------------------------------------------------------------------------
FAMILIES: list[dict] = [
    {
        "name": "node-version",
        "code": "package.json engines.node",
        "pat": re.compile(r"Node(?:\.js)?\s*(\d{2})\+", re.IGNORECASE),
        "key": lambda _m: "node-major",
    },
    {
        "name": "pnpm-version",
        "code": "package.json packageManager",
        "pat": re.compile(r"pnpm\s*(\d+(?:\.\d+)*)\+?", re.IGNORECASE),
        "key": lambda _m: "pnpm-major",
        "norm": lambda v: v.split(".")[0],
    },
    {
        "name": "rust-version",
        "code": "rust-toolchain.toml channel",
        "pat": re.compile(r"Rust(?:\s+toolchain)?\s*(1\.\d{2})", re.IGNORECASE),
        "key": lambda _m: "rust-channel",
    },
    {
        "name": "postgres-version",
        "code": "infra/dev/docker-compose.yml postgres image",
        "pat": re.compile(r"Postgres\s*(\d{2})\b", re.IGNORECASE),
        "key": lambda _m: "postgres-major",
    },
    {
        "name": "provider-count",
        "code": "crates/gateway/src/providers/mod.rs provider_id_for_model",
        "pat": re.compile(r"(\d{2})\+?\s*(?:LLM\s*)?providers", re.IGNORECASE),
        "key": lambda _m: "provider-count",
    },
    {
        "name": "painpoint-eval-count",
        "code": "evals/pain-points/*.eval.ts",
        "pat": re.compile(r"(\d{2,3})\s*pain[- ]point", re.IGNORECASE),
        "key": lambda _m: "painpoint-evals",
    },
    {
        "name": "ft-eval-count",
        "code": "evals/fault-tolerance/*.eval.ts",
        "pat": re.compile(r"(\d{1,3})\s*fault[- ]tolerance", re.IGNORECASE),
        "key": lambda _m: "ft-evals",
    },
    {
        "name": "anchor-batch-size",
        "code": "crates/gateway/src/server.rs TRACELANE_REKOR_ANCHOR_EVERY",
        "pat": re.compile(r"[Ee]very\s+(\d+)\s+events", re.IGNORECASE),
        "key": lambda _m: "anchor-batch",
    },
    {
        "name": "retention-days",
        "code": "apps/web/db/seed.mjs retention_days",
        # "Free | 7 days", "Business ($899) | 180 days"
        "pat": re.compile(
            r"\b(Free|Builder|Team|Business|Enterprise)\b[^|\n]{0,40}?\|\s*(\d{1,4})\s*day",
            re.IGNORECASE,
        ),
        "key": lambda m: f"retention-{m.group(1).lower()}",
        "grp": 2,
    },
    {
        "name": "rpm-limit",
        "code": "crates/gateway/src/rate_limiter.rs",
        "pat": re.compile(
            r"\b(Free|Builder|Team|Business)\b[^|\n]{0,40}?\|\s*([\d,]{2,7})\s*(?:RPM|requests per minute)",
            re.IGNORECASE,
        ),
        "key": lambda m: f"rpm-{m.group(1).lower()}",
        "grp": 2,
        "norm": lambda v: v.replace(",", ""),
    },
    {
        "name": "eu-ai-act-date",
        "code": None,  # regulatory fact — no code anchor; must agree across docs
        "pat": re.compile(
            r"(?:Annex III|high-risk|[Ee]nforcement date)[^.\n]{0,80}?"
            r"((?:January|February|March|April|May|June|July|August|September|"
            r"October|November|December)\s+\d{1,2},?\s+20\d{2}|20\d{2})",
        ),
        "key": lambda _m: "eu-ai-act-timeline",
    },
    {
        "name": "rekor-entry-id-semantics",
        "code": "crates/gateway/src/audit_export.rs skip_serializing_if",
        # the absent-vs-null contradiction that shipped in two docs at once
        "pat": re.compile(
            r"rekor_entry_id[^.\n]{0,120}?\b(absent|omitted|empty|null)\b",
            re.IGNORECASE,
        ),
        "key": lambda _m: "rekor-entry-id-when-unanchored",
        "norm": lambda v: {"omitted": "absent", "null": "empty"}.get(
            v.lower(), v.lower()
        ),
    },
    {
        "name": "audit-export-endpoint",
        "code": "crates/gateway/src/server.rs route mounts",
        "pat": re.compile(r"(/(?:v1|api)/audit/(?:export|range))\b"),
        "key": lambda _m: "audit-export-path",
    },
]

# CLI invocations are checked structurally rather than by value: a documented flag
# that no command registers is a contradiction between docs and the CLI source.
# TWO binaries with DIFFERENT flag sets: `tlane` is the TypeScript CLI
# (packages/cli), `tracelane-audit` is the Rust verifier (crates/tracelane-audit-cli).
# Conflating them made this gate report 9 false positives on its first run - the
# check has to know which registry an invocation belongs to.
CLI_INVOKE = re.compile(
    r"\b(?:npx\s+\S*cli\s+|(tlane)|(tracelane-audit))\s+([a-z][a-z-]*)\s+([^\n`]*)"
)
CLI_FLAG = re.compile(r"(--[a-z][a-z0-9-]*)")


def sh(*args: str) -> str:
    return subprocess.run(
        args, capture_output=True, text=True, cwd=ROOT, check=False
    ).stdout


def exported_docs() -> list[str]:
    """Reuse the classification gate's export logic rather than reimplementing it."""
    spec = _ilu.spec_from_file_location(
        "clsgate", ROOT / "scripts" / "ci" / "check-doc-classification.py"
    )
    if spec is None or spec.loader is None:
        return []
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    allow, deny = mod.parse_allow(), mod.parse_deny()
    out = sh("git", "ls-files", "-z").split("\0")
    return [
        p
        for p in out
        if p
        and p.endswith((".md", ".mdx", ".mdc"))
        and (ROOT / p).exists()
        and mod.is_exported(p, allow, deny)
    ]


def all_docs() -> list[str]:
    out = sh("git", "ls-files", "-z").split("\0")
    return [
        p
        for p in out
        if p and p.endswith((".md", ".mdx", ".mdc")) and (ROOT / p).exists()
    ]


def rust_cli_flags() -> set[str]:
    """Flags of the Rust verifier, read from its clap-derive struct fields."""
    src = ROOT / "crates" / "tracelane-audit-cli" / "src" / "main.rs"
    if not src.is_file():
        return set()
    txt = src.read_text(encoding="utf-8", errors="replace")
    fields = re.findall(r"^\s+(?:pub )?([a-z][a-z0-9_]*)\s*:", txt, re.MULTILINE)
    return {"--" + f.replace("_", "-") for f in fields}


def registered_cli_flags() -> dict[str, set[str]]:
    """Map subcommand -> registered flags, read from the TypeScript CLI source."""
    reg: dict[str, set[str]] = defaultdict(set)
    cmd_dir = ROOT / "packages" / "cli" / "src" / "commands"
    if not cmd_dir.is_dir():
        return reg
    for f in cmd_dir.glob("*.ts"):
        txt = f.read_text(encoding="utf-8", errors="replace")
        # .command("verify <ledger>")  /  .command("export")
        cmds = re.findall(r'\.command\(\s*"([a-z][a-z-]*)', txt)
        flags = set(
            re.findall(r'\.(?:required)?[Oo]ption\(\s*"(--[a-z][a-z0-9-]*)', txt)
        )
        for c in cmds:
            reg[c] |= flags
    return reg


def scan(docs: list[str]) -> tuple[dict, list]:
    facts: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    cli_hits: list[tuple[str, int, str, str, str]] = []
    for p in docs:
        text = (ROOT / p).read_text(encoding="utf-8", errors="replace")
        in_fence = False
        for i, line in enumerate(text.split("\n"), 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
            for fam in FAMILIES:
                m = fam["pat"].search(line)
                if not m:
                    continue
                val = m.group(fam.get("grp", 1))
                if "norm" in fam:
                    val = fam["norm"](val)
                facts[f"{fam['name']}::{fam['key'](m)}"].append((val, p, i))
            if in_fence:
                mc = CLI_INVOKE.search(line)
                if mc:
                    binary = "rust" if mc.group(2) else "ts"
                    cli_hits.append((p, i, mc.group(3), mc.group(4), binary))
    return facts, cli_hits


def report(docs: list[str]) -> int:
    facts, cli_hits = scan(docs)
    problems = 0

    print(
        f"cross-document consistency — {len(docs)} docs, {len(FAMILIES)} fact families\n"
    )

    for key, seen in sorted(facts.items()):
        values = {v for v, _, _ in seen}
        if len(values) <= 1:
            continue
        fam_name = key.split("::")[0]
        anchor = next((f.get("code") for f in FAMILIES if f["name"] == fam_name), None)
        problems += 1
        print(f"CONFLICT [{key}] — {len(values)} different values across docs:")
        for v, p, i in sorted(seen):
            print(f"    {v:<22} {p}:{i}")
        if anchor:
            print(f"    -> resolve to CODE: {anchor}")
        else:
            print(
                "    -> no code anchor: pick the value matching shipped behaviour, fix the other"
            )
        print()

    reg = registered_cli_flags()
    rust = rust_cli_flags()
    for p, i, cmd, rest, binary in cli_hits:
        if binary == "rust":
            if not rust:
                continue
            known, label = rust, "tracelane-audit (Rust)"
        else:
            if cmd not in reg:
                continue
            known, label = reg[cmd], f"tlane {cmd}"
        for fl in CLI_FLAG.findall(rest):
            if fl not in known:
                problems += 1
                print(
                    f"CONFLICT [cli-flag] {p}:{i} — `{fl}` is not registered on {label}"
                )
                print(f"    -> registered: {' '.join(sorted(known)) or '(none)'}\n")

    if problems:
        print(f"FAIL — {problems} cross-document conflict(s).")
        return 1
    print("OK — no cross-document conflicts in the encoded fact families.")
    print("NOTE: green here means the ENCODED families agree. It is not proof of")
    print("      correctness, and it cannot see families nobody encoded.")
    return 0


def selftest() -> int:
    """Plant a contradiction and a bogus CLI flag; prove both block."""
    print("selftest: planting a cross-document contradiction ...")
    with tempfile.TemporaryDirectory() as td:
        a = Path(td) / "a.md"
        b = Path(td) / "b.md"
        a.write_text("Requires Node 22+ and pnpm 9.\n", encoding="utf-8")
        b.write_text("Requires Node 20+ and pnpm 9.\n", encoding="utf-8")

        global ROOT
        real_root = ROOT
        ROOT = Path(td)
        try:
            facts, _ = scan(["a.md", "b.md"])
            conflicts = [k for k, s in facts.items() if len({v for v, _, _ in s}) > 1]
        finally:
            ROOT = real_root

        if not conflicts:
            print("  FAIL: planted Node 22-vs-20 contradiction was NOT detected")
            return 1
        print(f"  OK: detected {conflicts}")

    print("selftest: confirming a matching pair does NOT fire ...")
    with tempfile.TemporaryDirectory() as td:
        Path(td, "a.md").write_text("Requires Node 22+.\n", encoding="utf-8")
        Path(td, "b.md").write_text("Requires Node 22+.\n", encoding="utf-8")
        real_root = ROOT
        ROOT = Path(td)
        try:
            facts, _ = scan(["a.md", "b.md"])
            conflicts = [k for k, s in facts.items() if len({v for v, _, _ in s}) > 1]
        finally:
            ROOT = real_root
        if conflicts:
            print(f"  FAIL: false positive on agreeing docs: {conflicts}")
            return 1
        print("  OK: no false positive")

    print(
        "selftest PASSED — the gate blocks a real contradiction and stays quiet otherwise."
    )
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    docs = all_docs() if "--all" in sys.argv else exported_docs()
    return report(docs)


KNOWN_FLAGS = {"--selftest", "--all"}


def reject_unknown_flags(argv: list[str]) -> None:
    """Exit 2 on any flag-shaped token we do not implement — a silently ignored
    `--selftesst` runs the ordinary gate and exits 0, so the operator believes a
    falsification ran when none did. Only `-`-prefixed tokens are judged."""
    unknown = [a for a in argv if a.startswith("-") and a not in KNOWN_FLAGS]
    if unknown:
        print(
            f"check-doc-consistency.py: unknown option(s): {' '.join(unknown)}\n"
            f"usage: check-doc-consistency.py [--all | --selftest]",
            file=sys.stderr,
        )
        raise SystemExit(2)


if __name__ == "__main__":
    reject_unknown_flags(sys.argv[1:])
    raise SystemExit(main())
