#!/usr/bin/env python3
"""CLAUDE.md's skill routing graph must only name skills that EXIST and are ENABLED.

WHY THIS EXISTS — 2026-09-10. The graph in `CLAUDE.md` §4a routes ~31 skills by
trigger. It is resident prose, so a skill that is renamed, uninstalled or switched
off in `~/.claude/settings.json` leaves the graph pointing at nothing — and the
failure is SILENT: the reader is told to reach for something that will never
appear in the skill listing, which reads as "I reached for it and nothing
happened" rather than as a broken pointer.

That is the same shape as the two defects the graph itself was built to fix:
`.claude/skills/verify-rust` carried a Rust test bar of "222 gateway / 47 ingest"
against a measured 1,417 — a number nothing re-measured because nothing invoked
it; and `spawn-reviewer`'s description asserted a model version that had rotted.
Prose about tooling rots exactly like prose about code.

WHAT IT CAN AND CANNOT DO, stated here and printed in its own output:
  CAN:    prove every skill the graph NAMES is installed and not disabled, and
          that the DO-NOT-REACH-FOR list names real skills too (a warning about a
          skill that no longer exists is noise that trains people to skim).
  CANNOT: prove the graph's TRIGGERS are well-shaped, or that anyone follows it.
          Invocation is judgement. The measured lesson behind this file is that
          naming a mechanism is NOT sufficient — `proof-of-done` and
          `security-reviewer` were both named and mandated and ran zero times in
          30 days — so a green here means the pointers resolve, never that the
          routing works.

RUNS IN A CLEAN CONTAINER — 2026-09-12. The first version read `~/.claude/skills`
unconditionally, so it passed on the founder's laptop and failed on tl-node-1: CI on
main was red for seven pushes and the deploy record said "verdict NOT read". Skills
that live only in the operator's home are now DECLARED in
`.claude/skills/ENVIRONMENT.txt`; where `~/.claude/skills` is absent the guard
verifies the declaration and says plainly that presence cannot be checked here.

USAGE
  check-skill-routing-graph.py            # check the tree
  check-skill-routing-graph.py --selftest # prove it BLOCKS
EXIT 0 clean · 1 the graph names a missing or disabled skill · 2 cannot determine
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLAUDE_MD = ROOT / "CLAUDE.md"
REPO_SKILLS = ROOT / ".claude/skills"
REPO_AGENTS = ROOT / ".claude/agents"
USER_SKILLS = pathlib.Path.home() / ".claude/skills"
SETTINGS = pathlib.Path.home() / ".claude/settings.json"
# The graph may route to skills that live only in the operator's ~/.claude/skills.
# Those are a property of the MACHINE, so the repo has to DECLARE them for this
# guard to be runnable anywhere else — see the header of that file.
ENV_MANIFEST = REPO_SKILLS / "ENVIRONMENT.txt"

GRAPH_START = "**skills — THE ROUTING GRAPH.**"
GRAPH_END = "· **subagents**"
# A skill name in backticks: lowercase, hyphenated, >=4 chars. The length floor
# keeps ordinary inline code (`{}`, `paths:`) out of the candidate set.
NAME_RE = re.compile(r"`([a-z][a-z0-9-]{3,})`")


def installed() -> set[str]:
    """Everything the graph may legitimately route to.

    SKILLS **and AGENTS**. The graph routes to both — `security-reviewer` is the
    right thing to reach for when a diff touches PII, and it is an agent, not a
    skill. The first version of this guard knew only about skills and therefore
    refused a CORRECT graph, which is the false-refusal shape that gets a guard
    switched off. Caught by running it against the real tree rather than only its
    own fixtures.

    Returns only what is REPO-RESIDENT. Environment-provided skills are a
    separate population — see `environment()` — because a guard that silently
    folds the operator's home directory into "installed" passes on the laptop
    and fails in CI, which is exactly what happened (2026-09-12, seven red
    pushes on main).
    """
    out: set[str] = set()
    if REPO_SKILLS.is_dir():
        out |= {p.name for p in REPO_SKILLS.iterdir() if (p / "SKILL.md").exists()}
    if REPO_AGENTS.is_dir():
        out |= {p.stem for p in REPO_AGENTS.glob("*.md")}
    return out


def declared_env() -> set[str]:
    """Names the repo DECLARES as environment-provided (.claude/skills/ENVIRONMENT.txt)."""
    if not ENV_MANIFEST.is_file():
        return set()
    return {
        ln.strip()
        for ln in ENV_MANIFEST.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    }


def environment() -> set[str] | None:
    """What ~/.claude/skills actually holds, or None when there is no such
    directory (CI, a clean container) — None is "cannot see", never "empty".
    """
    if not USER_SKILLS.is_dir():
        return None
    return {p.name for p in USER_SKILLS.iterdir() if (p / "SKILL.md").exists()}


def disabled() -> set[str]:
    if not SETTINGS.is_file():
        return set()
    try:
        cfg = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return {k for k, v in (cfg.get("skillOverrides") or {}).items() if v == "off"}


def graph_text(md: str) -> str:
    i = md.find(GRAPH_START)
    if i < 0:
        return ""
    j = md.find(GRAPH_END, i)
    return md[i : j if j > i else len(md)]


def check(
    md: str,
    have: set[str],
    off: set[str],
    env_declared: set[str] | None = None,
    env_present: set[str] | None = None,
) -> int:
    """`have` is repo-resident; `env_declared` is the manifest; `env_present` is
    what ~/.claude/skills holds, or None when it cannot be seen (CI).
    """
    env_declared = env_declared or set()
    graph = graph_text(md)
    if not graph:
        print(
            f"✗ CANNOT DETERMINE — no routing graph found in CLAUDE.md.\n"
            f"  Expected a block starting {GRAPH_START!r}.\n"
            f"  An unread graph is not a clean graph: this guard would certify "
            f"anything.",
            file=sys.stderr,
        )
        return 2
    # TWO POPULATIONS, and conflating them made this guard's headline check DEAD
    # CODE on its first run — caught by its own selftest, which is the only reason
    # it is not shipping vacuous.
    #
    # (a) The ROUTING TABLE's "reach for" column. A backticked name there IS a
    #     skill by construction, so a name that resolves to nothing is a REAL
    #     defect and must refuse. This is the population the missing-check needs.
    # (b) Prose elsewhere in the block. A backticked token there could be anything
    #     — a file, a flag, a rule — so an unknown name is not evidence of a
    #     defect. Those are only checked for being DISABLED, which is decidable.
    #
    # The first version took the intersection of ALL names with what the machine
    # already knew, which filtered every missing skill out BEFORE the missing
    # check could see it. A guard whose main branch cannot be reached is worse
    # than no guard: it reports OK on exactly the condition it exists to catch.
    routed: set[str] = set()
    for line in graph.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        # skip the header/separator rows
        if set(cells[-1]) <= set("-: "):
            continue
        routed |= set(NAME_RE.findall(cells[-1]))
    known = have | env_declared
    prose = {n for n in NAME_RE.findall(graph) if n in known or n in off}
    named = routed | prose
    if not named:
        print(
            "✗ CANNOT DETERMINE — the graph named zero recognisable skills.",
            file=sys.stderr,
        )
        return 2

    # Missing is only decidable for the TABLE population — see above. A routed
    # name resolves if it is repo-resident, or declared environment-provided.
    missing = sorted(n for n in routed if n not in known and n not in off)
    # Declared-but-absent is decidable ONLY where the environment is visible.
    env_routed = sorted(n for n in routed if n in env_declared and n not in have)
    unseen = []
    if env_present is None:
        unseen = env_routed
        absent_env: list[str] = []
    else:
        absent_env = [n for n in env_routed if n not in env_present]
    switched_off = sorted(n for n in named if n in off)
    if missing or switched_off or absent_env:
        print("✗ THE ROUTING GRAPH POINTS AT SKILLS THAT WILL NEVER APPEAR:\n")
        if missing:
            print(f"  NOT INSTALLED: {', '.join(missing)}")
            print("    Not in .claude/skills/, not a .claude/agents/ agent, and not")
            print("    declared in .claude/skills/ENVIRONMENT.txt. The graph tells a")
            print("    reader to reach for something that cannot load, which reads as")
            print("    the skill failing rather than as a dead pointer.")
        if absent_env:
            print(f"  DECLARED BUT ABSENT: {', '.join(absent_env)}")
            print("    .claude/skills/ENVIRONMENT.txt says these are provided by the")
            print("    operator's ~/.claude/skills — and on THIS machine they are not.")
            print("    Install them, or remove them from the manifest and the graph.")
        if switched_off:
            print(f"  DISABLED:      {', '.join(switched_off)}")
            print('    `skillOverrides` has these "off" in ~/.claude/settings.json,')
            print("    so they are absent from the listing. Either re-enable them or")
            print("    move them into the DO-NOT-REACH-FOR paragraph with the reason.")
        return 1

    print(
        f"OK — all {len(named)} skill(s) the routing graph names resolve and are enabled."
    )
    if unseen:
        print(
            f"  {len(unseen)} of them are ENVIRONMENT-PROVIDED (declared in "
            f".claude/skills/ENVIRONMENT.txt) and there is no ~/.claude/skills here,"
        )
        print("  so their presence CANNOT be verified on this machine — only that the")
        print(
            "  repo declares them. They are verified wherever ~/.claude/skills exists."
        )
    print("  NOTE: this proves the POINTERS RESOLVE. It cannot prove the triggers are")
    print(
        "  well-shaped, and it cannot prove anyone follows them — `proof-of-done` and"
    )
    print("  `security-reviewer` were both named AND mandated and ran zero times in 30")
    print("  days. Routing is judgement; only the pointer is machine-checkable.")
    return 0


def selftest() -> int:
    fails = 0

    def case(
        label: str,
        md: str,
        have: set[str],
        off: set[str],
        want: int,
        env_declared: set[str] | None = None,
        env_present: set[str] | None = None,
    ) -> None:
        nonlocal fails
        got = check(md, have, off, env_declared, env_present)
        if got == want:
            print(f"  ✓ {label}")
        else:
            print(f"  ✗ {label} — expected rc={want}, got {got}")
            fails += 1

    # A TABLE, because that is the population the missing-check reads. A prose-only
    # fixture is what let the dead branch pass review the first time.
    good = (
        f"{GRAPH_START}\n"
        "| About to… | Reach for |\n"
        "|---|---|\n"
        "| build a thing | `spec-first` |\n"
        "| edit copy | `public-copy` |\n"
        f"{GRAPH_END}"
    )
    case(
        "a graph naming installed, enabled skills PASSES",
        good,
        {"spec-first", "public-copy"},
        set(),
        0,
    )
    case("a graph naming an UNINSTALLED skill REFUSES", good, {"spec-first"}, set(), 1)
    case(
        "a graph naming a DISABLED skill REFUSES",
        good,
        {"spec-first", "public-copy"},
        {"public-copy"},
        1,
    )
    case(
        "no graph at all is CANNOT DETERMINE, never a pass",
        "# CLAUDE.md with no routing block",
        {"spec-first"},
        set(),
        2,
    )
    case(
        "a graph naming zero recognisable skills is CANNOT DETERMINE",
        f"{GRAPH_START} prose with no skills {GRAPH_END}",
        {"spec-first"},
        set(),
        2,
    )

    # The environment split — the defect that had CI red for seven pushes.
    env_graph = (
        f"{GRAPH_START}\n"
        "| About to… | Reach for |\n"
        "|---|---|\n"
        "| build a thing | `spec-first` |\n"
        "| write a test | `test-driven-development` |\n"
        f"{GRAPH_END}"
    )
    case(
        "an env-provided skill, DECLARED, with NO ~/.claude visible (CI) PASSES",
        env_graph,
        {"spec-first"},
        set(),
        0,
        env_declared={"test-driven-development"},
        env_present=None,
    )
    case(
        "an env-provided skill NOT declared, with no ~/.claude visible, REFUSES",
        env_graph,
        {"spec-first"},
        set(),
        1,
        env_declared=set(),
        env_present=None,
    )
    case(
        "a DECLARED env skill that is ABSENT from a visible ~/.claude REFUSES",
        env_graph,
        {"spec-first"},
        set(),
        1,
        env_declared={"test-driven-development"},
        env_present={"something-else"},
    )
    case(
        "a DECLARED env skill PRESENT in a visible ~/.claude PASSES",
        env_graph,
        {"spec-first"},
        set(),
        0,
        env_declared={"test-driven-development"},
        env_present={"test-driven-development"},
    )

    # And it must parse the REAL tree, or it certifies nothing — BOTH ways: as the
    # operator's machine sees it, and as a clean container (CI) would.
    real = check(
        CLAUDE_MD.read_text(encoding="utf-8"),
        installed(),
        disabled(),
        declared_env(),
        environment(),
    )
    real_ci = check(
        CLAUDE_MD.read_text(encoding="utf-8"),
        installed(),
        set(),
        declared_env(),
        None,
    )
    if real_ci == 0:
        print(
            "  ✓ the real CLAUDE.md graph resolves in a CLEAN CONTAINER (no ~/.claude)"
        )
    else:
        print(f"  ✗ the real graph does NOT resolve without ~/.claude (rc={real_ci})")
        fails += 1
    if real == 0:
        print("  ✓ the real CLAUDE.md graph resolves")
    else:
        print(f"  ✗ the real CLAUDE.md graph does NOT resolve (rc={real})")
        fails += 1

    if fails:
        print(f"\nSELFTEST FAILED — {fails} case(s)")
        return 1
    print("\nSELFTEST PASSED — a missing skill, a disabled skill and an absent graph")
    print("  all refuse, and a clean graph passes.")
    return 0


def main() -> int:
    # REJECT UNKNOWN ARGV, and the reason is the meta-gate's, not mine: a guard that
    # exits 0 for `--tracelane-meta-gate-nonsense-flag` demonstrably does not parse
    # its arguments — so its `--selftest` "pass" proves NOTHING, because the flag
    # may simply have been ignored and the normal check run instead. That is exactly
    # what this file did on its first run, and `check-guard-selftests.py` refused it.
    argv = sys.argv[1:]
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print(f"✗ unknown argument(s): {' '.join(argv)}", file=sys.stderr)
        print(__doc__.split("USAGE")[-1].strip(), file=sys.stderr)
        return 2
    if not CLAUDE_MD.is_file():
        print(f"✗ CANNOT DETERMINE — {CLAUDE_MD} not found", file=sys.stderr)
        return 2
    return check(
        CLAUDE_MD.read_text(encoding="utf-8"),
        installed(),
        disabled(),
        declared_env(),
        environment(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
