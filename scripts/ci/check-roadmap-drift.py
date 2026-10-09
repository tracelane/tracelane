#!/usr/bin/env python3
"""Roadmap-drift guard (OG-93, RCA control C6): a commit that says it closed a tracked item
must move that item's ROADMAP row in the SAME commit.

WHY THIS EXISTS. `runbooks/RCA-one-gateway-bug-cluster-2026-10-01.md`, root cause 8: "tracker
closure flows one way". B-545 and PL-9 were fixed in code and their `docs/runbook/ROADMAP.md`
rows said PENDING-FOUNDER for days; the next session planned around a false state. Nothing tied a
row's status to the commit that made it untrue.

THE RULE. Parse the commit message for a CLOSING CLAIM: a closing word (fix / fixes / fixed /
close / closes / closed / resolve / resolves / resolved / built / done) in the same sentence as an
id that has a row in the ROADMAP. For each claimed id, the commit's diff MUST change that row's
STATUS cell (the second cell). Consequences, all deliberate:

  * An id with no row is ignored (a message may cite any ticket, in any system).
  * A row whose status is already terminal (BUILT / CUT / REFUTED / REMOVED) needs no move.
  * A row the commit ADDS counts as moved (its status is being set).
  * The escape hatch is a trailer, never silence:
        Roadmap-Drift-Ok: <id> <reason of at least 20 characters>
    It is printed on every run it is used. A reason shorter than 20 characters does not count.

WHAT IT DOES NOT DO (spec OG-93 §6): it never infers closure from code. A commit that fixes a
tracked item WITHOUT SAYING SO is invisible to it. That is a real blind spot, and the replay of
commit 0a44e389 shows it (see the selftest and the OG-93 hand-off): that commit's own message
names no id at all.

USAGE
  check-roadmap-drift.py --msg-file FILE --staged   # .githooks/commit-msg: FILE vs the staged diff
  check-roadmap-drift.py --commit REV [--msg-file F] # one commit; --msg-file replays ANOTHER message
                                                    # against REV's own diff
  check-roadmap-drift.py --range REVS...            # every commit in `git rev-list REVS...`
  check-roadmap-drift.py                            # the unpushed commits: HEAD --not --remotes
  check-roadmap-drift.py --selftest                 # build a throwaway repo and prove it BLOCKS

Fail-CLOSED on the claim path: an unreadable ROADMAP at a revision where a claim was made is an
error, not a pass. Fail-OPEN where there is nothing to check: no ROADMAP in either revision, or a
merge commit (its parents were each checked when they were made).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def _repo_root() -> Path:
    """The repository the caller is IN (a hook or verify-all runs from its root; the selftest runs
    from a throwaway repo) — never the repo this file happens to live in."""
    p = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    return (
        Path(p.stdout.strip()) if p.returncode == 0 and p.stdout.strip() else Path.cwd()
    )


ROOT = _repo_root()
ROADMAP = "docs/runbook/ROADMAP.md"
MIN_REASON = 20

# The spec's claim vocabulary. Whole tokens only, case-insensitive: "prefixed" must not claim.
CLOSING_VERBS = frozenset({"fix", "fixes", "close", "closes", "resolve", "resolves"})
CLOSING_PARTICIPLES = frozenset({"fixed", "closed", "resolved", "built", "done"})
# Words that may sit between a participle and the id it claims ("B-545 is now fixed").
FILLER = frozenset(
    {
        "is",
        "was",
        "are",
        "were",
        "now",
        "been",
        "has",
        "have",
        "all",
        "also",
        "and",
        "finally",
        "properly",
        "fully",
        "really",
        "just",
    }
)
# A sentence ends at . ! ? followed by whitespace/end, at ';', or at a newline. The id
# `B-545.` at the end of a sentence still ends it; `1.2` and `B-545` do not.
SENTENCE_END = re.compile(r"(?<=[.!?])\s+|;|\n+")
TRAILER = re.compile(r"^\s*Roadmap-Drift-Ok:\s*(\S+)\s*(.*?)\s*$", re.IGNORECASE)
# Statuses after which there is nothing left to flip.
TERMINAL = ("BUILT", "CUT", "REFUTED", "REMOVED")


class RoadmapUnreadable(Exception):
    pass


# ── git plumbing ────────────────────────────────────────────────────────────


def _git(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None
) -> tuple[int, str]:
    p = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return p.returncode, p.stdout


def _show(rev_path: str, *, cwd: Path, env: dict[str, str] | None) -> str | None:
    """File content at `rev:path` (or `:path` for the index); None when it does not exist."""
    rc, out = _git(["show", rev_path], cwd=cwd, env=env)
    return out if rc == 0 else None


# ── ROADMAP parsing ─────────────────────────────────────────────────────────


def parse_rows(text: str | None) -> dict[str, list[str]]:
    """`id -> [status cell, ...]` for every table row whose first cell is a backticked id.

    A grouped row (`B-561/B-563/B-564`) defines each of its ids. The status cell is the second
    cell, verbatim (whitespace-trimmed): any edit to it counts as a move.
    """
    rows: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        if not line.startswith("| `"):
            continue
        cells = line.split("|")
        if len(cells) < 4:
            continue
        first = cells[1].strip()
        m = re.fullmatch(r"`([^`]+)`", first)
        if not m:
            continue
        status = cells[2].strip()
        for ident in m.group(1).split("/"):
            ident = ident.strip()
            if ident:
                rows.setdefault(ident, []).append(status)
    return rows


def status_word(cell: str) -> str:
    m = re.match(r"\*\*([A-Za-z-]+)", cell)
    return m.group(1).upper() if m else ""


# ── message parsing ─────────────────────────────────────────────────────────


def strip_message(msg: str) -> str:
    """Drop git's `#` comment lines (a commit-msg file carries the template's)."""
    return "\n".join(ln for ln in msg.splitlines() if not ln.startswith("#"))


def trailers(msg: str) -> dict[str, str]:
    """`id -> reason` for every well-formed Roadmap-Drift-Ok trailer (reason >= MIN_REASON)."""
    out: dict[str, str] = {}
    for ln in msg.splitlines():
        m = TRAILER.match(ln)
        if m and len(m.group(2)) >= MIN_REASON:
            out[m.group(1)] = m.group(2)
    return out


def short_trailers(msg: str) -> list[str]:
    return [
        m.group(1)
        for ln in msg.splitlines()
        if (m := TRAILER.match(ln)) and len(m.group(2)) < MIN_REASON
    ]


TOKEN = re.compile(r"[A-Za-z0-9#_-]+")
# How many words after a VERB form an id may sit and still be what it closes.
VERB_REACH = 6


def claimed_ids(msg: str, known: set[str]) -> set[str]:
    """Row ids a closing word is ABOUT, within one sentence.

    The spec says "within the same sentence". Replayed over this repo's history that over-claims
    twice, so the rule is tightened to where a closing word actually points:

      * a participle doubles as an adjective ("fixed policy windows" made a dashboard commit claim
        OBS-60 closed) and a verb as a noun ("B-459 gate fixes: …", "…and the security fixes" at the
        end of a five-id subject line claimed all five). So:
      * ANY closing word claims an id it is NEXT to — nothing but filler words ("is", "now",
        "and"…) or other ids between — on either side: "B-545 is now fixed", "fixed B-545",
        "B-545: fixes the retry";
      * a VERB form (fix, fixes, close, closes, resolve, resolves) also claims ids up to six words
        AFTER it: "fixes the alert retry loop (B-545)";
      * whatever it claims extends through the list the id belongs to: "closes B-1, B-2 and B-3".
    """
    if not known:
        return set()
    out: set[str] = set()
    for sentence in SENTENCE_END.split(msg):
        # The trailer line itself must not be read as a claim ("...Ok: B-1 reason: fixed").
        if TRAILER.match(sentence):
            continue
        toks = TOKEN.findall(sentence)
        id_at = [i for i, t in enumerate(toks) if t in known]
        if not id_at:
            continue
        for k, t in enumerate(toks):
            low = t.lower()
            if low not in CLOSING_VERBS and low not in CLOSING_PARTICIPLES:
                continue
            claimed: set[int] = set()
            for i in id_at:
                between = range(min(i, k) + 1, max(i, k))
                adjacent = all(
                    toks[j].lower() in FILLER or toks[j] in known for j in between
                )
                if adjacent or (low in CLOSING_VERBS and 0 < i - k <= VERB_REACH):
                    claimed.add(i)
            for start in list(claimed):  # extend through "B-1, B-2 and B-3"
                for step in (1, -1):
                    j = start + step
                    while 0 <= j < len(toks) and (
                        toks[j] in known or toks[j].lower() == "and"
                    ):
                        if toks[j] in known:
                            claimed.add(j)
                        j += step
            out.update(toks[i] for i in claimed)
    return out


# ── the check ───────────────────────────────────────────────────────────────


def check(
    label: str,
    msg: str,
    old_text: str | None,
    new_text: str | None,
) -> tuple[list[str], list[str]]:
    """(violations, notes) for one commit/message against its ROADMAP before and after."""
    msg = strip_message(msg)
    old_rows, new_rows = parse_rows(old_text), parse_rows(new_text)
    known = set(old_rows) | set(new_rows)
    ids = claimed_ids(msg, known)
    ok = trailers(msg)
    violations: list[str] = []
    notes: list[str] = []
    for bad in short_trailers(msg):
        notes.append(
            f"{label}: Roadmap-Drift-Ok for {bad} ignored — the reason must be at least {MIN_REASON} characters"
        )
    for ident in sorted(ids):
        old_s, new_s = old_rows.get(ident), new_rows.get(ident)
        if old_s is None:
            continue  # the row is new in this commit: its status is being set
        if new_s is not None and sorted(new_s) != sorted(old_s):
            continue  # moved
        if old_s and all(status_word(s) in TERMINAL for s in old_s):
            notes.append(
                f"{label}: {ident} is already {status_word(old_s[0])} — nothing to move"
            )
            continue
        if ident in ok:
            notes.append(f"{label}: OVERRIDE Roadmap-Drift-Ok {ident}: {ok[ident]}")
            continue
        shown = (
            (old_s[0][:70] + "…")
            if old_s and len(old_s[0]) > 70
            else (old_s or ["?"])[0]
        )
        violations.append(
            f"{label}: the message claims {ident} closed, but its ROADMAP row (`{ROADMAP}`) is "
            f"unchanged — status still {shown}"
        )
    return violations, notes


def _hint() -> str:
    return (
        "  Fix: flip the row's status cell in docs/runbook/ROADMAP.md in THIS commit, or, if the\n"
        "  message is not a closure claim, say so in the message:\n"
        "      Roadmap-Drift-Ok: <id> <reason of at least 20 characters>\n"
    )


def read_roadmap_pair(
    rev: str, parents: list[str], *, cwd: Path, env: dict[str, str] | None
) -> tuple[str | None, str | None]:
    new = _show(f"{rev}:{ROADMAP}", cwd=cwd, env=env)
    old = _show(f"{parents[0]}:{ROADMAP}", cwd=cwd, env=env) if parents else None
    return old, new


def commit_info(
    rev: str, *, cwd: Path, env: dict[str, str] | None
) -> tuple[str, str, list[str]]:
    rc, out = _git(["log", "-1", "--format=%h%x00%P%x00%B", rev], cwd=cwd, env=env)
    if rc != 0 or "\x00" not in out:
        raise RoadmapUnreadable(f"cannot read commit {rev}")
    short, parents, body = out.split("\x00", 2)
    return short, body, parents.split()


def check_commit(
    rev: str,
    *,
    msg_override: str | None = None,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    short, body, parents = commit_info(rev, cwd=cwd, env=env)
    if len(parents) > 1:
        return [], [f"{short}: merge commit — skipped (its parents were each checked)"]
    old, new = read_roadmap_pair(rev, parents, cwd=cwd, env=env)
    if old is None and new is None:
        return [], []
    return check(short, body if msg_override is None else msg_override, old, new)


def check_staged(msg: str, *, cwd: Path = ROOT, env: dict[str, str] | None = None):
    old = _show(f"HEAD:{ROADMAP}", cwd=cwd, env=env)
    new = _show(f":{ROADMAP}", cwd=cwd, env=env)
    if old is None and new is None:
        return [], []
    return check("staged", msg, old, new)


def check_revs(revs: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None):
    rc, out = _git(["rev-list", "--reverse", *revs], cwd=cwd, env=env)
    if rc != 0:
        raise RoadmapUnreadable(f"cannot list commits ({' '.join(revs)})")
    violations: list[str] = []
    notes: list[str] = []
    for rev in out.split():
        v, n = check_commit(rev, cwd=cwd, env=env)
        violations += v
        notes += n
    return violations, notes


def report(violations: list[str], notes: list[str]) -> int:
    for n in notes:
        print(f"  note: {n}")
    if violations:
        for v in violations:
            print(f"✗ roadmap-drift: {v}", file=sys.stderr)
        print(_hint(), file=sys.stderr, end="")
        return 1
    print("roadmap-drift: OK")
    return 0


# ── selftest ────────────────────────────────────────────────────────────────

ROADMAP_FIXTURE = """# ROADMAP

| id | status | what |
|---|---|---|
| `B-1` | **PENDING-FOUNDER** (waiting) | alert delivery |
| `B-2` | **PENDING** | something else |
| `B-3` | **BUILT** | already done |
| `B-10/B-11` | **PENDING** | a grouped row |
"""


def _clean_env() -> dict[str, str]:
    """The B-558 lesson: a hook runs with an absolute GIT_DIR (and GIT_INDEX_FILE, GIT_WORK_TREE…)
    that BEATS `-C`, so a fixture built under it writes into the caller's repo. Drop them all."""
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def selftest() -> int:
    if os.environ.get("ROADMAP_DRIFT_SELFTEST_INNER") != "1":
        return _selftest_isolation()
    env = _clean_env()
    fails = 0
    me = Path(__file__).resolve()

    def sh(cwd: Path, *a: str) -> str:
        rc, out = _git(
            [
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.com",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *a,
            ],
            cwd=cwd,
            env=env,
        )
        if rc != 0:
            raise RuntimeError(f"git {' '.join(a)} failed in {cwd}")
        return out

    def run(cwd: Path, *args: str) -> tuple[int, str]:
        p = subprocess.run(
            [sys.executable, str(me), *args],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return p.returncode, p.stdout + p.stderr

    def expect(
        label: str, want: int, got: tuple[int, str], *, contains: str = ""
    ) -> None:
        nonlocal fails
        ok = got[0] == want and (not contains or contains in got[1])
        print(
            f"  {'✓' if ok else '✗'} {label} → exit {got[0]}"
            + (
                ""
                if ok
                else f" (wanted {want}{', containing ' + repr(contains) if contains else ''})"
            )
        )
        if not ok:
            print(got[1])
            fails += 1

    def commit(
        cwd: Path,
        message: str,
        *,
        row_edit: tuple[str, str] | None = None,
        note: str = "",
    ) -> str:
        """Commit a code change (and optionally a ROADMAP edit); returns the new sha."""
        n = len(list(cwd.glob("code-*.txt")))
        (cwd / f"code-{n}.txt").write_text(f"change {n} {note}\n")
        if row_edit:
            p = cwd / ROADMAP
            p.write_text(p.read_text().replace(*row_edit))
        sh(cwd, "add", "-A")
        sh(cwd, "commit", "-q", "-m", message)
        return sh(cwd, "rev-parse", "HEAD").strip()

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "r"
        (repo / "docs/runbook").mkdir(parents=True)
        sh(repo, "init", "-q")
        (repo / ROADMAP).write_text(ROADMAP_FIXTURE)
        sh(repo, "add", "-A")
        sh(repo, "commit", "-q", "-m", "seed")
        base = sh(repo, "rev-parse", "HEAD").strip()

        # 1. The claim without a row change → RED.
        c1 = commit(repo, "alerts: fixes B-1, retried delivery")
        expect("claim, row untouched", 1, run(repo, "--commit", c1), contains="B-1")
        # 2. The claim WITH the row change → GREEN.
        c2 = commit(
            repo,
            "alerts: fixes B-2",
            row_edit=("| `B-2` | **PENDING** |", "| `B-2` | **BUILT** (2026-10-02) |"),
        )
        expect("claim, row moved", 0, run(repo, "--commit", c2))
        # 3. The trailer → GREEN and PRINTED.
        c3 = commit(
            repo,
            "alerts: closes B-1\n\nRoadmap-Drift-Ok: B-1 the row is moved in the follow-up commit",
        )
        expect(
            "trailer, long reason", 0, run(repo, "--commit", c3), contains="OVERRIDE"
        )
        # 4. A trailer with a short reason does not count → RED.
        c4 = commit(repo, "alerts: closes B-1\n\nRoadmap-Drift-Ok: B-1 later")
        expect(
            "trailer, short reason",
            1,
            run(repo, "--commit", c4),
            contains="at least 20",
        )
        # 5. No claim → GREEN.
        c5 = commit(repo, "alerts: B-1 work in progress, retry loop")
        expect("no closing word", 0, run(repo, "--commit", c5))
        # 6. An id without a row is ignored → GREEN.
        c6 = commit(repo, "tls: fixes ZZ-99")
        expect("id with no row", 0, run(repo, "--commit", c6))
        # 7. A claim on an already-BUILT row → GREEN, noted.
        c7 = commit(repo, "tls: fixed B-3 follow-up")
        expect(
            "row already BUILT", 0, run(repo, "--commit", c7), contains="already BUILT"
        )
        # 8. A grouped row defines each id; word boundaries hold ("B-1" is not "B-10").
        c8 = commit(repo, "x: resolved B-10")
        expect("grouped row id, unmoved", 1, run(repo, "--commit", c8), contains="B-10")
        c9 = commit(repo, "x: prefixed B-1000 and unfixed B-1-ish")
        expect("no word-boundary false claim", 0, run(repo, "--commit", c9))
        # 9. Different sentences do not combine: "Fixes typo." then an id.
        c10 = commit(repo, "docs: fixes a typo. B-2 is next")
        expect("closing word in another sentence", 0, run(repo, "--commit", c10))
        # An adjective is not a claim (the replay over history hit exactly this once).
        c11 = commit(repo, "ui: the (B-1) cards use fixed policy windows by design")
        expect("'fixed' as an adjective", 0, run(repo, "--commit", c11))
        # A participle claims the whole list it belongs to; B-2 is moved here, B-1 is not.
        c12 = commit(
            repo,
            "x: B-1 and B-2 fixed",
            row_edit=(
                "| `B-2` | **BUILT** (2026-10-02) |",
                "| `B-2` | **BUILT** (2026-10-02, again) |",
            ),
        )
        expect(
            "participle claims a list", 1, run(repo, "--commit", c12), contains="B-1"
        )
        # "…and the security fixes" at the end of a long subject line is not a claim on its ids.
        c14 = commit(repo, "backend: B-1, B-2 and a cache, and the security fixes")
        expect("a trailing noun 'fixes'", 0, run(repo, "--commit", c14))
        c15 = commit(repo, "B-1 gate fixes: tidy the guard")
        expect(
            "'B-1 gate fixes:' describes, it does not claim",
            0,
            run(repo, "--commit", c15),
        )
        # A verb reaches an id a few words after it.
        c16 = commit(repo, "fixes the alert retry loop (B-1)")
        expect(
            "a verb reaches an id a few words on",
            1,
            run(repo, "--commit", c16),
            contains="B-1",
        )
        c17 = commit(repo, "B-1: fixes the alert retry loop")
        expect("'ID: fixes …'", 1, run(repo, "--commit", c17), contains="B-1")
        c13 = commit(repo, "x: B-1 is now fixed")
        expect(
            "participle after filler words",
            1,
            run(repo, "--commit", c13),
            contains="B-1",
        )
        expect(
            "participle, B-2 moved, only B-1 named",
            1,
            run(repo, "--commit", c12),
            contains="claims B-1 closed",
        )

        # 10. REPLAY: a message from elsewhere against THIS commit's diff (the 0a44e389 shape).
        silent = commit(repo, "alerts: retry failed delivery", note="silent fix")
        msgf = Path(td) / "claim.txt"
        msgf.write_text("alerts: retry failed delivery. Fixes B-1.\n")
        expect("replay: the real (silent) message", 0, run(repo, "--commit", silent))
        expect(
            "replay: same diff, a claiming message",
            1,
            run(repo, "--commit", silent, "--msg-file", str(msgf)),
            contains="B-1",
        )

        # 11. RANGE: red when it contains the violating commit, green when it does not.
        expect("range containing c1", 1, run(repo, "--range", f"{base}..HEAD"))
        expect("range after c1", 0, run(repo, "--range", f"{c1}..{c2}"))
        expect(
            "range of one commit", 0, run(repo, "--range", f"{c1}..{c3}"), contains=""
        )

        # 12. STAGED (the commit-msg hook): the message file against the index.
        sh(repo, "reset", "-q", "--hard", base)
        (repo / "code-s.txt").write_text("staged\n")
        sh(repo, "add", "-A")
        mf = Path(td) / "msg"
        mf.write_text(
            "fixes B-1\n# Please enter the commit message\n# fixes B-2 in a comment line\n"
        )
        expect(
            "staged claim, row untouched",
            1,
            run(repo, "--msg-file", str(mf), "--staged"),
            contains="B-1",
        )
        p = repo / ROADMAP
        p.write_text(
            p.read_text().replace(
                "**PENDING-FOUNDER** (waiting)", "**BUILT** (2026-10-02)"
            )
        )
        sh(repo, "add", "-A")
        expect(
            "staged claim, row staged", 0, run(repo, "--msg-file", str(mf), "--staged")
        )
        # A comment line is not a claim.
        mf.write_text("tidy\n# fixes B-2\n")
        expect(
            "comment lines are not claims",
            0,
            run(repo, "--msg-file", str(mf), "--staged"),
        )

        # 13. Fail-CLOSED: an unresolvable revision is an error, not a pass.
        expect("unresolvable --commit", 2, run(repo, "--commit", "no-such-rev"))
        expect("unresolvable --range", 2, run(repo, "--range", "no-such-rev"))
        # 14. A nonsense flag is rejected (the meta-gate relies on this).
        expect(
            "nonsense flag rejected",
            2,
            run(repo, "--tracelane-meta-gate-nonsense-flag"),
        )

    print(
        "check-roadmap-drift selftest "
        + ("PASSED." if fails == 0 else f"FAILED ({fails}).")
    )
    return 0 if fails == 0 else 1


def _selftest_isolation() -> int:
    """Re-run the selftest under a HOSTILE inherited GIT_DIR and prove it cannot reach it (B-558)."""
    with tempfile.TemporaryDirectory() as td:
        sentinel = Path(td) / "sentinel"
        sentinel.mkdir()
        clean = _clean_env()
        _git(["init", "-q"], cwd=sentinel, env=clean)
        _git(["config", "user.email", "sentinel@example.com"], cwd=sentinel, env=clean)
        _git(["config", "core.worktree", str(sentinel)], cwd=sentinel, env=clean)
        before = (sentinel / ".git" / "config").read_text()
        env = dict(os.environ)
        env["ROADMAP_DRIFT_SELFTEST_INNER"] = "1"
        env["GIT_DIR"] = str(sentinel / ".git")
        env["GIT_INDEX_FILE"] = str(sentinel / ".git" / "index")
        rc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--selftest"],
            env=env,
            check=False,
        ).returncode
        after = (sentinel / ".git" / "config").read_text()
        _, log = _git(["log", "--oneline"], cwd=sentinel, env=clean)
        if before != after or log.strip():
            print("  ✗ the fixture leaked into an inherited GIT_DIR (B-558 class)")
            return 1
        print("  ✓ an inherited GIT_DIR/GIT_INDEX_FILE did not reach the caller's repo")
        return rc


# ── main ────────────────────────────────────────────────────────────────────


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant each violation in a throwaway repo",
    )
    ap.add_argument(
        "--msg-file",
        help="commit message file (hook), or the message to REPLAY with --commit",
    )
    ap.add_argument(
        "--staged", action="store_true", help="check --msg-file against the staged diff"
    )
    ap.add_argument(
        "--commit",
        metavar="REV",
        help="check one commit (message from REV unless --msg-file)",
    )
    ap.add_argument(
        "--range",
        nargs=argparse.REMAINDER,
        metavar="REV",
        help="every commit in `git rev-list REV...` (the LAST option: it also takes `--not --remotes`)",
    )
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    try:
        if args.staged:
            if not args.msg_file:
                ap.error("--staged needs --msg-file")
            msg = Path(args.msg_file).read_text()
            v, n = check_staged(msg)
        elif args.commit:
            override = Path(args.msg_file).read_text() if args.msg_file else None
            v, n = check_commit(args.commit, msg_override=override)
        elif args.range is not None:
            if not args.range:
                ap.error("--range needs at least one revision")
            v, n = check_revs(args.range)
        else:
            v, n = check_revs(["HEAD", "--not", "--remotes"])
    except (RoadmapUnreadable, OSError) as e:
        print(f"✗ roadmap-drift: {e} — refusing (fail-closed)", file=sys.stderr)
        return 2
    return report(v, n)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
