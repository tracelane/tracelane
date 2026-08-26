#!/usr/bin/env python3
"""check-post-ledger-span-emit — no silent exit after the audit ledger has recorded.

WHY (B-245 §5.2, measured 2026-08-14). On the chat path the tamper-evident ledger row is
published BEFORE provider dispatch. Past that point the ledger asserts the request
happened, so **a return without a span is a request the ledger attests to and the product
cannot show**. Fleet-wide there were ~500 such rows — on every tenant with traffic, at
5-8% of requests, present from the first day of the current ledger — and no instrument
anywhere reported one. A customer reconciling their audit export against /traces finds a
gap we cannot explain.

Six exits existed. Three emitted a span and three did not, and the three that emitted were
THE SAME TEN LINES COPY-PASTED — which is how the other three came to be missed
(`TRAPS.md` §29: a finding recorded at one call site is not recorded). R13 collapsed all
six onto `emit_post_ledger_error_span(...)`; this guard is the half that stops a seventh
from landing silently.

WHAT IT CHECKS. Inside `chat_completions_handler`, from the `audit_chain.publish(` anchor
to the end of the function, every `return` must have a call to
`emit_post_ledger_error_span(` reachable before it — searched across the return's own
block and every ENCLOSING block, which is exactly the set of statements that could have
run on the way to it. Anything else must be named in ALLOWLIST with a written reason.

HONEST LIMITS, because a guard that oversells is worse than none:
  * It matches a CONSTRUCTION (`emit_post_ledger_error_span(`), never a word, and it
    strips comments and the `#[cfg(test)]` module first (`TRAPS.md` §19).
  * It is a REACHABILITY approximation, not a proof. Sibling blocks ARE excluded (the
    backwards walk tracks the shallowest depth seen, so anything inside an already-closed
    block is dropped) — but an emit sitting in an enclosing `if` still counts even though
    that `if` may not have been taken. It fails CLOSED on a new unguarded return, which is
    the direction that matters; it cannot prove the emit executes on every path.
  * It covers the CHAT path only. `/v1/embeddings` has its own ledger publish and is not
    in scope here.

EXIT: 0 clean · 1 a post-ledger return with no reachable emit · 2 the anchors moved
(fail-closed: if this cannot find the handler or the publish, it refuses rather than
passing).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TARGET = Path("crates/gateway/src/server.rs")
HANDLER = "async fn chat_completions_handler"
# Split so this file cannot match its own needle when someone greps the tree.
ANCHOR = "audit_chain" + ".publish("
EMIT = "emit_post_ledger_error_span" + "("

# A return that legitimately carries no error span. Each entry is (marker, reason) where
# `marker` is a literal appearing in the return's OWN statement — never a fixed line
# window, which leaked the success marker onto a neighbouring return. An entry without a
# reason is not accepted: the reason is the part a human reads.
ALLOWLIST: list[tuple[str, str]] = [
    (
        "dispatch_result",
        (
            "the SUCCESS return — the normal gateway span is built and published on "
            "the dispatch path itself, not as an error span"
        ),
    ),
    (
        "x-tracelane-cache",
        (
            "GWY-24 semantic-cache HIT. Also a success return, and it carries a FULL "
            "gateway span published immediately above it via spawn_span_publish — "
            "including the tier, the similarity and a pointer to the trace whose "
            "answer was reused. An error span would be wrong here: nothing failed. "
            "This is the one return where the span matters most, because a served "
            "cache hit with no span is precisely the 'trace gap' that killed the "
            "exact-match cache in specs/GWY-25 — so the allowlist entry is not a "
            "waiver, it is a statement that the span is emitted by a different call."
        ),
    ),
]


def strip_comments(src: str) -> str:
    """Remove comments WITHOUT deleting the code that shares their line.

    `TRAPS.md` §19: a strip pass that drops whole lines carrying `*/` swallows the code
    beside it. Block comments are replaced by an equal number of newlines so every line
    number downstream still refers to the real file.
    """

    def _blank(m: re.Match[str]) -> str:
        return "\n" * m.group(0).count("\n")

    src = re.sub(r"/\*.*?\*/", _blank, src, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", src)


def handler_body(lines: list[str]) -> tuple[int, int]:
    """(start, end) line indices of the handler body, brace-matched. Fails closed."""
    start = next((i for i, ln in enumerate(lines) if HANDLER in ln), None)
    if start is None:
        sys.exit(
            f"CANNOT DETERMINE — `{HANDLER}` not found in {TARGET}. Anchors moved."
        )
    depth, seen = 0, False
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if lines[i].count("{"):
            seen = True
        if seen and depth <= 0:
            return start, i
    sys.exit(f"CANNOT DETERMINE — could not brace-match {HANDLER}. Anchors moved.")


def depths(lines: list[str], start: int, end: int) -> list[int]:
    """Brace depth at the START of each line, relative to the handler."""
    out, d = [], 0
    for i in range(start, end + 1):
        out.append(d)
        d += lines[i].count("{") - lines[i].count("}")
    return out


def check(src: str) -> list[str]:
    body_src = src.split("\n#[cfg(test)]")[0]
    lines = strip_comments(body_src).split("\n")
    start, end = handler_body(lines)

    anchor = next(
        (i for i in range(start, end + 1) if ANCHOR in lines[i]),
        None,
    )
    if anchor is None:
        sys.exit(
            f"CANNOT DETERMINE — `{ANCHOR}` not found inside {HANDLER}. The ledger "
            "publish moved; this guard cannot locate the region it protects."
        )

    d = depths(lines, start, end)

    # THE REGION STARTS WHERE THE ROW EXISTS, NOT WHERE THE PUBLISH IS ATTEMPTED.
    # `if let Err(..) = publish(..) { return 503 }` is the FAIL-CLOSED branch: the publish
    # failed, so there is no ledger row, so there is nothing for a span to reconcile
    # against and that return is correctly silent. Starting at the publish line flags it,
    # which is a false positive — and a guard that cries wolf gets waved away
    # (`TRAPS.md` §1 CLASS-3). Advance past the error branch: the row exists only once
    # brace depth returns to the publish statement's own level.
    anchor_depth = d[anchor - start]
    region_start = anchor
    for j in range(anchor + 1, end + 1):
        if d[j - start] <= anchor_depth:
            region_start = j
            break
    anchor = region_start
    violations: list[str] = []

    for i in range(anchor + 1, end + 1):
        if not re.search(r"\breturn\b", lines[i]):
            continue
        my_depth = d[i - start]

        # Statements that could actually have executed on the way to this return: walk
        # BACKWARDS, tracking the shallowest depth seen so far. A line is on the path
        # only while it is at or above that running minimum — the moment we pass a
        # closing brace the depth rises, and everything inside that already-closed
        # SIBLING block is excluded.
        #
        # This is the correction the selftest forced. The first version used a flat
        # `d[j] <= my_depth`, which counted an emit in a sibling `if` as reachable — so
        # once ANY emit existed at a given depth, every later return at that depth passed
        # and the guard silently stopped discriminating. It went green on the real file
        # for that reason, which is precisely the shape of a control that cannot fail
        # (`TRAPS.md` §22 / §25).
        reachable: list[str] = []
        min_depth = my_depth
        for j in range(i - 1, anchor - 1, -1):
            dj = d[j - start]
            min_depth = min(min_depth, dj)
            if dj <= min_depth:
                reachable.append(lines[j])
        if any(EMIT in ln for ln in reachable):
            continue

        # The allowlist must match THIS return's own statement, not a fixed window.
        # A 6-line window was the first version and it was wrong in the dangerous
        # direction: the SUCCESS return's marker three lines below leaked onto an
        # unguarded return above it, silently exempting it. A carve-out that reaches
        # past its own statement is indistinguishable from not checking (`TRAPS.md` §31).
        # Read to the end of the return statement — the first `;` at or above its depth.
        stmt = [lines[i]]
        if ";" not in lines[i]:
            for j in range(i + 1, min(i + 12, end + 1)):
                stmt.append(lines[j])
                if ";" in lines[j] and d[j - start] <= my_depth:
                    break
        window = "\n".join(stmt)
        if any(m in window for m, _ in ALLOWLIST):
            continue

        snippet = lines[i].strip()[:90]
        violations.append(
            f"{TARGET}:{i + 1}: post-ledger `return` with no reachable "
            f"emit_post_ledger_error_span(...)\n"
            f"      {snippet}\n"
            f"      The audit ledger already recorded this request. Returning here "
            f"leaves a ledger row the product cannot show (B-245 §5.2).\n"
            f"      Fix: call emit_post_ledger_error_span(&state, tenant_id, trace_id, "
            f'&model, request_start, "<reason>", None) before the return —\n'
            f"      or add it to ALLOWLIST in this file WITH A REASON if it genuinely "
            f"carries a span another way."
        )
    return violations


SELFTEST_CLEAN = """
async fn chat_completions_handler() -> Response {
    if let Err(e) = state.audit_chain.publish(ev).await {
        return bad();
    }
    if thing {
        emit_post_ledger_error_span(&state, t, id, &m, s, "x", None);
        return oops();
    }
    return dispatch_result;
}
"""

# The exact B-245 shape: a new exit added after the ledger publish, no span.
SELFTEST_DIRTY = """
async fn chat_completions_handler() -> Response {
    if let Err(e) = state.audit_chain.publish(ev).await {
        return bad();
    }
    if thing {
        emit_post_ledger_error_span(&state, t, id, &m, s, "x", None);
        return oops();
    }
    if breaker_open {
        return five_oh_three();
    }
    return dispatch_result;
}
"""

# TRAPS §19: a control that matches a WORD is not a control. If the emit only appears in
# a COMMENT, the guard must still go red.
SELFTEST_COMMENT_ONLY = """
async fn chat_completions_handler() -> Response {
    if let Err(e) = state.audit_chain.publish(ev).await {
        return bad();
    }
    if breaker_open {
        // we should call emit_post_ledger_error_span( here one day
        return five_oh_three();
    }
    return dispatch_result;
}
"""


def selftest() -> int:
    fails = 0

    def expect(label: str, src: str, want_violations: bool) -> None:
        nonlocal fails
        got = check(src)
        if bool(got) == want_violations:
            print(f"  ✓ {label}")
        else:
            print(
                f"  ✗ {label} — expected {'RED' if want_violations else 'GREEN'}, "
                f"got {len(got)} violation(s)"
            )
            fails += 1

    # BOTH HALVES, or the carve-out is indistinguishable from not scanning at all
    # (`TRAPS.md` §31). A guard that only proves the allow-case proves nothing.
    expect("a guarded post-ledger return passes", SELFTEST_CLEAN, False)
    expect("a NEW unguarded post-ledger return BLOCKS", SELFTEST_DIRTY, True)
    expect(
        "an emit that exists only in a COMMENT still BLOCKS",
        SELFTEST_COMMENT_ONLY,
        True,
    )

    if fails == 0:
        print(
            "post-ledger-span-emit selftest PASSED — it was observed BLOCKING, "
            "not merely passing."
        )
        return 0
    print(f"post-ledger-span-emit selftest FAILED — {fails} case(s).")
    return 1


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    if sys.argv[1:]:
        print(f"usage: {sys.argv[0]} [--selftest]  (unknown argument: {sys.argv[1]})")
        return 2
    if not TARGET.exists():
        print(f"CANNOT DETERMINE — {TARGET} not found (run from the repo root).")
        return 2

    violations = check(TARGET.read_text(encoding="utf-8"))
    if not violations:
        print(
            "✓ post-ledger span emit: every return after the audit publish emits a span"
        )
        return 0
    print(
        "✗ POST-LEDGER SILENT EXIT — a request the ledger attests to would be "
        "invisible in the product:\n"
    )
    for v in violations:
        print(f"  {v}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
