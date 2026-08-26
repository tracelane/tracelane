#!/usr/bin/env bash
# pre-public-push.sh — PUBLIC variant (ships in tracelane/tracelane).
#
# Sanitized per ADR-021/023 + the L11 export policy: this guard ships only the
# marketing-honesty + leakage backstop LOGIC. The private-file deny-list and the
# strategy-revealing comments live in the PRIVATE guard only — they are
# meaningless here (those files do not exist in the public repo).
#
# Scans the working tree (correct for a public pre-push hook), not a diff.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
FAIL=0

# ── selftest ────────────────────────────────────────────────────────────────────
# A guard nobody has watched fail is assumed decorative. This plants a struck claim
# in a real public-capable tree and asserts the gate BLOCKS, then asserts an empty
# list also blocks — because a gate with nothing to check reporting green over an
# unguarded surface is the exact failure the never-say-again list exists to close.
# ARGV IS AN ALLOWLIST, and the reason is that its absence made this guard's meta-gate
# result an ACCIDENT. The meta-gate probes every guard with a nonsense flag and requires
# a non-zero exit, to prove the script parses argv at all. This script had no allowlist:
# anything that was not exactly `--selftest` fell through to a full scan, and that scan
# happens to exit 1 because the PRIVATE tree carries 213 pre-existing leakage hits (a
# condition the comment above documents as expected here).
#
# So the meta-gate has been reading "the guard rejected a nonsense flag" from a number
# produced by something else entirely. Clean up those 213 hits and this guard would exit
# 0 for the bogus flag and the meta-gate would flip RED with no code change — a
# discriminating-field failure of exactly the shape `docs/reference/TRAPS.md` §38 names.
case "${1:-}" in
    ""|--selftest) ;;
    *) echo "usage: $(basename "$0") [--selftest]  (unknown argument: $1)" >&2; exit 2 ;;
esac

if [ "${1:-}" = "--selftest" ]; then
    st_fail=0
    tmpd="$(mktemp -d)"; trap 'rm -rf "$tmpd"' EXIT

    # NOTE ON SCOPE: this gate is designed to run over the EXPORTED tree, so against the
    # private root it also reports pre-existing leakage hits (PROGRESS.md, FOUNDER_ACTIONS
    # references in infra/) that are expected here and absent from an export. So the
    # selftest asserts on THIS check's own label rather than the whole script's exit code —
    # otherwise it would be testing unrelated scope, and would never be satisfiable.
    run_gate() { bash "$0" 2>&1 || true; }

    # 1. A banned phrase in a public-capable file must be REPORTED by its label.
    planted="$ROOT/docs/guides/_nsa_selftest_planted.md"
    printf '<!-- tracelane:classification: PUBLIC -->\n# probe\n\nOur ledger is tamper-proof.\n' > "$planted"
    if run_gate | grep -q 'BLOCKED \[tamper-proof\]'; then
        echo "  ✓ a planted banned phrase is caught and named"
    else
        echo "  ✗ a planted banned phrase was NOT caught"; st_fail=$((st_fail+1))
    fi
    rm -f "$planted"

    # 2. Removed, that label must NOT appear — a guard that always fires is not a guard.
    if run_gate | grep -q 'BLOCKED \[tamper-proof\]'; then
        echo "  ✗ the phrase still reported after removal (always-fires)"; st_fail=$((st_fail+1))
    else
        echo "  ✓ with the phrase removed, that check is quiet"
    fi

    # 3. An EMPTY list must FAIL CLOSED — a gate with nothing to check must not go quiet.
    cp "$ROOT/docs/reference/NEVER_SAY_AGAIN.md" "$tmpd/nsa.bak"
    awk '/NEVER-SAY-AGAIN:BEGIN/{print; skip=1; next} /NEVER-SAY-AGAIN:END/{skip=0} !skip' \
        "$tmpd/nsa.bak" > "$ROOT/docs/reference/NEVER_SAY_AGAIN.md"
    if run_gate | grep -q 'parsed to ZERO rules'; then
        echo "  ✓ an EMPTY list fails CLOSED"
    else
        echo "  ✗ an EMPTY list did not fail closed"; st_fail=$((st_fail+1))
    fi
    cp "$tmpd/nsa.bak" "$ROOT/docs/reference/NEVER_SAY_AGAIN.md"

    # 4. A MISSING list must fail closed too.
    #
    # DELETE-AND-RESTORE, NEVER MOVE-AND-MOVE-BACK. This used to `mv` the file into
    # `$tmpd` and `mv` it back — putting the ONLY copy of a tracked CONFIDENTIAL file
    # inside a directory whose EXIT trap is `rm -rf`, across a full-tree scan that takes
    # seconds. A Ctrl-C, a kill, or an OOM anywhere in that window destroyed it
    # permanently, and this selftest runs on EVERY pre-push.
    #
    # `nsa.bak` above is a `cp`, so a copy already exists and outlives the removal. The
    # correct order for any temporary mutation of a tracked file is: copy first, mutate
    # second, restore from the copy — which case 3 immediately above already did. Found
    # 2026-08-16 while scoping the gate; the two cases were written days apart and only
    # one of them got it right.
    rm -f "$ROOT/docs/reference/NEVER_SAY_AGAIN.md"
    if run_gate | grep -q 'the list is MISSING'; then
        echo "  ✓ a MISSING list fails CLOSED"
    else
        echo "  ✗ a MISSING list did not fail closed"; st_fail=$((st_fail+1))
    fi
    cp "$tmpd/nsa.bak" "$ROOT/docs/reference/NEVER_SAY_AGAIN.md"

    [ "$st_fail" -eq 0 ] && { echo "never-say-again selftest PASSED."; exit 0; }
    echo "never-say-again selftest FAILED — $st_fail case(s)."; exit 1
fi

# ── Drop hits in files export-deny.txt pulls back ────────────────────────────
#
# This guard answers ONE question: can a banned phrase reach the PUBLIC surface?
# A file the deny list removes cannot, so a hit in it is true about the text and
# false about the risk.
#
# It is not hypothetical noise. On a clean tree, four of the six phrase rules fire
# ONLY on `.claude/agents/{marketing-writer,competitor-tracker,frontend-builder}.md`
# — all three DENIED — and every hit is the rule that FORBIDS the phrase quoting it
# (`- **Never** "inline SLM judge"`). Left in, the natural fix is one exemption per
# phrase, and a guard accumulating exemptions stops meaning anything.
#
# FILTERING HITS, NOT INPUTS. A first attempt filtered the DOCS array and was inert:
# DOCS holds DIRECTORY paths for whole trees, so comparing them to the deny list's
# file entries matched nothing. It ran, changed no behaviour, and read like a working
# control. Hits carry a real file path, so filtering here cannot silently do nothing.
deny_filter() {  # stdin: "path:line:text" -> stdout: same, minus denied paths
  local deny="$ROOT/scripts/export/export-deny.txt"
  if [ ! -f "$deny" ]; then cat; return; fi
  awk -v deny="$deny" -v root="$ROOT/" '
    BEGIN {
      while ((getline l < deny) > 0) {
        sub(/[ \t]+$/, "", l)
        if (l == "" || l ~ /^#/) continue
        d[++n] = l
      }
    }
    {
      path = $0; sub(/:.*$/, "", path); rel = path; sub("^" root, "", rel)
      for (i = 1; i <= n; i++) {
        # exact file, or a directory prefix entry
        if (rel == d[i] || index(rel, d[i] "/") == 1) next
      }
      print
    }'
}

scan() { # <label> <regex> <path...>
  local label="$1"; shift
  local re="$1"; shift
  local hits
  hits=$(grep -rIniE \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next \
    --exclude-dir=target --exclude-dir=dist \
    --exclude=CHANGELOG.md --exclude=pre-public-push.sh \
    "$re" "$@" 2>/dev/null | deny_filter || true)
  if [ -n "$hits" ]; then
    # `echo "$hits" | head -8` SIGPIPEd whenever there were MORE than 8 hits:
    # head closed the pipe, echo took SIGPIPE, `pipefail` propagated 141, and
    # `set -e` killed the whole script. The guard therefore stopped running
    # EXACTLY when it had found the most, reporting on the checks it had reached
    # and staying silent about the rest — indistinguishable from passing them.
    # `sed -n` reads its input to the end, so it cannot close the pipe early.
    local n; n="$(printf '%s\n' "$hits" | grep -c . || true)"
    echo "BLOCKED [$label]: $n hit(s)"
    printf '%s\n' "$hits" | sed -n '1,8p'
    if [ "$n" -gt 8 ]; then echo "  … $((n - 8)) more not shown"; fi
    FAIL=1
  fi
}

# Marketing scans read PROSE a customer sees, so they are markdown-only. Scanning
# .rs/.ts as well false-positives on internal code comments (an ADR-009 comment in
# main.rs is not marketing copy) and a noisy guard gets ignored, which is worse
# than a narrow one.
scan_docs() { # <label> <regex> <path...>
  local label="$1"; shift
  local re="$1"; shift
  local hits
  hits=$(grep -rIniE --include='*.md' --include='*.mdx' --include='*.mdc' \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next \
    --exclude-dir=target --exclude-dir=dist --exclude-dir=archive \
    --exclude=CHANGELOG.md --exclude=CHANGELOG.public.md --exclude=changelog.mdx \
    --exclude=pre-public-push.sh \
    `# evals/*/INDEX.md are denied by export-deny.txt, so they do not exist in the` \
    `# public tree. Excluded so a private-tree run is not noisy with hits that` \
    `# cannot ship. A guard people learn to ignore stops being a guard.` \
    --exclude=INDEX.md \
    "$re" "$@" 2>/dev/null | deny_filter || true)
  if [ -n "$hits" ]; then
    # `echo "$hits" | head -8` SIGPIPEd whenever there were MORE than 8 hits:
    # head closed the pipe, echo took SIGPIPE, `pipefail` propagated 141, and
    # `set -e` killed the whole script. The guard therefore stopped running
    # EXACTLY when it had found the most, reporting on the checks it had reached
    # and staying silent about the rest — indistinguishable from passing them.
    # `sed -n` reads its input to the end, so it cannot close the pipe early.
    local n; n="$(printf '%s\n' "$hits" | grep -c . || true)"
    echo "BLOCKED [$label]: $n hit(s)"
    printf '%s\n' "$hits" | sed -n '1,8p'
    if [ "$n" -gt 8 ]; then echo "  … $((n - 8)) more not shown"; fi
    FAIL=1
  fi
}

# 1. Marketing honesty (ADR-021 / ADR-023 / B-035) over the customer-facing surfaces.
#
# SCOPE = every tree that ships publicly, not just the two app dirs. Scoping this
# to apps/web + apps/docs was B-182: README-class files were never
# marketing-scanned, so a claim could sit in docs/guides/ or a package README
# indefinitely. The 2026-08-07 ledger pass found the gap still open across ~30
# more exported files. Anything added to build-public-export.sh's ALLOW array
# belongs here too — a public-capable file outside this list is unguarded.
# R136 (B-279 L2a): THE SCAN SCOPE IS DERIVED FROM THE EXPORT ALLOWLIST, not
# maintained beside it.
#
# This block used to be a hand-kept list of trees that had to be updated whenever
# build-public-export.sh's ALLOW array changed. The comment above said exactly that —
# "Anything added to build-public-export.sh's ALLOW array belongs here too" — which is
# a rule a human has to remember, and it failed: `.claude/agents` was in ALLOW while
# this list never named it, so NINE agent definitions shipped UNSCANNED and one carried
# `5K RPS`, a phrase on the enforced never-say-again list. B-182 was the same defect one
# tree earlier. The rule was never wrong; keeping the list by hand was.
#
# TWO TREES, one list, fail-CLOSED — the same shape as the never-say-again list below.
# In the private repo the source is scripts/export/export-allow.txt. That directory is
# DENIED from the export, so build-public-export.sh materializes a copy at
# scripts/export-allow.txt and this resolves whichever exists. If NEITHER exists this
# BLOCKS: a scan with no scope would pass everything and report success, which is the
# precise failure this file exists to prevent.
ALLOW_LIST="$ROOT/scripts/export/export-allow.txt"
[ -f "$ALLOW_LIST" ] || ALLOW_LIST="$ROOT/scripts/export-allow.txt"
DOCS=()
if [ ! -f "$ALLOW_LIST" ]; then
  echo "BLOCKED [scan-scope]: the export allowlist is MISSING."
  echo "  Looked for scripts/export/export-allow.txt (private repo) and"
  echo "  scripts/export-allow.txt (export tree). Neither exists."
  echo "  A marketing scan with no scope inspects nothing and reports success."
  FAIL=1
else
  # NOT PROSE, and excluded with the reason at the site. These ship, but they carry no
  # customer-readable claims — a lockfile or a git attributes file cannot make a
  # marketing statement, and scanning them only adds runtime and false-positive
  # surface. Everything else in the allowlist IS scanned, including every root
  # markdown file, which is what B-182 was about.
  _not_prose() {
    case "$1" in
      Cargo.lock|pnpm-lock.yaml|package.json|pnpm-workspace.yaml|rust-toolchain.toml) return 0 ;;
      .gitattributes|.gitleaks.toml|deny.toml|osv-scanner.toml|.grype.yaml|.cargo/audit.toml) return 0 ;;
      .env.example|LICENSE|NOTICE|CODEOWNERS|Dockerfile) return 0 ;;
      *) return 1 ;;
    esac
  }
  _al_seen=0
  while IFS= read -r _p; do
    case "$_p" in ''|\#*) continue ;; esac
    _al_seen=$((_al_seen+1))
    _not_prose "$_p" && continue
    if [ -d "$ROOT/$_p" ] || [ -f "$ROOT/$_p" ]; then DOCS+=("$ROOT/$_p"); fi
  done < "$ALLOW_LIST"
  if [ "$_al_seen" -lt 1 ]; then
    echo "BLOCKED [scan-scope]: the export allowlist parsed to ZERO entries ($ALLOW_LIST)."
    FAIL=1
  fi
  # CLAUDE.public.md ships AS CLAUDE.md and is therefore not an allowlist entry, but it
  # is public-capable prose and must be scanned in the private tree.
  [ -f "$ROOT/CLAUDE.public.md" ] && DOCS+=("$ROOT/CLAUDE.public.md")
  echo "scan scope: ${#DOCS[@]} path(s) derived from $(basename "$ALLOW_LIST") ($_al_seen entries)"
fi

# NOTE (2026-08-13): this scan is NOT deny-aware, and that is a real gap —
# see PROGRESS.md B-217. A first attempt at filtering here was REMOVED rather than
# left in place: DOCS holds DIRECTORY paths for whole trees, so comparing them
# against export-deny.txt's file entries matched nothing. It ran, changed no
# behaviour, and read like a working control. Inert machinery that looks live is
# worse than a named gap.

if [ ${#DOCS[@]} -gt 0 ]; then
  # THE NEVER-SAY-AGAIN LIST IS DATA, NOT CODE (2026-08-10).
  #
  # These phrases used to be nine hardcoded literals here, which is exactly why 60
  # struck claims produced 9 checks: adding a strike meant editing a shell script, so
  # nobody did. The list now lives in docs/reference/NEVER_SAY_AGAIN.md — the artifact
  # DECISION_SHEET.md mandates in four places and which, until today, did not exist.
  # Adding a strike is a one-line edit to that file.
  #
  # TWO LOCATIONS, because this guard runs in TWO trees (fixed 2026-08-11).
  #
  # In the private repo the list is the CONFIDENTIAL artifact at
  # docs/reference/NEVER_SAY_AGAIN.md. But `docs/reference` is DENIED from the export
  # (export-deny.txt:26), while this guard is COPIED INTO the export and run there
  # (build-public-export.sh:293,307) — so in the export tree that path does not exist
  # and the gate blocked unconditionally. Every export failed at step 8 from the moment
  # the list shipped: the gate was right (fail-closed on a missing list) about a tree
  # that could never satisfy it.
  #
  # The export therefore materializes a PHRASES-ONLY copy at scripts/never-say-again.txt
  # — `label | regex`, with the `why` column dropped, because the why is the internal
  # reasoning for a strike and has no business on the public surface. The regexes must
  # ship: the public repo runs this same guard.
  #
  # Fail-closed is UNCHANGED. If NEITHER location exists, this blocks.
  NSA_LIST="$ROOT/docs/reference/NEVER_SAY_AGAIN.md"
  [ -f "$NSA_LIST" ] || NSA_LIST="$ROOT/scripts/never-say-again.txt"
  if [ ! -f "$NSA_LIST" ]; then
    echo "BLOCKED [never-say-again]: the list is MISSING."
    echo "  Looked for docs/reference/NEVER_SAY_AGAIN.md (private repo) and"
    echo "  scripts/never-say-again.txt (export tree). Neither exists."
    echo "  The gate cannot pass by having nothing to check — that is the failure mode"
    echo "  this list exists to close. Restore it or fix the path."
    FAIL=1
  else
    # Extract `label | regex | why`. Between the markers when they exist (the private
    # .md); otherwise every rule line (the generated export .txt, which has no markers).
    if grep -q 'NEVER-SAY-AGAIN:BEGIN' "$NSA_LIST"; then
      NSA_BLOCK="$(awk '/NEVER-SAY-AGAIN:BEGIN/{f=1;next} /NEVER-SAY-AGAIN:END/{f=0} f' "$NSA_LIST")"
    else
      NSA_BLOCK="$(grep -v '^#' "$NSA_LIST")"
    fi
    # LABELS ARE MIXED-CASE. This pattern was `^[a-z0-9-]+ \|`, which silently dropped
    # every label containing a capital — `inline-SLM-judge` and `old-B1-wedge` — so the
    # list held 11 rules and the gate enforced 9, reporting the 9 as if that were all of
    # them. A partial gate that reports a confident count is the §18 shape, and this file
    # is the one that warns about it. Found 2026-08-11 while making the export resolve.
    NSA_RULES="$(printf '%s\n' "$NSA_BLOCK" | grep -E '^[A-Za-z0-9_-]+ *\|' || true)"
    NSA_COUNT="$(printf '%s' "$NSA_RULES" | grep -c . || true)"
    # NO SILENT DROPS. Every non-blank, non-comment line in the block must parse as a
    # rule. A typo'd label is now a BLOCK, not an invisible subtraction from coverage.
    NSA_LINES="$(printf '%s\n' "$NSA_BLOCK" | grep -cE '^[^[:space:]#]' || true)"
    if [ "${NSA_LINES:-0}" -ne "${NSA_COUNT:-0}" ]; then
      echo "BLOCKED [never-say-again]: $NSA_LINES rule line(s) present, only $NSA_COUNT parsed."
      echo "  Every line in the list must match '<label> | <regex>'. A line that does not"
      echo "  parse is coverage you believe you have and do not."
      printf '%s\n' "$NSA_BLOCK" | grep -E '^[^[:space:]#]' | grep -vE '^[A-Za-z0-9_-]+ *\|' \
        | sed 's/^/    unparsed: /'
      FAIL=1
    fi
    # An EMPTY list must fail, not pass silently. A gate with nothing to check reports
    # green over an unguarded surface — the §18 shape.
    if [ "${NSA_COUNT:-0}" -lt 1 ]; then
      echo "BLOCKED [never-say-again]: the list parsed to ZERO rules."
      echo "  A gate that checks nothing is not a gate. Check the BEGIN/END markers."
      FAIL=1
    else
      echo "never-say-again: $NSA_COUNT banned phrase(s) loaded from the list"
      # PARSE ON " | " (SPACE PIPE SPACE), NOT ON "|". Earned 2026-08-13.
      #
      # This loop used `IFS='|' read -r label regex why`, which splits on EVERY
      # pipe — including the `\|` alternation INSIDE the regex column. Six of the
      # eleven rules were therefore truncated at their first alternative, and the
      # remainder of each pattern was silently swallowed into the `why` field:
      #
      #   unverified-perf        ->  `sub-50ms\`   (not `…\|5K RPS\|<10ms p99`)
      #   block-prevent-failures ->  `block failures\`
      #   100-percent            ->  `100% reliable\`
      #   eidas-qtsp             ->  `eIDAS\`
      #
      # Each also ended in a dangling backslash, so grep's own complaint about an
      # invalid pattern was swallowed by the `2>/dev/null || true` in scan_docs.
      # **This is why `5K RPS` sat on the public surface**: the phrase never
      # reached grep at all. The scan-set gap fixed earlier was real but secondary.
      #
      # Column separators in the list are padded (` | `); alternation is not
      # (`\|`). That difference is what makes the split unambiguous.
      while IFS= read -r nsa_line; do
        [ -n "$nsa_line" ] || continue
        nsa_label="${nsa_line%%" | "*}"
        nsa_rest="${nsa_line#*" | "}"
        nsa_regex="${nsa_rest%%" | "*}"
        nsa_label="$(printf '%s' "$nsa_label" | tr -d '[:space:]')"
        nsa_regex="$(printf '%s' "$nsa_regex" | sed 's/^ *//; s/ *$//')"
        [ -n "$nsa_label" ] && [ -n "$nsa_regex" ] || continue

        # The list writes alternation BRE-style (`\|`) but uses ERE quantifiers
        # elsewhere (`under 10 ?ms`, and `\+` meaning a LITERAL plus in the
        # old-B1-wedge rule). grep -E is therefore correct and `\|` is the odd
        # one out: under -E it means a literal pipe character. Translate it.
        nsa_regex="$(printf '%s' "$nsa_regex" | sed 's/\\|/|/g')"

        # WHITESPACE TOLERANCE. The architecture SVG carried `≥5 K RPS` and the
        # pattern was `5K RPS` — one space defeated the whole rule. Allow optional
        # whitespace wherever a digit is followed directly by a letter, which is
        # exactly the shape these units take (`5K`, `10ms`, `50ms`).
        nsa_regex="$(printf '%s' "$nsa_regex" | sed -E 's/([0-9])([A-Za-z])/\1[[:space:]]*\2/g')"

        # A pattern grep will not accept must be LOUD, not silently skipped —
        # that silence is what hid the truncation above for as long as it lived.
        # Capture grep's OWN exit code. `if ! cmd; then case $?` does NOT work:
        # after `!` the status is the NEGATION's result, so a healthy rule
        # (exit 1 = no match on empty input) reads as 0 and every rule reports
        # invalid. Caught by this guard's own first run — it declared all eleven
        # patterns broken while they were, in fact, finally correct.
        # grep: 0 = matched, 1 = no match, >=2 = the pattern itself is bad.
        nsa_rc=0
        printf '' | grep -qE "$nsa_regex" 2>/dev/null || nsa_rc=$?
        if [ "$nsa_rc" -ge 2 ]; then
          echo "BLOCKED [never-say-again]: rule '$nsa_label' is not a valid regex: $nsa_regex"
          FAIL=1; continue
        fi
        scan_docs "$nsa_label" "$nsa_regex" "${DOCS[@]}"
      done <<< "$NSA_RULES"
    fi
  fi
fi

# 2. Leakage backstop — strategy / internal-doc / economics phrases that must never
#    appear anywhere in a public tree.
scan "internal-trackers" 'BLOCKERS\.md|FOUNDER_ACTIONS|TRACELANE_(BRD|TRD)|Sanjeevlabs/tracelane-private' "$ROOT"
scan "strategy/economics" 'acquirer |moat |reservation price|gross margin|AI-tourist' "$ROOT"
# Private-doc references (private spec/tracker names + internal trackers) must not ship. README.md is public, excluded.
scan "private-doc-refs" 'GUARDRAILS_V1_SPEC|Design_System_Spec|SAMPLING_MECHANISM_DESIGN|Database_Schema|INFRA_CHANGES|PROGRESS\.md|SECURITY_FINDINGS|V1_LAUNCH_STATUS|TRACELANE_FEATURE_CHECKLIST|BUILD_SPEC|BUILD_CHEATSHEET|Test_Plan|docs/(product/specs|internal|trackers|archive)/[A-Za-z_]+\.(md|ya?ml)' "$ROOT"

# NOTE: secret scanning is handled by gitleaks + trufflehog in CI (with an allowlist
# for the synthetic redaction/PII test vectors, e.g. AWS's own AKIAIOSFODNN7EXAMPLE and
# clearly-fake sk_live_abcd… fixtures). A naive secret-shape grep over the tree would
# false-positive on exactly those test vectors, so it is intentionally NOT duplicated here.

if [ "$FAIL" -eq 1 ]; then
  echo ""
  echo "pre-public-push.sh: BLOCKED. Resolve the above before pushing."
  exit 1
fi
echo "All public-push checks passed."
exit 0
