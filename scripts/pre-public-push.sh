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

scan() { # <label> <regex> <path...>
  local label="$1"; shift
  local re="$1"; shift
  local hits
  hits=$(grep -rIniE \
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next \
    --exclude-dir=target --exclude-dir=dist \
    --exclude=CHANGELOG.md --exclude=pre-public-push.sh \
    "$re" "$@" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "BLOCKED [$label]:"
    echo "$hits" | head -8
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
    "$re" "$@" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "BLOCKED [$label]:"
    echo "$hits" | head -8
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
DOCS=()
for d in apps/web apps/docs docs/guides packages crates spec evals ml bench infra .github; do
  [ -d "$ROOT/$d" ] && DOCS+=("$ROOT/$d")
done
for f in README.md SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md VERSIONING.md \
         AI_DISCLOSURE.md LICENSE-PLEDGE.md CLAUDE.public.md; do
  [ -f "$ROOT/$f" ] && DOCS+=("$ROOT/$f")
done
if [ ${#DOCS[@]} -gt 0 ]; then
  scan_docs "all-12-predictive"        'all 12 predictive'                                   "${DOCS[@]}"
  scan_docs "inline-SLM-judge"         'inline SLM judge'                                     "${DOCS[@]}"
  scan_docs "unlimited-seats-every"    'unlimited seats every'                               "${DOCS[@]}"
  scan_docs "block/stop/prevent-fail"  'block failures|blocks failures|stop failures|prevent failures' "${DOCS[@]}"
  scan_docs "before-they-execute"      'before they execute|before they happen'             "${DOCS[@]}"
  scan_docs "unverified-perf"          'sub-50ms|sub-millisecond|sub-10ms|under 10 ?ms|5K RPS|5,000 RPS|<10ms p99' "${DOCS[@]}"
  scan_docs "tamper-proof"             'tamper-proof'                                         "${DOCS[@]}"
  scan_docs "100-percent"              '100% reliable|100% accurate|100% safe|100% prevention' "${DOCS[@]}"
  scan_docs "old-B1-wedge"             'Prompt Promotion \+ Eval Gates \+ Auto-Rollback'     "${DOCS[@]}"
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
