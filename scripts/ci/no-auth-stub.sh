#!/usr/bin/env bash
# scripts/ci/no-auth-stub.sh
#
# CI guard: ensure `crates/ingest/src/auth.rs` never regresses to the
# `Ok(())` stub that shipped in the pre-PR#6 ingest. Tracked as
#  INGEST-001 (RESOLVED 2026-05-22) and ADR-028.
#
# A literal `Ok(())` returned from `verify_spiffe_svid` would re-introduce
# the CRITICAL stub vulnerability. This script greps for the regression
# pattern and exits non-zero if seen. Other occurrences of `Ok(())` in the
# file (e.g., test helpers that legitimately return unit) are allowed —
# we only fail when an *uncommented* `Ok(())` appears in the top-level
# pub fn body.
#
# Run locally:  ./scripts/ci/no-auth-stub.sh
# CI:           wired into .github/workflows/ci.yml job `no-auth-stub`.
# Falsify:      ./scripts/ci/no-auth-stub.sh --selftest
#               (plants every regression this guard names, in a throwaway tree,
#                and proves each one BLOCKS — plus that a clean tree passes)

set -euo pipefail

AUTH_FILE="crates/ingest/src/auth.rs"

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

usage() {
    cat <<'EOF'
usage: no-auth-stub.sh [--selftest | --help]

  (no args)    run the guard against ./crates/ingest/src/auth.rs
               exit 0 = intact · 1 = regression detected · 2 = file missing
  --selftest   plant each regression in a throwaway tree and prove it blocks
  -h, --help   this message
EOF
}

# ---------------------------------------------------------------- selftest ---
# The guard reads ONE relative path, uses no git and no network, so a complete
# falsification is just a temp dir with a synthetic crates/ingest/src/auth.rs.
# Nothing inside the repo is written, which is why the tree-unchanged assertion
# at the end is cheap and true.
selftest() {
    local fails=0 tmp before after rc=0

    before="$(git status --porcelain 2>/dev/null || true)"

    # Case 0 — the negative that makes every other case mean something. A guard
    # that failed on EVERY input would "catch" all six plants below and still be
    # worthless. It must pass the real, intact tree first.
    bash "$SELF" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "SELFTEST ABORT: the guard is already RED against this tree (exit $rc)." >&2
        echo "Fix the tree first — a red baseline makes every planted case vacuous." >&2
        return 1
    fi
    echo "✓ clean case: the real repo tree passes (exit 0)"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/crates/ingest/src"

    _plant() { cat >"$tmp/crates/ingest/src/auth.rs"; }

    _expect() { # label, expected_exit, [expected message substring]
        local got=0 out
        out="$( (cd "$tmp" && bash "$SELF") 2>&1 )" || got=$?
        if [[ "$got" -ne "$2" ]]; then
            echo "✗ $1 — expected exit $2, got $got" >&2
            printf '%s\n' "$out" >&2
            fails=$((fails + 1))
            return 0
        fi
        if [[ -n "${3:-}" ]] && ! printf '%s' "$out" | grep -Fq "$3"; then
            echo "✗ $1 — exit $got was right but the message never said '$3'" >&2
            printf '%s\n' "$out" >&2
            fails=$((fails + 1))
            return 0
        fi
        echo "✓ $1 (exit $got)"
    }

    # 1. A faithful implementation — parses the DER, extracts the SPIFFE id,
    #    returns the typed error. Must PASS, or the plants below prove nothing.
    _plant <<'RS'
use x509_parser::prelude::X509Certificate;

pub fn verify_spiffe_svid(der: &[u8]) -> Result<SpiffeIdentity, SpiffeAuthError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| SpiffeAuthError::MalformedCertificate)?;
    parse_spiffe_id(san_uri(&cert)?)
}
RS
    _expect "clean case: a faithful verify_spiffe_svid passes" 0

    # 2. THE regression (INGEST-001): the body collapses to Ok(()). All three
    #    required tokens are still present, so this is caught by the stub
    #    pattern specifically — not by a token going missing.
    _plant <<'RS'
use x509_parser::prelude::X509Certificate;

pub fn verify_spiffe_svid(_der: &[u8]) -> Result<(), ()> { Ok(()) }

fn _tokens_still_here() {
    let _ = X509Certificate::from_der;
    let _ = parse_spiffe_id;
    let _: Option<SpiffeAuthError> = None;
}
RS
    _expect "Ok(()) stub in verify_spiffe_svid BLOCKS" 1 "regressed to the Ok(()) stub"

    # 3. Discriminating negative: the same stub inside a line comment must NOT
    #    trip the guard, or every doc mentioning the bug becomes unmergeable.
    _plant <<'RS'
use x509_parser::prelude::X509Certificate;

// NEVER do this: pub fn verify_spiffe_svid(d: &[u8]) -> R { Ok(()) }
pub fn verify_spiffe_svid(der: &[u8]) -> Result<SpiffeIdentity, SpiffeAuthError> {
    let (_, cert) = X509Certificate::from_der(der)?;
    parse_spiffe_id(san_uri(&cert)?)
}
RS
    _expect "clean case: a COMMENTED-OUT stub is not a false positive" 0

    # 4. Cert parsing removed — "look up the tenant and return Ok" is the same
    #    bypass wearing a real signature.
    _plant <<'RS'
pub fn verify_spiffe_svid(der: &[u8]) -> Result<SpiffeIdentity, SpiffeAuthError> {
    parse_spiffe_id(tenant_from_bytes(der))
}
RS
    _expect "dropping X509Certificate::from_der BLOCKS" 1 "X509Certificate::from_der"

    # 5. Parses the cert but never extracts/validates the SPIFFE id (F-4).
    _plant <<'RS'
use x509_parser::prelude::X509Certificate;

pub fn verify_spiffe_svid(der: &[u8]) -> Result<SpiffeIdentity, SpiffeAuthError> {
    let (_, _cert) = X509Certificate::from_der(der)
        .map_err(|_| SpiffeAuthError::MalformedCertificate)?;
    Ok(SpiffeIdentity::default())
}
RS
    _expect "dropping parse_spiffe_id BLOCKS" 1 "'parse_spiffe_id' is gone"

    # 6. Typed rejection surface gone — errors can no longer be fail-closed.
    _plant <<'RS'
use x509_parser::prelude::X509Certificate;

pub fn verify_spiffe_svid(der: &[u8]) -> Result<SpiffeIdentity, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| e.to_string())?;
    parse_spiffe_id(san_uri(&cert)?)
}
RS
    _expect "dropping SpiffeAuthError BLOCKS" 1 "'SpiffeAuthError' is gone"

    # 7. The file itself disappearing must be loud (exit 2), never a silent pass
    #    — a guard whose subject was moved away is the classic vacuous green.
    rm -f "$tmp/crates/ingest/src/auth.rs"
    _expect "auth.rs missing entirely BLOCKS (exit 2, not a silent pass)" 2 "not found"

    rm -rf "$tmp"
    trap - EXIT

    # 8. State restored: the selftest wrote only under mktemp, so the repo must
    #    be byte-identical to how we found it.
    after="$(git status --porcelain 2>/dev/null || true)"
    if [[ "$before" != "$after" ]]; then
        echo "✗ selftest mutated the working tree — git status changed" >&2
        diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
        fails=$((fails + 1))
    else
        echo "✓ working tree unchanged (git status --porcelain identical)"
    fi

    if [[ "$fails" -ne 0 ]]; then
        echo "selftest FAILED — $fails case(s). This guard is not trustworthy." >&2
        return 1
    fi
    echo "selftest PASSED."
    return 0
}

# ------------------------------------------------------------ arg handling ---
# Default-deny on argv. Silently ignoring an unknown flag is how `--selftest`
# came to "pass" on a guard that had no selftest at all.
if [[ "$#" -gt 1 ]]; then
    echo "ERROR: too many arguments: $*" >&2
    usage >&2
    exit 2
fi
case "${1:-}" in
    "") ;;
    --selftest) selftest; exit $? ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "ERROR: unknown argument '$1'" >&2
        usage >&2
        exit 2
        ;;
esac

if [[ ! -f "$AUTH_FILE" ]]; then
    echo "FAIL: $AUTH_FILE not found — repo layout changed without updating this guard."
    exit 2
fi

# Strip line comments before grepping so `// Ok(())` examples in docs
# don't trigger a false positive.
STRIPPED=$(sed -E 's://.*$::' "$AUTH_FILE")

# The stub the guard exists to prevent.
STUB_PATTERN='pub fn verify_spiffe_svid[^{]*\{\s*Ok\(\(\)\)\s*\}'

if echo "$STRIPPED" | tr '\n' ' ' | grep -Eq "$STUB_PATTERN"; then
    cat <<EOF >&2
ERROR: $AUTH_FILE — verify_spiffe_svid has regressed to the Ok(()) stub.

This is the CRITICAL SPIFFE bypass tracked internally
INGEST-001 (resolved 2026-05-22 in PR #6 + #7 / ADR-028). Any merge
that re-introduces this stub silently disables ingest authentication
and lets any process inject spans for any tenant.

Restore the real implementation before this CI job will pass.
EOF
    exit 1
fi

# Additionally, the public entry point must call x509-parser to actually
# look at the cert. A regression to "look up tenant, return Ok" without
# parsing the SVID would also re-create the bypass.
if ! grep -q 'X509Certificate::from_der' "$AUTH_FILE"; then
    cat <<EOF >&2
ERROR: $AUTH_FILE — verify_spiffe_svid no longer calls
X509Certificate::from_der. The SPIFFE SVID parser is the only thing
that verifies the cert is a real certificate; removing it would
silently bypass identity verification.
EOF
    exit 1
fi

#  review F-4: parsing the cert is not enough — the SPIFFE identity
# must also be EXTRACTED AND VALIDATED (trust domain, tenant path, workload
# kind). A refactor that keeps the DER parse but returns a fixed/nil
# identity would pass the two checks above; require the SAN→SPIFFE-ID
# validation path and its typed error surface to still exist.
for TOKEN in 'parse_spiffe_id' 'SpiffeAuthError'; do
    if ! grep -q "$TOKEN" "$AUTH_FILE"; then
        cat <<EOF >&2
ERROR: $AUTH_FILE — '$TOKEN' is gone. The SPIFFE-ID extraction/validation
path (SAN → parse_spiffe_id → typed SpiffeAuthError rejections) is what
binds the peer certificate to a tenant identity; removing or renaming it
without updating this guard re-opens the INGEST-001 bypass class.
EOF
        exit 1
    fi
done

echo "no-auth-stub guard: OK ($AUTH_FILE intact)."
