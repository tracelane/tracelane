#!/usr/bin/env bash
# scripts/ci/no-auth-stub.sh
#
# CI guard: ensure `crates/ingest/src/auth.rs` never regresses to the
# `Ok(())` stub that shipped in the pre-PR#6 ingest. Tracked as
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

set -euo pipefail

AUTH_FILE="crates/ingest/src/auth.rs"

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
