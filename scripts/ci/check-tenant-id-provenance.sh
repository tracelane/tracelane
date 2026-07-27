#!/usr/bin/env bash
# scripts/ci/check-tenant-id-provenance.sh
#
# CI guard: the org_id -> tenant-UUID seam (the #1 recurring bug class).
#
# `session.tenantId` (web) and a WorkOS access-token claim = the WorkOS
# *org_id* (org_01KTB8...), NOT the internal tenant UUID (1bb14687...).
# ClickHouse and Postgres tenant rows key on the INTERNAL UUID. Binding the
# raw org_id into a data query silently matches zero rows (CH) or rejects (PG).
#
# This class has bitten 4+ times (gateway auth, provider-key proxy, the 6+1
# dashboard ClickHouse trace reads, and latent MCP/CLI surfaces). The fix is
# always the same: resolve the internal UUID FIRST.
#   * Web:     upsertTenantId(session.tenantId)   (apps/web/lib/tenant.ts)
#   * Gateway: Claims.tenant_id from validate_authorization (always internal UUID)
#
# THE RULE this guard enforces: no ClickHouse tenant binding may use the raw
# `session.tenantId`. Postgres `eq(tenants.workosOrgId, session.tenantId)` is
# CORRECT (it filters the org_id *column*) and is NOT flagged.
#
# Run the whole audit at once (so we never find these one by one):
#   ./scripts/ci/check-tenant-id-provenance.sh
#
# STATUS: WIRED into the CI merge gate (.github/workflows/ci.yml job
# `tenant-id-provenance`) as of the Option-1 gateway-proxied trace refactor
# () — which removed the 7 dashboard offenders, so the tree is clean and
# this exits 0. From here on it catches any regression / new instance across ALL
# surfaces (apps/web, apps/mcp, packages/cli). See memory: tenant-id-org-seam.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Surfaces that read ClickHouse with a session/JWT-derived tenant.
SCAN_DIRS=(apps/web apps/mcp packages/cli)

fail=0

echo "== org_id->tenant-UUID provenance guard =="
echo "Scanning: ${SCAN_DIRS[*]}"
echo

# The exact buggy shapes (all 7 current offenders match one of these):
#   query_params: { tenantId: session.tenantId ... }
#   params.tenantId = session.tenantId
#   queryTraceSummaries(session.tenantId, ...)  / any fn(session.tenantId) that binds CH
# A raw `session.tenantId` bound as a ClickHouse `tenantId` value is the bug.
PATTERNS=(
  'tenantId:[[:space:]]*session\.tenantId'      # query_params object literal
  '\.tenantId[[:space:]]*=[[:space:]]*session\.tenantId'  # params.tenantId = ...
  'queryTraceSummaries\([[:space:]]*session\.tenantId'    # pass-through to a CH-binding fn
)

for dir in "${SCAN_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  for pat in "${PATTERNS[@]}"; do
    # Skip test files (fixtures may use literal ids on purpose).
    hits=$(grep -rnE "$pat" "$dir" --include='*.ts' --include='*.tsx' 2>/dev/null \
            | grep -viE '/__tests__/|\.test\.|\.spec\.' || true)
    if [ -n "$hits" ]; then
      echo "FAIL: raw WorkOS org_id (session.tenantId) bound to a ClickHouse tenant filter:"
      echo "$hits" | sed 's/^/  /'
      echo "  -> resolve first: const internalTenantId = await upsertTenantId(session.tenantId)"
      echo
      fail=1
    fi
  done
done

# ---------------------------------------------------------------------------
# Rust gateway audit read-endpoints (ADR-066 self-verify + the export).
#
# These handlers read `tracelane.audit_log` for a tenant. The tenant MUST be the
# validated-claim UUID (`claims.tenant_id` from `validate_authorization`), NEVER
# a request query/body/header field. This is the same org_id→tenant seam as the
# TS surfaces, in Rust: a `tenant_id` on a request-input struct (`*Query` /
# `*Body` / `*Request` / `*Params`) or a `q./query./body./params.tenant_id`
# access is the bug — it lets the request pick the tenant and read another
# tenant's chain.
# ---------------------------------------------------------------------------
RUST_AUDIT_FILES=(
  crates/gateway/src/audit_self_verify.rs
  crates/gateway/src/audit_export.rs
)

echo
echo "== Rust audit-endpoint tenant-provenance guard =="
echo "Scanning: ${RUST_AUDIT_FILES[*]}"
echo

for f in "${RUST_AUDIT_FILES[@]}"; do
  [ -f "$f" ] || continue

  # (a) A `tenant`-named field on a REQUEST-INPUT struct (named *Query / *Body /
  #     *Request / *Params). ClickHouse-result rows (AuditLogRow / AuditAnchorRow,
  #     which carry the tenant_id COLUMN) do not match this name pattern, so they
  #     are not flagged.
  bad_field=$(awk '
    /struct[ \t]/ && /(Query|Body|Request|Params)/ { grab = 14 }
    grab > 0 { if ($0 ~ /tenant/) print FILENAME ":" FNR ": " $0; grab-- }
  ' "$f" || true)
  if [ -n "$bad_field" ]; then
    echo "FAIL: request-input struct carries a tenant field — tenancy must come"
    echo "      from the validated claim (claims.tenant_id), not the request:"
    echo "$bad_field" | sed 's/^/  /'
    echo
    fail=1
  fi

  # (b) A request-derived variable feeding tenancy.
  bad_access=$(grep -nE '\b(q|query|body|params|req|payload|headers)\.tenant_?[iI]d\b' "$f" || true)
  if [ -n "$bad_access" ]; then
    echo "FAIL: request-derived tenant_id used in $f (must be claims.tenant_id):"
    echo "$bad_access" | sed 's/^/  /'
    echo
    fail=1
  fi

  # (c) Provenance present: the handler must resolve tenancy from the claim.
  if ! grep -qE 'claims\.tenant_id' "$f"; then
    echo "FAIL: $f reads the audit ledger but never binds claims.tenant_id"
    echo "      (the validated-claim tenant UUID). Resolve the tenant from"
    echo "      validate_authorization(), never from the request."
    echo
    fail=1
  fi
done

# (d) TenantId::from_self_host_config (ADR-067) is a trust boundary reachable ONLY
#     from the guarded single-tenant self-host resolver, which hard-fails on any
#     multi-tenant signal. It must NEVER appear on a hosted/multi-tenant code path
#     — a misuse would stamp one fixed tenant where a validated claim / SVID is
#     required (cross-tenant spoof). Allow it only where it is defined + resolved.
echo
echo "== self-host tenant-boundary guard (ADR-067) =="
# Flag only PRODUCTION usage: skip the definition (tenant.rs) + the guarded
# resolver (self_host.rs), and skip anything after a file's `#[cfg(test)]` / `mod
# tests` boundary (unit tests legitimately construct a fixed TenantId; tests live
# at the bottom of the file per the Rust convention).
selfhost_misuse=""
for f in $(grep -rlE 'from_self_host_config' crates/ --include='*.rs' 2>/dev/null \
    | grep -vE 'crates/shared/src/(self_host|tenant)\.rs'); do
  hit=$(awk '/#\[cfg\(test\)\]/ || /^[[:space:]]*mod tests/ { intest=1 }
             !intest && /from_self_host_config/ { print FILENAME ":" FNR ": " $0 }' "$f")
  [ -n "$hit" ] && selfhost_misuse="${selfhost_misuse}${hit}"$'\n'
done
selfhost_misuse=$(printf '%s' "$selfhost_misuse" | sed '/^[[:space:]]*$/d')
if [ -n "$selfhost_misuse" ]; then
  echo "FAIL: TenantId::from_self_host_config used outside the guarded self-host"
  echo "      resolver (crates/shared/src/self_host.rs) — hosted-path spoof risk (ADR-067):"
  echo "$selfhost_misuse" | sed 's/^/  /'
  echo
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "PASS: no raw session.tenantId bound to a ClickHouse tenant filter,"
  echo "      and every Rust audit endpoint binds claims.tenant_id."
else
  echo "Guard FAILED — see the org_id->tenant-UUID seam (memory: tenant-id-org-seam)."
  echo "Every ClickHouse/Postgres tenant filter must bind the INTERNAL tenant UUID."
fi
exit "$fail"
