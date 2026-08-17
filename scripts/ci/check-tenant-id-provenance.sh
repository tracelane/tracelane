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

#
# Falsify it: ./scripts/ci/check-tenant-id-provenance.sh --selftest
# Exit codes: 0 = clean · 1 = violation(s) found · 2 = bad usage / selftest failed.

set -uo pipefail

usage() {
  cat <<'EOF'
usage: check-tenant-id-provenance.sh [--selftest] [-h|--help]

  (no args)   Scan the repo for the org_id->tenant-UUID seam: a raw
              session.tenantId bound to a ClickHouse tenant filter, a Rust audit
              endpoint taking its tenant from the request instead of the
              validated claim, or TenantId::from_self_host_config on a hosted
              path. Exit 1 on any violation.
  --selftest  Prove the guard BLOCKS: plant each violation shape in a temp tree
              and assert it is caught, and assert a clean tree still passes.
              Exit 0 only if every case holds.
EOF
}

mode=scan
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) mode=selftest ;;
    -h|--help)  usage; exit 0 ;;
    *)
      echo "check-tenant-id-provenance.sh: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Surfaces that read ClickHouse with a session/JWT-derived tenant.
SCAN_DIRS=(apps/web apps/mcp packages/cli)

# Scans $PWD. Returns 0 when clean, 1 when any violation is found.
run_guard() {
local fail=0

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
  'tenantId:[[:space:]]*session\.organizationId'          # the same seam, WorkOS naming
  'tenantId:[[:space:]]*.?["'"'"']org_'                   # a raw org_ literal bound as the tenant
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
# ---------------------------------------------------------------------------
# THE STRUCTURAL CHECK — and the honest reason it exists.
#
# The three patterns above match three literal SPELLINGS. A falsification on
# 2026-08-13 planted nine real-shape violations and they caught one: a single
# variable hop (`const t = session.tenantId`), ES6 shorthand, a destructured
# session, or simply a DIFFERENT ClickHouse-binding function all sail through.
# **grep cannot follow a variable, and no amount of added patterns will change
# that** — each new pattern only pins one more spelling of a bug with unbounded
# spellings.
#
# What actually closes the TS surface is structural: `apps/web` has NO
# ClickHouse client (ADR: the dashboard reads only via the gateway's /v1/*
# routes), so there is no tenant filter there to bind wrongly. That property,
# not the regexes, is why the seven original offenders cannot come back — and it
# is a property a guard CAN check exactly.
#
# So the patterns stay as a cheap regression pin, and this is the real control.
# ---------------------------------------------------------------------------
echo
echo "== structural: the dashboard must not talk to ClickHouse directly =="
ch_dep=$(grep -rlE '@clickhouse/client|createClient\(.*clickhouse' apps/web \
           --include='*.ts' --include='*.tsx' --include='package.json' 2>/dev/null \
         | grep -v node_modules || true)
if [ -n "$ch_dep" ]; then
  echo "FAIL: apps/web has acquired a ClickHouse client. The dashboard reads"
  echo "      ClickHouse ONLY through the gateway's /v1/* routes, where the tenant"
  echo "      comes from a validated claim. A direct client re-opens the whole"
  echo "      org_id->tenant-UUID seam, and the patterns above cannot cover it —"
  echo "      one variable hop defeats every one of them:"
  echo "$ch_dep" | sed 's/^/  /'
  echo
  fail=1
else
  echo "OK: no ClickHouse client under apps/web (reads go through the gateway)."
fi

# Files that must AFFIRMATIVELY bind claims.tenant_id (check (c) only). This is
# a presence check, so it is meaningful only where reading the ledger for a
# tenant is the whole job of the file.
RUST_CLAIM_FILES=(
  crates/gateway/src/audit_self_verify.rs
  crates/gateway/src/audit_export.rs
)

# Checks (a) and (b) are scanned REPO-WIDE.
#
# EARNED 2026-08-13. These two checks used to run against the same two
# hardcoded files as (c). A falsification planting nine real-shape violations
# caught ONE. **27 files under crates/ bind a tenant into a ClickHouse-shaped
# query; the guard read two of them** — not `trace_reads.rs` (17 dashboard read
# routes), not `annotation_routes.rs`, not `notification_routes.rs`, the last
# two added the same day the gap was found. A guard whose scope is a hand-kept
# list silently stops covering the surface the moment the surface grows, and
# nothing about it looks wrong: it still passes, still runs in CI, still reports
# the files it was told about.
RUST_SCAN_FILES=$(find crates -name '*.rs' -type f 2>/dev/null | sort)

echo
echo "== Rust request-tenant provenance guard (repo-wide) =="
echo "Scanning: $(printf '%s\n' "$RUST_SCAN_FILES" | grep -c . ) file(s) under crates/"
echo

# (a) + (b) in one precise pass. The awk this replaces grabbed 14 lines after any
# struct line and printed anything containing "tenant" — repo-wide that reported
# doc comments, SQL strings and unrelated locals as violations. A guard with false
# positives gets exemptions added until it means nothing, so precision here is a
# security property, not tidiness.
# Scans $PWD, NOT $ROOT — run_guard is called with cwd set to the tree under
# test, and the selftest's whole method is pointing it at a planted fixture.
# Passing $ROOT here made case 14 scan the real repo, find it clean, and report
# a pass for a violation that was never looked at: the guard's own selftest
# reproducing the exact defect the guard exists to catch.
rust_hits=$(python3 - "." <<'PY'
import re, sys, pathlib

root = pathlib.Path(sys.argv[1])

# Request-input structs that legitimately carry a tenant field. Each needs WHY —
# the cost of writing the reason is what keeps the list short.
ALLOW_STRUCT = {
    "PubkeyQuery": "GET /v1/audit/pubkey is deliberately unauthenticated and returns "
                   "a PUBLIC key — an offline verifier must fetch it with no "
                   "credentials. Rate-limited; parsed to a UUID and bound as a UUID. "
                   "Nothing tenant-private is reachable through it.",
}
ALLOW_ACCESS = {
    # file -> reason. Same argument as above, at the access site.
    "crates/gateway/src/audit_pubkey.rs":
        "the public-key lookup above; the tenant IS the query parameter by design",
}

REQ_STRUCT = re.compile(
    r"((?:#\[[^\]]*\]\s*)+)(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w*(?:Query|Body|Request|Params))\s*\{([^}]*)\}"
)
# A real field declaration, not a comment or a string.
FIELD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?tenant_?[iI]d\s*:", re.MULTILINE)
ACCESS = re.compile(r"\b(?:q|query|body|params|req|payload|headers)\.tenant_?[iI]d\b")

out = []
for p in sorted(root.joinpath("crates").rglob("*.rs")):
    rel = p.relative_to(root).as_posix()
    src = p.read_text(encoding="utf-8", errors="replace")

    # (a) request-input struct with a genuine tenant FIELD
    for m in REQ_STRUCT.finditer(src):
        attrs, name, body = m.group(1), m.group(2), m.group(3)
        if "Deserialize" not in attrs or name in ALLOW_STRUCT:
            continue
        if FIELD.search(body):
            line = src[: m.start()].count("\n") + 1
            out.append(f"A|{rel}:{line}|struct {name} takes tenant_id from the request")

    # (b) a request-derived variable feeding tenancy. Tests legitimately build
    # request structs, so stop at the test module; skip comment lines.
    if rel in ALLOW_ACCESS:
        continue
    head = src.split("#[cfg(test)]")[0]
    for i, ln in enumerate(head.splitlines(), 1):
        s = ln.strip()
        if s.startswith("//") or s.startswith("*"):
            continue
        if ACCESS.search(ln):
            out.append(f"B|{rel}:{i}|{s[:100]}")

print("\n".join(out))
PY
)
if [ -n "$rust_hits" ]; then
  echo "$rust_hits" | while IFS='|' read -r kind loc detail; do
    if [ "$kind" = "A" ]; then
      echo "FAIL: request-input struct carries a tenant field — tenancy must come"
      echo "      from the validated claim, not the request:"
    else
      echo "FAIL: request-derived tenant_id used (must be claims.tenant_id):"
    fi
    echo "  $loc: $detail"
    echo
  done
  fail=1
fi

# (c) Provenance present — only for the files whose entire job is reading the
#     ledger for a tenant. A presence check repo-wide would be noise.
for f in "${RUST_CLAIM_FILES[@]}"; do
  [ -f "$f" ] || continue
  if ! grep -qE 'claims\.tenant_id' "$f"; then
    echo "FAIL: $f reads the audit ledger but never binds claims.tenant_id"
    echo "      (the validated-claim tenant UUID). Resolve the tenant from"
    echo "      validate_authorization(), never from the request."
    echo
    fail=1
  fi
done

# ---------------------------------------------------------------------------
# (e) THE FOURTH CONSTRUCTOR.
#
# `TenantId` documents three trust boundaries — `from_jwt_claim`,
# `from_spiffe_svid`, `from_self_host_config` — and says an audit grep for
# `TenantId::from_` enumerates every one of them. It does not.
# `crates/shared/src/tenant.rs` derives `Deserialize` with
# `#[serde(transparent)]`, so **serde is a fourth constructor**: any struct with
# a `TenantId`-typed field builds one straight from bytes, through no trust
# boundary, and the documented audit grep returns clean.
#
# Contained today, by environment rather than by the type: the only bytes->
# TenantId path is the NATS payload, which the gateway produces from a validated
# claim, and the OTLP resource-attribute fallback is `#[cfg(debug_assertions)]`-
# gated so release builds reject it. Both are properties of the deployment, not
# of `TenantId`. Add one `Json<T>` handler whose `T` carries a `TenantId` and the
# request picks the tenant — with nothing to grep for.
#
# So: a Deserialize-deriving struct may not carry a TenantId field unless it is
# named here with a reason.
# ---------------------------------------------------------------------------
echo
echo "== serde fourth-constructor guard (TenantId is Deserialize) =="
serde_hits=$(python3 - <<'PY'
import re, pathlib, sys
# Internal envelopes whose bytes are produced by a trusted component, never by a
# client. Each entry states WHO writes the bytes — that is the whole argument.
ALLOW = {
    "TracelaneSpan": "NATS span payload; written by the gateway from a validated "
                     "claim, and NATS is not client-reachable",
}
out = []
for p in sorted(pathlib.Path("crates").rglob("*.rs")):
    src = p.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r"((?:#\[[^\]]*\]\s*)+)(?:pub )?struct (\w+)\s*\{([^}]*)\}", src):
        attrs, name, body = m.group(1), m.group(2), m.group(3)
        if "Deserialize" not in attrs:
            continue
        if not re.search(r":\s*(?:Option<)?TenantId", body):
            continue
        if name in ALLOW:
            continue
        line = src[: m.start()].count("\n") + 1
        out.append(f"{p}:{line}: struct {name} derives Deserialize and carries a TenantId field")
print("\n".join(out))
PY
)
if [ -n "$serde_hits" ]; then
  echo "FAIL: a Deserialize-deriving struct carries a TenantId field — serde will"
  echo "      construct the tenant from BYTES, bypassing all three trust boundaries,"
  echo "      and \`grep TenantId::from_\` will not show it:"
  echo "$serde_hits" | sed 's/^/  /'
  echo "  -> take the tenant from the validated claim; if the bytes are genuinely"
  echo "     internal, add the struct to ALLOW with WHO writes them."
  echo
  fail=1
fi

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
return "$fail"
}

# ── Selftest ───────────────────────────────────────────────────────────────
#
# Every case runs the REAL run_guard against a planted temp tree. Nothing under
# the repo is written, so `git status --porcelain` is unchanged afterwards.

selftest_failures=0
selftest_tmp=""

# _case <name> <expected_exit> <dir> [expected_substring]
_case() {
  local name="$1" want="$2" dir="$3" needle="${4:-}" rc=0 out
  out="$( cd "$dir" && run_guard 2>&1 )" || rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "✗ $name: expected exit $want, got $rc"
    printf '%s\n' "$out" | sed 's/^/      /'
    selftest_failures=$((selftest_failures + 1))
    return 0
  fi
  if [ -n "$needle" ] && ! printf '%s' "$out" | grep -qF "$needle"; then
    echo "✗ $name: exit $rc as expected, but output did not mention '$needle'"
    printf '%s\n' "$out" | sed 's/^/      /'
    selftest_failures=$((selftest_failures + 1))
    return 0
  fi
  echo "✓ $name (exit $rc)"
}

# Lays down a tree that is clean by construction; callers then plant into it.
_fixture() {
  local d="$1"
  mkdir -p "$d/apps/web/lib" "$d/apps/mcp/src" "$d/packages/cli/src" \
           "$d/crates/gateway/src" "$d/crates/shared/src"

  # Correct TS shape: the org_id is resolved to the internal UUID first.
  cat > "$d/apps/web/lib/tenant.ts" <<'TS'
export async function load(session: Session) {
  const internalTenantId = await upsertTenantId(session.tenantId);
  return queryTraceSummaries(internalTenantId, {});
}
TS
  # Postgres filter on the workos_org_id COLUMN is correct, and must not flag.
  cat > "$d/apps/mcp/src/read.ts" <<'TS'
const row = await db.select().from(tenants)
  .where(eq(tenants.workosOrgId, session.tenantId));
TS
  echo 'export const noop = 1;' > "$d/packages/cli/src/verify.ts"

  # Correct Rust shape: tenancy from the validated claim. The request struct is
  # placed AFTER the handler and carries no tenant field.
  cat > "$d/crates/gateway/src/audit_self_verify.rs" <<'RS'
use axum::extract::Query;

pub async fn self_verify(claims: Claims) -> Result<Json<Verdict>> {
    let tenant = claims.tenant_id;
    read_chain(tenant).await
}

#[derive(Deserialize)]
pub struct SelfVerifyQuery {
    pub window: Option<String>,
    pub limit: Option<u32>,
}
RS
  cat > "$d/crates/gateway/src/audit_export.rs" <<'RS'
pub async fn export(claims: Claims) -> Result<Body> {
    let tenant = claims.tenant_id;
    stream_chain(tenant).await
}
RS
  # The two sanctioned homes of from_self_host_config (ADR-067).
  echo 'pub fn resolve() -> TenantId { TenantId::from_self_host_config(cfg) }' \
    > "$d/crates/shared/src/self_host.rs"
  echo 'impl TenantId { pub fn from_self_host_config(c: &Cfg) -> Self { .. } }' \
    > "$d/crates/shared/src/tenant.rs"
}

selftest() {
  local d
  selftest_tmp="$(mktemp -d)"   # global: the EXIT trap fires after locals die
  trap 'rm -rf "$selftest_tmp"' EXIT
  echo "check-tenant-id-provenance.sh --selftest"
  echo

  # 1. NEGATIVE CONTROL — a clean tree must pass, or the guard is a wall.
  d="$selftest_tmp/clean"; _fixture "$d"
  _case "clean tree passes" 0 "$d" "PASS: no raw session.tenantId"

  # 2-4. The three TS shapes that bind the raw WorkOS org_id to a CH filter.
  d="$selftest_tmp/ts-object"; _fixture "$d"
  echo 'const rows = await ch.query({ query_params: { tenantId: session.tenantId } });' \
    > "$d/apps/web/lib/traces.ts"
  _case "planted 'tenantId: session.tenantId' BLOCKS" 1 "$d" \
    "FAIL: raw WorkOS org_id (session.tenantId) bound to a ClickHouse tenant filter"

  d="$selftest_tmp/ts-assign"; _fixture "$d"
  echo 'params.tenantId = session.tenantId;' > "$d/apps/web/lib/traces.ts"
  _case "planted 'params.tenantId = session.tenantId' BLOCKS" 1 "$d" \
    "apps/web/lib/traces.ts"

  d="$selftest_tmp/ts-passthru"; _fixture "$d"
  echo 'const s = await queryTraceSummaries(session.tenantId, { limit: 20 });' \
    > "$d/apps/mcp/src/traces.ts"
  _case "planted 'queryTraceSummaries(session.tenantId' BLOCKS" 1 "$d" \
    "apps/mcp/src/traces.ts"

  # 5. Test fixtures are exempt (same violation, .test.ts path).
  d="$selftest_tmp/ts-test"; _fixture "$d"
  echo 'const rows = await ch.query({ query_params: { tenantId: session.tenantId } });' \
    > "$d/apps/web/lib/traces.test.ts"
  _case "same violation in a .test.ts is exempt" 0 "$d" "PASS: no raw session.tenantId"

  # 6. Rust (a): a request-input struct carrying a tenant field.
  d="$selftest_tmp/rs-struct"; _fixture "$d"
  cat > "$d/crates/gateway/src/audit_self_verify.rs" <<'RS'
pub async fn self_verify(claims: Claims, q: SelfVerifyQuery) -> Result<()> {
    let tenant = claims.tenant_id;
    read_chain(tenant).await
}

#[derive(Deserialize)]
pub struct SelfVerifyQuery {
    pub tenant_id: String,
}
RS
  _case "request-input struct with a tenant field BLOCKS" 1 "$d" \
    "FAIL: request-input struct carries a tenant field"

  # 7. Rust (b): tenancy read off a request-derived variable.
  d="$selftest_tmp/rs-access"; _fixture "$d"
  cat > "$d/crates/gateway/src/audit_export.rs" <<'RS'
pub async fn export(claims: Claims, q: ExportArgs) -> Result<Body> {
    let tenant = q.tenant_id;
    let _ = claims.tenant_id;
    stream_chain(tenant).await
}
RS
  _case "request-derived q.tenant_id BLOCKS" 1 "$d" \
    "crates/gateway/src/audit_export.rs:2"

  # 8. Rust (c): an audit endpoint that never binds the validated claim.
  d="$selftest_tmp/rs-noclaim"; _fixture "$d"
  cat > "$d/crates/gateway/src/audit_export.rs" <<'RS'
pub async fn export() -> Result<Body> {
    stream_whole_ledger().await
}
RS
  _case "audit endpoint without claims.tenant_id BLOCKS" 1 "$d" \
    "never binds claims.tenant_id"

  # 9. ADR-067 (d): from_self_host_config on a hosted path.
  d="$selftest_tmp/rs-selfhost"; _fixture "$d"
  cat > "$d/crates/gateway/src/hosted.rs" <<'RS'
pub fn tenant_for(req: &Request) -> TenantId {
    TenantId::from_self_host_config(&CFG)
}
RS
  _case "from_self_host_config on a hosted path BLOCKS" 1 "$d" \
    "FAIL: TenantId::from_self_host_config used outside the guarded self-host"

  # 10. …but the same call inside #[cfg(test)] is legitimate and must pass.
  d="$selftest_tmp/rs-selfhost-test"; _fixture "$d"
  cat > "$d/crates/gateway/src/hosted.rs" <<'RS'
pub fn tenant_for(claims: &Claims) -> TenantId { claims.tenant_id }

#[cfg(test)]
mod tests {
    #[test]
    fn fixed() { let _ = TenantId::from_self_host_config(&CFG); }
}
RS
  _case "from_self_host_config under #[cfg(test)] is exempt" 0 "$d" \
    "PASS: no raw session.tenantId"

  # ── Added 2026-08-13 after the falsification below. Each case here exists
  #    because the guard MISSED that shape when it was planted for real.

  # 11. THE STRUCTURAL CHECK — a ClickHouse client under apps/web.
  d="$selftest_tmp/ts-chdep"; _fixture "$d"
  echo '{ "dependencies": { "@clickhouse/client": "^1.0.0" } }' \
    > "$d/apps/web/package.json"
  _case "a ClickHouse client under apps/web BLOCKS" 1 "$d" \
    "FAIL: apps/web has acquired a ClickHouse client"

  # 12. The same seam under WorkOS's own field name.
  d="$selftest_tmp/ts-orgid"; _fixture "$d"
  echo 'const r = await ch.query({ query_params: { tenantId: session.organizationId } });' \
    > "$d/apps/web/lib/traces.ts"
  _case "'tenantId: session.organizationId' BLOCKS" 1 "$d" \
    "apps/web/lib/traces.ts"

  # 13. A raw org_ literal bound as the tenant.
  d="$selftest_tmp/ts-orglit"; _fixture "$d"
  echo 'const r = await ch.query({ query_params: { tenantId: "org_01KTB8ZZZ" } });' \
    > "$d/apps/web/lib/traces.ts"
  _case "a raw org_ literal bound as the tenant BLOCKS" 1 "$d" \
    "apps/web/lib/traces.ts"

  # 14. THE SCOPE FIX — a request-supplied tenant in a file the OLD guard's
  #     hardcoded two-file list did not read. This is the miss that mattered:
  #     trace_reads.rs has 17 routes and was never scanned.
  d="$selftest_tmp/rs-newfile"; _fixture "$d"
  cat > "$d/crates/gateway/src/trace_reads.rs" <<'RS'
#[derive(Deserialize)]
pub struct TraceListQuery {
    pub tenant_id: String,
    pub limit: Option<u32>,
}
RS
  _case "request tenant in an UNLISTED route file BLOCKS" 1 "$d" \
    "struct TraceListQuery takes tenant_id from the request"

  # 15. THE FOURTH CONSTRUCTOR — serde builds a TenantId straight from bytes,
  #     and `grep TenantId::from_` cannot see it.
  d="$selftest_tmp/rs-serde"; _fixture "$d"
  cat > "$d/crates/gateway/src/ingest_route.rs" <<'RS'
#[derive(Debug, Deserialize)]
pub struct SpanUpload {
    pub tenant_id: TenantId,
    pub name: String,
}
RS
  _case "Deserialize struct with a TenantId field BLOCKS" 1 "$d" \
    "serde will"

  # 16. …and the allowlisted internal envelope must still PASS, or the guard
  #     forbids the one shape that is legitimate.
  d="$selftest_tmp/rs-serde-allow"; _fixture "$d"
  cat > "$d/crates/shared/src/span.rs" <<'RS'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracelaneSpan {
    pub span_id: Uuid,
    pub tenant_id: TenantId,
}
RS
  _case "the allowlisted TracelaneSpan envelope passes" 0 "$d" \
    "PASS: no raw session.tenantId"

  # 17. A doc comment mentioning a tenant field must NOT fail — the awk this
  #     replaced reported doc comments and SQL strings as violations, and a
  #     guard with false positives gets exempted until it means nothing.
  d="$selftest_tmp/rs-comment"; _fixture "$d"
  cat > "$d/crates/gateway/src/tool_analytics.rs" <<'RS'
/// Bind order: tenant, hours, limit.
/// WHERE tenant_id = ? AND name != ''
#[derive(Deserialize)]
pub struct AnalyticsQuery {
    pub hours: u32,
}
RS
  _case "a doc comment naming tenant_id does NOT false-positive" 0 "$d" \
    "PASS: no raw session.tenantId"

  if [ "$selftest_failures" -gt 0 ]; then
    echo
    echo "selftest FAILED — $selftest_failures case(s). The guard is not trustworthy."
    return 2
  fi
  echo
  echo "selftest PASSED."
  return 0
}

if [ "$mode" = selftest ]; then
  selftest
  exit $?
fi

cd "$ROOT"
run_guard
exit $?
