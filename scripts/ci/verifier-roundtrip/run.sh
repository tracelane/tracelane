#!/usr/bin/env bash
# scripts/ci/verifier-roundtrip/run.sh
#
# CROWN-JEWEL cross-verifier assertion (ADR-062). The three independent reference
# verifiers (Rust / TypeScript / Python) must AGREE on the committed conformance
# vectors, verified against the tenant's TRUSTED Ed25519 pubkey:
#
#   anchored.v1.ndjson  → GREEN   (hash chain + Ed25519 sig + anchors_included ≥ 1)
#   forged-anchor.ndjson→ REJECTED(a real, publicly-queryable Rekor entry planted
#                                   with an attacker's OWN key over a tampered chain
#                                   — the permissionless-log attack; anchors_included=0)
#   anchored.v1 tampered→ RED     (one row payload mutated → hash chain breaks)
#
# Exit 0 iff all 3 verifiers give the expected verdict on all 3 vectors.
# Wired as a CI job step (not just a local script) so the gate covers the hero.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$ROOT/scripts/ci/verifier-roundtrip"
VEC="$ROOT/evals/audit-ledger"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

ANCHORED="$VEC/anchored.v1.ndjson"
FORGED="$VEC/forged-anchor.ndjson"
TAMPERED="$WORK/anchored.tampered.ndjson"
[ -f "$ANCHORED" ] || { echo "FATAL: missing $ANCHORED"; exit 2; }
[ -f "$FORGED" ]   || { echo "FATAL: missing $FORGED"; exit 2; }

# Trusted tenant pubkey = anchored.v1's own Ed25519 anchor pubkey (the out-of-band root).
PK="$(node -e 'const fs=require("fs");const l=fs.readFileSync(process.argv[1],"utf8").split("\n").filter(Boolean).map(JSON.parse);process.stdout.write(l.find(x=>x.type==="anchor").ed25519.pubkey)' "$ANCHORED")"
[ -n "$PK" ] || { echo "FATAL: could not read trusted pubkey from $ANCHORED"; exit 2; }

# Tampered variant: mutate the first non-anchor row's payload — the chain must break.
node -e '
const fs=require("fs");const [inF,outF]=process.argv.slice(1);
const lines=fs.readFileSync(inF,"utf8").split("\n").filter(Boolean);
const i=lines.findIndex(l=>JSON.parse(l).type!=="anchor");
const o=JSON.parse(lines[i]);
o.payload=(typeof o.payload==="string"?o.payload:JSON.stringify(o.payload))+"_TAMPERED";
lines[i]=JSON.stringify(o); fs.writeFileSync(outF, lines.join("\n")+"\n");
' "$ANCHORED" "$TAMPERED"

# --- verifier artifacts (build if missing so `bash run.sh` works locally too) ---
TS_DIST="$ROOT/packages/verifier-typescript/dist/index.js"
[ -f "$TS_DIST" ] || (cd "$ROOT" && pnpm --filter @tracelanedev/audit-verifier build >/dev/null) || { echo "FATAL: TS verifier build failed"; exit 2; }
# HONOUR CARGO_TARGET_DIR. CI sets it to a persistent dir (B-202c/B-203), so the
# binary does NOT land in $ROOT/target — and this line used to hardcode
# $ROOT/target/release.
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
RUST_BIN="$CARGO_TARGET/release/tracelane-audit"
if [ ! -x "$RUST_BIN" ]; then
  (cd "$ROOT" && cargo build --release -p tracelane-audit >/dev/null 2>&1) \
    || { echo "FATAL: rust verifier build failed"; exit 2; }
fi
# ASSERT THE POSTCONDITION, NOT THE BUILD'S EXIT CODE.
#
# This is what actually broke (2026-08-13). `cargo build` exited 0 while placing
# the binary under $CARGO_TARGET_DIR, so the old `|| { FATAL }` never fired; the
# missing $RUST_BIN was then exec'd with stderr swallowed, every rust check
# produced empty output, and the harness rendered it as `<parse-error>` —
# i.e. a MISSING verifier reported as a DISAGREEING one, on the job whose whole
# purpose is detecting disagreement. The job had been `skipped` on every run
# since CARGO_TARGET_DIR was introduced, so nothing went red for four commits.
[ -x "$RUST_BIN" ] || {
  echo "FATAL: rust verifier absent at $RUST_BIN after a SUCCESSFUL build"
  echo "       CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-<unset>}  ROOT=$ROOT"
  exit 2
}
PYTHON="${PYTHON:-python3}"
"$PYTHON" -c 'import tracelane_audit_verifier' 2>/dev/null || { echo "FATAL: python verifier not importable via '$PYTHON' — pip install ./packages/verifier-python"; exit 2; }

run_ts()   { node "$HERE/ts-verify.mjs" "$TS_DIST" "$1" "$PK"; }
run_py()   { "$PYTHON" "$HERE/py-verify.py" "$1" "$PK"; }
# `2>/dev/null` is tolerable ONLY because $RUST_BIN's existence is asserted above.
# Without that assertion it converts "binary not found" into silent empty output.
run_rust() { "$RUST_BIN" verify --file "$1" --tenant-pubkey "$PK" --format json 2>/dev/null | sed -n '/^{/,$p'; }

# GREEN iff chain valid AND sig valid AND at least one anchor's inclusion proof verified.
verdict() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);process.stdout.write((j.hash_chain_valid&&j.signatures_valid&&j.anchors_included>=1)?"GREEN":"NOTGREEN")})'; }

FAIL=0
check() { # <verifier> <scenario> <ledger> <expect GREEN|NOTGREEN>
  local v="$1" sc="$2" led="$3" exp="$4" out got
  out="$("run_$v" "$led")"
  got="$(printf '%s' "$out" | verdict 2>/dev/null)"
  if [ "$got" = "$exp" ]; then echo "  OK   $v · $sc -> $got   $out"
  else echo "  FAIL $v · $sc -> ${got:-<parse-error>}, expected $exp   $out"; FAIL=1; fi
}

echo "== anchored.v1 -> GREEN (chain + sig + anchors_included>=1) =="
for v in ts py rust; do check "$v" anchored "$ANCHORED" GREEN; done
echo "== forged-anchor -> REJECTED (real Rekor entry, attacker key → NOTGREEN) =="
for v in ts py rust; do check "$v" forged "$FORGED" NOTGREEN; done
echo "== anchored.v1 tampered -> RED (chain broken → NOTGREEN) =="
for v in ts py rust; do check "$v" tampered "$TAMPERED" NOTGREEN; done

echo
if [ "$FAIL" -eq 0 ]; then
  echo "ROUND-TRIP GREEN — Rust + TS + Python agree on all three vectors (trusted pubkey ${PK:0:12}…)."
  exit 0
else
  echo "ROUND-TRIP FAILED — a verifier disagreed. Inspect above."
  exit 1
fi
