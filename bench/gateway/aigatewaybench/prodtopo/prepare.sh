#!/usr/bin/env bash
# prodtopo/prepare.sh — build the control-plane inputs for tracelane.prodtopo.compose.yml.
#
# Writes prodtopo/generated/ (gitignored):
#   10-migrations.sql  every apps/web/db/migrations/*.sql in order (the same application
#                      order scripts/ci/run-ledger-integration.sh proves against a throwaway
#                      Postgres) — Postgres' initdb runs it before the gateway boots, which
#                      the gateway's boot schema check requires
#   20-reference.sql   the §23 reference tables, DUMPED FROM PROD (plan_entitlements,
#                      pricing_rates, billing_policy, provider_capabilities) — passed in as
#                      GWBENCH_REFERENCE_SQL; refused when absent, because a hand-typed plan
#                      row is not prod's plan row
#   30-seed.sql        ONE tenant (plan enterprise: no rate cap, F8) + ONE admin-scoped
#                      tlane_ key, minted with the same recipe the prod deploy proofs use
#                      (HMAC-SHA256(pepper, body) lookup hash + Argon2id PHC) + ONE BYOK
#                      row for `anthropic`: the v3 envelope `0x03 || kek 0 || nonce ||
#                      AES-256-GCM(plaintext, aad="provider-key:<tenant>:anthropic")`
#                      under the throwaway master key (`crates/gateway/src/byok.rs:25-31`,
#                      `:407-409`). Written by the seed because the BYOK route refuses
#                      every API key by design (`byok_api/provider_keys_api.rs:210-236`:
#                      mutation needs a verified OWNER JWT) — the gateway then DECRYPTS it
#                      through its real path, AAD and all, on the first request
#   env                TRACELANE_APIKEY_PEPPER / TRACELANE_BYOK_MASTER_KEY (fresh, throwaway)
#                      + GWBENCH_TENANT_ID for compose
#   bearer             the plaintext key, mode 0600 — read by run.sh via
#                      GWBENCH_TRACELANE_BEARER_FILE, never echoed
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"
OUT="$HERE/generated"
REF="${GWBENCH_REFERENCE_SQL:-}"
[ -n "$REF" ] && [ -s "$REF" ] || { echo "REFUSING: GWBENCH_REFERENCE_SQL must name a non-empty dump of the reference tables (prod's plan rows are the fixture, not a hand-typed one)" >&2; exit 2; }
grep -q 'plan_entitlements' "$REF" || { echo "REFUSING: $REF carries no plan_entitlements rows" >&2; exit 2; }

rm -rf "$OUT"; mkdir -p "$OUT"; chmod 700 "$OUT"

# 10 — migrations, in order, one file (initdb reads the top level only).
: > "$OUT/10-migrations.sql"
n=0
for f in "$REPO_ROOT"/apps/web/db/migrations/*.sql; do
  printf -- '-- ===== %s =====\n' "$(basename "$f")" >> "$OUT/10-migrations.sql"
  cat "$f" >> "$OUT/10-migrations.sql"; printf '\n' >> "$OUT/10-migrations.sql"
  n=$((n+1))
done
echo "prepare: $n migrations concatenated"

# 20 — the reference tables as dumped from prod.
cp "$REF" "$OUT/20-reference.sql"

# 30 — tenant + key. The mint recipe mirrors crates/gateway/src/db/api_keys.rs:
# body = 43 base62 chars, lookup_hash = HMAC-SHA256(pepper, body), argon2id PHC over body.
PEPPER_HEX="$(openssl rand -hex 32)"
MASTER_B64="$(openssl rand -base64 32)"
TENANT_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
BYOK_PLAINTEXT="bench-mock-key"
MINT_PY='
import os, secrets, hmac, hashlib, binascii, base64
from argon2.low_level import hash_secret, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
n=int.from_bytes(secrets.token_bytes(32),"big"); s=""
while n: n,r=divmod(n,62); s=alphabet[r]+s
body=s.rjust(43,"0")
pep=binascii.unhexlify(os.environ["PEPPER_HEX"])
lookup=hmac.new(pep, body.encode(), hashlib.sha256).hexdigest()
phc=hash_secret(body.encode(), secrets.token_bytes(16), time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, type=Type.ID).decode()
# BYOK v3 envelope under KEK 0 (the legacy single key), AAD bound to (tenant, provider).
kek=base64.b64decode(os.environ["MASTER_B64"]); assert len(kek)==32
aad=("provider-key:%s:anthropic" % os.environ["TENANT_ID"]).encode()
nonce=secrets.token_bytes(12)
ct=AESGCM(kek).encrypt(nonce, os.environ["BYOK_PLAINTEXT"].encode(), aad)   # ct || 16-byte tag
blob=base64.b64encode(bytes([0x03, 0x00])+nonce+ct).decode()
print(body); print(lookup); print(phc); print(blob)
'
MINT_ENV=(PEPPER_HEX="$PEPPER_HEX" MASTER_B64="$MASTER_B64" TENANT_ID="$TENANT_ID" BYOK_PLAINTEXT="$BYOK_PLAINTEXT")
if python3 -c 'import argon2, cryptography' 2>/dev/null; then
  OUTP="$(env "${MINT_ENV[@]}" python3 -c "$MINT_PY")"
elif command -v uv >/dev/null 2>&1; then
  OUTP="$(env "${MINT_ENV[@]}" uv run --quiet --with argon2-cffi --with cryptography python3 -c "$MINT_PY")"
else
  OUTP="$(env "${MINT_ENV[@]}" docker run --rm -i -e PEPPER_HEX -e MASTER_B64 -e TENANT_ID -e BYOK_PLAINTEXT python:3.12-slim sh -c 'pip install -q argon2-cffi cryptography >/dev/null 2>&1; python3 -' <<<"$MINT_PY")"
fi
BODY="$(printf '%s\n' "$OUTP" | sed -n '1p')"; LOOKUP="$(printf '%s\n' "$OUTP" | sed -n '2p')"; PHC="$(printf '%s\n' "$OUTP" | sed -n '3p')"; BLOB="$(printf '%s\n' "$OUTP" | sed -n '4p')"
[ "${#BODY}" -eq 43 ] && [ "${#LOOKUP}" -eq 64 ] && [[ "$PHC" == '$argon2id$'* ]] && [ "${#BLOB}" -gt 40 ] || { echo "REFUSING: key mint produced the wrong shape" >&2; exit 1; }

cat > "$OUT/30-seed.sql" <<SQL
-- prodtopo seed: one enterprise tenant, one admin-scoped key (throwaway box, throwaway secrets)
INSERT INTO tenants (id, workos_org_id, plan, audit_enabled)
  VALUES ('$TENANT_ID', 'org_gwbench_prodtopo', 'enterprise', true);
INSERT INTO api_keys (tenant_id, name, lookup_hash, argon2id_phc, key_prefix, minted_by, scope)
  VALUES ('$TENANT_ID', 'gwbench-prodtopo', decode('$LOOKUP','hex'), '$PHC', '${BODY:0:6}', 'gwbench-prodtopo', ARRAY['chat','read','ingest','admin']);
-- BYOK row (see the header): the gateway's own decrypt path validates the AAD on first use.
INSERT INTO provider_keys (tenant_id, provider_id, ciphertext_b64, last4)
  VALUES ('$TENANT_ID', 'anthropic', '$BLOB', '${BYOK_PLAINTEXT: -4}');
SQL

umask 077
printf 'TRACELANE_APIKEY_PEPPER=%s\nTRACELANE_BYOK_MASTER_KEY=%s\nGWBENCH_TENANT_ID=%s\n' "$PEPPER_HEX" "$MASTER_B64" "$TENANT_ID" > "$OUT/env"
printf 'tlane_%s' "$BODY" > "$OUT/bearer"
echo "prepare: tenant $TENANT_ID, key prefix ${BODY:0:6}, outputs in $OUT (bearer 0600, never printed)"
