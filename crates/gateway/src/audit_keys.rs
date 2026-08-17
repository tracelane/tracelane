//! Per-tenant Ed25519 signing keypair management for the tamper-evident audit ledger.
//!
//! Each tenant (Enterprise tier) can have a dedicated Ed25519 keypair for signing
//! Rekor Merkle-root anchors. Keypairs are generated on first use, PKCS#8-encoded,
//! envelope-encrypted with the workspace BYOK master key, and persisted in the
//! `tenant_audit_keys` Postgres table.
//!
//! The `TRACELANE_REKOR_SIGNING_KEY` env var provides a global fallback for
//! non-Enterprise tenants and for development (no DB required).
//!
//! Callers: `crates/gateway/src/audit.rs` — `RekorClient` looks up the keypair
//! for the active tenant before submitting a Merkle root.
//!
//! the Audit SKU entitlement (`f_audit_addon`) — checked in `get_or_create` via the
//! `EntitlementCache`. An existing keypair is always honoured; a non-entitled tenant
//! falls back to the global `TRACELANE_REKOR_SIGNING_KEY`. (CLAUDE.md: per-feature
//! grants in `workspace_entitlements`, not the plan-tier path, are the mechanism.)

use std::sync::Arc;

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use deadpool_postgres::Pool;
use ring::signature::KeyPair as _;
use ring::{rand, signature};
use secrecy::zeroize::Zeroize as _;
use secrecy::{ExposeSecret, SecretString};
use tracing::instrument;

use crate::byok::ByokMasterKey;
use crate::entitlement_cache::{EntitlementCache, FeatureKey};
use tracelane_shared::TenantId;

/// Ed25519 signing keypair for a tenant's audit ledger.
///
/// The private key bytes are held in a `SecretString` to ensure they are
/// zeroed on drop and never appear in logs or tracing output.
pub struct TenantAuditKeypair {
    pub tenant_id: TenantId,
    /// PKCS#8 DER private key, wrapped in SecretString.
    private_key_der: SecretString,
    /// Cached parsed keypair for signing — avoids re-parsing on every call.
    key_pair: Arc<signature::Ed25519KeyPair>,
}

impl TenantAuditKeypair {
    /// Generate a new Ed25519 keypair for a tenant.
    ///
    /// The generated keypair is ready to sign but not yet persisted.
    /// Call [`TenantAuditKeyStore::store`] to persist it.
    pub fn generate(tenant_id: TenantId) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow::anyhow!("Ed25519 keypair generation failed"))?;
        let mut der = pkcs8_bytes.as_ref().to_vec();
        let parsed = signature::Ed25519KeyPair::from_pkcs8(&der);
        let private_key_der = SecretString::from(B64.encode(&der));
        der.zeroize(); // scrub the transient plaintext DER (the SecretString retains it)
        let key_pair =
            parsed.map_err(|e| anyhow::anyhow!("Ed25519 keypair parse after generate: {e:?}"))?;
        Ok(Self {
            tenant_id,
            private_key_der,
            key_pair: Arc::new(key_pair),
        })
    }

    /// Sign `message` bytes with this tenant's private key.
    ///
    /// Returns the raw Ed25519 signature (64 bytes).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message).as_ref().to_vec()
    }

    /// Public key bytes (raw 32-byte Ed25519 public key).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }
}

/// Fixed DER prefix for a P-256 `SubjectPublicKeyInfo`. Concatenated with ring's
/// 65-byte uncompressed public point (`0x04 ‖ X ‖ Y`) it yields the 91-byte SPKI
/// DER that Rekor v2 expects as `verifier.publicKey.rawBytes` (ADR-062). Encodes
/// `SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING { point } }`.
/// Verified byte-exact against a live Rekor v2 entry's `rawBytes`.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// ECDSA-P256 **anchor** keypair (ADR-062 two-key model). Single-purpose: signs the
/// `ANCHOR_ARTIFACT` (`b"tracelane-anchor-ecdsa-v1\0" ‖ merkle_root`) submitted to
/// the Rekor v2 `hashedrekord` entry. Distinct from the Ed25519
/// [`TenantAuditKeypair`] — Rekor v2 hashedrekord rejects pure Ed25519 (it loads
/// the verifier with `WithED25519ph`). NEVER used for the local attestation; the
/// Ed25519 key remains the sole local-attestation signer (ADR-057).
pub struct TenantAnchorKeypair {
    pub tenant_id: TenantId,
    /// PKCS#8 DER private key, base64, wrapped in `SecretString` (zeroed on drop).
    private_key_der: SecretString,
    /// Parsed ECDSA keypair — avoids re-parsing on every sign.
    key_pair: Arc<signature::EcdsaKeyPair>,
}

impl TenantAnchorKeypair {
    /// Generate a fresh ECDSA-P256 anchor keypair for `tenant_id`.
    ///
    /// The keypair is ready to sign but not yet persisted; the caller
    /// ([`TenantAuditKeyStore::get_or_create_anchor`]) persists it.
    pub fn generate(tenant_id: TenantId) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .map_err(|_| anyhow::anyhow!("ECDSA-P256 anchor keypair generation failed"))?;
        Self::from_pkcs8_der(tenant_id, pkcs8.as_ref())
    }

    /// Parse an anchor keypair from raw PKCS#8 DER bytes.
    fn from_pkcs8_der(tenant_id: TenantId, der: &[u8]) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            der,
            &rng,
        )
        .map_err(|e| anyhow::anyhow!("parse ECDSA anchor keypair: {e:?}"))?;
        Ok(Self {
            tenant_id,
            private_key_der: SecretString::from(B64.encode(der)),
            key_pair: Arc::new(key_pair),
        })
    }

    /// DER (ASN.1) ECDSA-P256/SHA-256 signature over `message` — the exact
    /// encoding Rekor v2 hashedrekord expects for `signature.content`.
    ///
    /// # Errors
    /// Fail-closed on RNG failure: return `Err` so the batch is left UNANCHORED
    /// rather than signed with a degraded nonce (a bad ECDSA nonce leaks the key).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = rand::SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, message)
            .map_err(|_| anyhow::anyhow!("ECDSA anchor signing failed (RNG)"))?;
        Ok(sig.as_ref().to_vec())
    }

    /// `SubjectPublicKeyInfo` (DER) — the Rekor `verifier.publicKey.rawBytes`
    /// and the value the verifier's `anchor_commitment` binding hashes.
    pub fn public_key_spki_der(&self) -> Vec<u8> {
        let point = self.key_pair.public_key().as_ref(); // 65-byte uncompressed 0x04‖X‖Y
        let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + point.len());
        spki.extend_from_slice(&P256_SPKI_PREFIX);
        spki.extend_from_slice(point);
        spki
    }
}

/// Postgres-backed store for per-tenant audit signing keypairs.
///
/// Keypairs are stored encrypted (via [`ByokMasterKey`]) in the
/// `tenant_audit_keys` table. Missing keypairs are generated on first use
/// and persisted automatically.
pub struct TenantAuditKeyStore {
    pool: Pool,
    byok: Arc<ByokMasterKey>,
    /// Entitlement cache used to gate MINTING a new per-tenant keypair on the
    /// `AuditAddon` (`f_audit_addon`) feature. `None` (e.g. Postgres-less dev)
    /// is permissive, matching the pre-gate behaviour.
    entitlements: Option<Arc<EntitlementCache>>,
}

impl TenantAuditKeyStore {
    /// Create a new key store backed by the given Postgres pool and BYOK master
    /// key. `entitlements` gates minting a new per-tenant keypair on the Audit
    /// SKU (`f_audit_addon`) — CLAUDE.md requires per-feature grants, not the
    /// plan-tier path, to be the entitlement mechanism. Pass `None` only where
    /// no entitlement cache exists.
    pub fn new(
        pool: Pool,
        byok: Arc<ByokMasterKey>,
        entitlements: Option<Arc<EntitlementCache>>,
    ) -> Self {
        Self {
            pool,
            byok,
            entitlements,
        }
    }

    /// R47 condition 2 — **prove the derived public half really verifies signatures made
    /// by the stored private key, BEFORE publishing it.**
    ///
    /// Founder ruling, and the reasoning is the point: *"a wrong pubkey is worse than an
    /// empty one — empty renders a visible degraded state, wrong renders a confident
    /// false green that fails only when a customer verifies."* An empty
    /// `public_key_b64` makes `/v1/audit/pubkey` return 200-with-nothing, which the
    /// verifier rejects loudly (`untrusted_tenant_key`). A WRONG one would be published
    /// as this workspace's trust root and would fail for an auditor, on their desk,
    /// against a ledger that is actually intact.
    ///
    /// `ring` derives the public half from the private key by construction, so a mismatch
    /// should be impossible — but "impossible by construction" is an assertion, and this
    /// is a round-trip PROOF: sign a fixed message with the private key, verify it with
    /// the derived public key. Costs one signature per pre-H1 row, once, at boot.
    fn derived_pubkey_verified(keypair: &TenantAuditKeypair) -> Option<String> {
        const PROBE: &[u8] = b"tracelane:r47:pubkey-derivation-selfcheck:v1";
        let pubkey_bytes = keypair.public_key_bytes();
        let sig = keypair.sign(PROBE);
        signature::UnparsedPublicKey::new(&signature::ED25519, &pubkey_bytes)
            .verify(PROBE, &sig)
            .ok()
            .map(|()| B64.encode(&pubkey_bytes))
    }

    /// R47 — publish the verification key for every pre-H1 row, at STARTUP.
    ///
    /// `get_or_create` heals a blank `public_key_b64` when the key is next USED, and that
    /// is not enough on its own: the tenant this exists for (`1bb14687`) is quiet and
    /// already fully anchored, so nothing would call `get_or_create` again and its
    /// `/v1/audit/pubkey` would keep answering **200 with an empty string** indefinitely.
    /// A defect that heals only on traffic does not heal for the tenants most likely to
    /// have it. This runs on every boot, is idempotent, and is a no-op once the fleet is
    /// clean — measured 2026-08-15: exactly 1 of 2 rows needs it.
    ///
    /// Returns the number of rows filled. **Infallible by design** — a fault-tolerance
    /// path: it must never prevent the gateway from booting or signing.
    pub async fn backfill_missing_public_keys(&self) -> usize {
        let Ok(client) = self.pool.get().await else {
            tracing::warn!("audit key backfill: no Postgres connection — skipping");
            return 0;
        };
        let rows = match client
            .query(
                "SELECT tenant_id, encrypted_private_key FROM tenant_audit_keys \
                 WHERE COALESCE(public_key_b64, '') = ''",
                &[],
            )
            .await
        {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(error = %err, "audit key backfill: query failed — skipping");
                return 0;
            }
        };
        let mut filled = 0usize;
        for row in rows {
            let uuid: uuid::Uuid = row.get(0);
            let encrypted: String = row.get(1);
            let tenant = TenantId::from_jwt_claim(uuid);
            // Derive, never re-key: the public half comes from the private key already
            // stored. No signature is recomputed; no historical row changes.
            let Ok(keypair) = self.decrypt_and_parse(tenant.clone(), &encrypted) else {
                tracing::warn!(
                    tenant_id = %tenant,
                    "audit key backfill: could not decrypt the stored private key — left as-is"
                );
                continue;
            };
            // R47 condition 2 — do not publish a key that cannot verify its own signature.
            let Some(derived) = Self::derived_pubkey_verified(&keypair) else {
                tracing::error!(
                    tenant_id = %tenant,
                    "audit key backfill: the derived public key FAILED to verify a signature \
                     made by the stored private key — REFUSING to publish it. The row is left \
                     empty, which is a visible degraded state; a wrong key would be a \
                     confident false green that only fails on the customer's desk."
                );
                continue;
            };
            match client
                .execute(
                    "UPDATE tenant_audit_keys SET public_key_b64 = $2 \
                     WHERE tenant_id = $1 AND COALESCE(public_key_b64, '') = ''",
                    &[&uuid, &derived],
                )
                .await
            {
                Ok(n) if n > 0 => {
                    filled += 1;
                    tracing::info!(
                        tenant_id = %tenant,
                        "audit key: published the verification key for a pre-H1 row"
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(
                    error = %err, tenant_id = %tenant,
                    "audit key backfill: UPDATE failed — /v1/audit/pubkey stays empty"
                ),
            }
        }
        filled
    }

    /// Retrieve or generate the Ed25519 keypair for `tenant_id`.
    ///
    /// If no keypair exists yet, one is generated and persisted atomically.
    /// Concurrent requests for the same tenant may both try to insert; the
    /// `ON CONFLICT DO NOTHING` ensures only one row lands.
    #[instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub async fn get_or_create(&self, tenant_id: &TenantId) -> Result<TenantAuditKeypair> {
        let client = self
            .pool
            .get()
            .await
            .context("acquire Postgres connection for tenant audit key")?;

        // Try loading existing key first.
        let row = client
            .query_opt(
                "SELECT encrypted_private_key, COALESCE(public_key_b64, '') \
                 FROM tenant_audit_keys WHERE tenant_id = $1",
                &[&tenant_id.as_uuid()],
            )
            .await
            .context("query tenant_audit_keys")?;

        if let Some(row) = row {
            let encrypted: String = row.get(0);
            let stored_pub: String = row.get(1);
            let keypair = self.decrypt_and_parse(tenant_id.clone(), &encrypted)?;

            // R47 — SELF-HEAL a pre-H1 row whose public half was never stored.
            //
            // `public_key_b64` was `DEFAULT ''` and written by nothing until the H1 fix
            // PRIVATE key and an EMPTY public one, so `GET /v1/audit/pubkey` answers
            // **200 with an empty string** — success-shaped, carrying nothing. An auditor
            // who follows the documented procedure and passes that to `--tenant-pubkey`
            // gets `untrusted_tenant_key`: a FALSE RED on an intact ledger.
            //
            // The public half is derivable from the private key we just decrypted, so
            // this re-derives rather than re-keys. **No signature is recomputed and no
            // history is touched** — every existing row keeps the exact signature it
            // already had, and this simply publishes the matching verification key.
            //
            // `WHERE public_key_b64 = ''` is load-bearing, not belt-and-braces: an UPDATE
            // that could overwrite a POPULATED pubkey would break verification for every
            // row signed under the old one. It can only ever fill a blank.
            if stored_pub.is_empty()
                && let Some(derived) = Self::derived_pubkey_verified(&keypair)
            {
                match client
                    .execute(
                        "UPDATE tenant_audit_keys SET public_key_b64 = $2 \
                         WHERE tenant_id = $1 AND COALESCE(public_key_b64, '') = ''",
                        &[&tenant_id.as_uuid(), &derived],
                    )
                    .await
                {
                    Ok(n) if n > 0 => tracing::info!(
                        tenant_id = %tenant_id,
                        "audit key: backfilled the missing public_key_b64 on a pre-H1 row \
                         (derived from the stored private key; no signature recomputed)"
                    ),
                    Ok(_) => {} // someone else filled it first — converged, nothing to do
                    Err(err) => {
                        // Fail-OPEN: signing must not break because a convenience mirror
                        // could not be written. The endpoint keeps returning empty until
                        // the next attempt, which is exactly today's behaviour.
                        tracing::warn!(
                            error = %err, tenant_id = %tenant_id,
                            "audit key: public_key_b64 backfill failed — /v1/audit/pubkey \
                             will keep returning an empty key for this tenant"
                        );
                    }
                }
            }
            return Ok(keypair);
        }

        // No key yet → about to MINT the per-tenant Ed25519 keypair, the Audit-SKU
        // artifact. Gate minting on `f_audit_addon` so it is not given away for
        // free (a tenant that already has a key, above, is always honoured). When
        // not entitled we error; the caller (`RekorClient::submit_for_tenant`)
        // falls back to the global signing key. No cache wired → permissive.
        if let Some(ents) = self.entitlements.as_ref() {
            if !ents
                .check(*tenant_id.as_uuid(), FeatureKey::AuditAddon)
                .await
            {
                anyhow::bail!(
                    "tenant not entitled to a per-tenant audit keypair (f_audit_addon); \
                     caller falls back to the global signing key"
                );
            }
        }

        // Generate and persist a new keypair.
        let keypair = TenantAuditKeypair::generate(tenant_id.clone())?;
        // R2 C-1: bind the ciphertext to (audit-key, tenant_id) via AAD
        // so a row swap into a different tenant's audit_keys table row
        // (or across the provider_keys table) fails GCM authentication.
        let aad = crate::byok::audit_key_aad(tenant_id);
        let encrypted = self
            .byok
            .encrypt_with_context(&keypair.private_key_der, &aad)
            .context("encrypt tenant audit keypair")?;

        // pin `audit_log.signing_pubkey` against a source outside ClickHouse's
        // blast radius (a CH-write attacker could otherwise forge a fresh keypair
        // and rewrite both the row signature and its inline pubkey). The row-inline
        // pubkey is a convenience mirror only; this Postgres row is the anchor.
        let public_key_b64 = B64.encode(keypair.public_key_bytes());
        client
            .execute(
                "INSERT INTO tenant_audit_keys (tenant_id, encrypted_private_key, public_key_b64, created_at) \
                 VALUES ($1, $2, $3, NOW()) \
                 ON CONFLICT (tenant_id) DO NOTHING",
                &[&tenant_id.as_uuid(), &encrypted, &public_key_b64],
            )
            .await
            .context("insert tenant_audit_keys")?;

        // per-tenant pubkeys): `ON CONFLICT DO NOTHING` means a racing request may
        // have persisted a DIFFERENT keypair first. Re-load the row so ALL
        // concurrent first-users converge on the ONE persisted key; otherwise an
        // event signs with a key that isn't in Postgres and the verifier's H1 pin
        // (pubkey from `tenant_audit_keys`) false-negatives that row.
        let persisted = client
            .query_opt(
                "SELECT encrypted_private_key FROM tenant_audit_keys WHERE tenant_id = $1",
                &[&tenant_id.as_uuid()],
            )
            .await
            .context("re-load tenant_audit_keys after insert")?;
        if let Some(row) = persisted {
            let encrypted: String = row.get(0);
            tracing::info!("minted or converged on the persisted Ed25519 audit keypair");
            return self.decrypt_and_parse(tenant_id.clone(), &encrypted);
        }

        // AUDIT-004 hardening (2026-08-09). This used to `Ok(keypair)` — returning the
        // LOCAL, NEVER-PERSISTED keypair. That is the original AUDIT-004 defect in its
        // last remaining form: a caller signing with a key absent from Postgres, so the
        // verifier's H1 pin (pubkey read from `tenant_audit_keys`) false-negatives every
        // row it signs, permanently, because the ledger is append-only.
        //
        // The re-load above cannot legitimately miss after the INSERT — either we won and
        // the row is ours, or we lost and it is the winner's. Reaching here means the row
        // vanished between the two statements, which is not a state we should paper over.
        // FAIL CLOSED (CLAUDE.md rule 10 — this is a security path); the caller falls back
        // to the global signing key, which IS verifiable. Matches `get_or_create_anchor`,
        // which has always bailed here.
        anyhow::bail!(
            "tenant_audit_keys row vanished between INSERT and re-load — refusing to sign \
             with a keypair that is not persisted (AUDIT-004)"
        )
    }

    /// Retrieve or generate the tenant's ECDSA-P256 **anchor** keypair (ADR-062).
    ///
    /// Precondition: the tenant's `tenant_audit_keys` row already exists — the
    /// Ed25519 [`get_or_create`](Self::get_or_create) creates it, and the anchor
    /// flow always mints the Ed25519 key first. Minting the anchor key is gated on
    /// the same Audit-SKU entitlement (`f_audit_addon`); an existing anchor key is
    /// always honoured.
    ///
    /// conditional `UPDATE ... WHERE encrypted_anchor_key IS NULL` lets only the
    /// first land, then a re-load converges every caller on the ONE persisted key.
    #[instrument(skip(self), fields(tenant_id = %tenant_id))]
    pub async fn get_or_create_anchor(&self, tenant_id: &TenantId) -> Result<TenantAnchorKeypair> {
        let client = self
            .pool
            .get()
            .await
            .context("acquire Postgres connection for tenant anchor key")?;

        // Existing anchor key?
        let row = client
            .query_opt(
                "SELECT encrypted_anchor_key FROM tenant_audit_keys \
                 WHERE tenant_id = $1 AND encrypted_anchor_key IS NOT NULL",
                &[&tenant_id.as_uuid()],
            )
            .await
            .context("query tenant_audit_keys anchor key")?;
        if let Some(row) = row {
            let encrypted: String = row.get(0);
            return self.decrypt_and_parse_anchor(tenant_id.clone(), &encrypted);
        }

        // No anchor key yet → MINT (Audit-SKU gated, same as the Ed25519 mint).
        if let Some(ents) = self.entitlements.as_ref() {
            if !ents
                .check(*tenant_id.as_uuid(), FeatureKey::AuditAddon)
                .await
            {
                anyhow::bail!("tenant not entitled to a per-tenant anchor keypair (f_audit_addon)");
            }
        }

        let keypair = TenantAnchorKeypair::generate(tenant_id.clone())?;
        // Distinct `anchor-key:` AAD (R2 C-1): an anchor-key ciphertext can never be
        // swapped into the Ed25519 signing-key slot and still authenticate.
        let aad = crate::byok::anchor_key_aad(tenant_id);
        let encrypted = self
            .byok
            .encrypt_with_context(&keypair.private_key_der, &aad)
            .context("encrypt tenant anchor keypair")?;
        let pubkey_spki_b64 = B64.encode(keypair.public_key_spki_der());

        // Conditional UPDATE — only the first racing writer sets the column. The
        // row already exists (Ed25519 key minted first). If it somehow does not,
        // 0 rows update and the re-load below returns None → error → caller falls
        // back (batch left unanchored).
        client
            .execute(
                "UPDATE tenant_audit_keys \
                 SET encrypted_anchor_key = $2, anchor_pubkey_spki_b64 = $3 \
                 WHERE tenant_id = $1 AND encrypted_anchor_key IS NULL",
                &[&tenant_id.as_uuid(), &encrypted, &pubkey_spki_b64],
            )
            .await
            .context("persist tenant anchor keypair")?;

        // Re-load so all concurrent minters converge on the ONE persisted key.
        let persisted = client
            .query_opt(
                "SELECT encrypted_anchor_key FROM tenant_audit_keys \
                 WHERE tenant_id = $1 AND encrypted_anchor_key IS NOT NULL",
                &[&tenant_id.as_uuid()],
            )
            .await
            .context("re-load tenant anchor key after mint")?;
        match persisted {
            Some(row) => {
                let encrypted: String = row.get(0);
                self.decrypt_and_parse_anchor(tenant_id.clone(), &encrypted)
            }
            None => anyhow::bail!(
                "tenant_audit_keys row missing — the Ed25519 key must be minted before the anchor key"
            ),
        }
    }

    fn decrypt_and_parse_anchor(
        &self,
        tenant_id: TenantId,
        encrypted: &str,
    ) -> Result<TenantAnchorKeypair> {
        let aad = crate::byok::anchor_key_aad(&tenant_id);
        let private_key_der = self
            .byok
            .decrypt_with_context(encrypted, &aad)
            .context("decrypt tenant anchor private key")?;
        let mut raw_der = B64
            .decode(private_key_der.expose_secret())
            .context("base64-decode tenant anchor private key DER")?;
        let result = TenantAnchorKeypair::from_pkcs8_der(tenant_id, &raw_der);
        raw_der.zeroize(); // scrub the transient plaintext DER heap window
        result
    }

    fn decrypt_and_parse(
        &self,
        tenant_id: TenantId,
        encrypted: &str,
    ) -> Result<TenantAuditKeypair> {
        // R2 C-1: same AAD context as encrypt site.
        let aad = crate::byok::audit_key_aad(&tenant_id);
        let private_key_der = self
            .byok
            .decrypt_with_context(encrypted, &aad)
            .context("decrypt tenant audit private key")?;
        let mut raw_der = B64
            .decode(private_key_der.expose_secret())
            .context("base64-decode tenant audit private key DER")?;
        let parsed = signature::Ed25519KeyPair::from_pkcs8(&raw_der);
        raw_der.zeroize(); // scrub the transient plaintext DER heap window
        let key_pair =
            parsed.map_err(|e| anyhow::anyhow!("parse tenant Ed25519 keypair: {e:?}"))?;
        Ok(TenantAuditKeypair {
            tenant_id,
            private_key_der,
            key_pair: Arc::new(key_pair),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap())
    }

    /// **AUDIT-004 — the `get_or_create` keypair race, driven for real.**
    ///
    /// re-load), but NOTHING proved the convergence property — so a refactor could have
    /// deleted the re-load and no gate would have noticed. A fix without falsification is
    /// not a fix you can rely on.
    ///
    /// This is NOT a mocked race: two tasks call the real `get_or_create` concurrently on
    /// a genuinely fresh tenant, against a live Postgres, on a multi-thread runtime. The
    /// defect being excluded is that the LOSER returns its own locally-generated keypair —
    /// which would then sign audit rows with a key absent from Postgres, permanently
    /// false-negativing the verifier's H1 pin on an append-only ledger.
    ///
    /// Asserts BOTH halves, because either alone is satisfiable by a broken
    /// implementation: exactly ONE row persists (the DB converged) AND both callers hold
    /// the SAME public key (the callers converged). A version that persists one row while
    /// handing the loser its local copy passes the first and fails the second — that is
    /// precisely AUDIT-004.
    ///
    ///   POSTGRES_TEST_URL=postgres://… TRACELANE_BYOK_MASTER_KEY=… \
    ///     cargo test -p gateway --bin gateway audit004 -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn audit004_concurrent_get_or_create_converges_on_one_persisted_key() {
        let Ok(url) = std::env::var("POSTGRES_TEST_URL") else {
            eprintln!("skip audit004: POSTGRES_TEST_URL unset");
            return;
        };
        let Ok(Some(byok)) = crate::byok::ByokMasterKey::from_env() else {
            eprintln!("skip audit004: TRACELANE_BYOK_MASTER_KEY unset");
            return;
        };

        let pg: tokio_postgres::Config = url.parse().expect("POSTGRES_TEST_URL parses");
        let mut cfg = deadpool_postgres::Config::new();
        cfg.host = pg.get_hosts().first().and_then(|h| match h {
            tokio_postgres::config::Host::Tcp(s) => Some(s.clone()),
            _ => None,
        });
        cfg.port = pg.get_ports().first().copied();
        cfg.user = pg.get_user().map(str::to_string);
        // Dropping the password yields deadpool's opaque "invalid configuration" at
        // pool-create, not at connect — caught by actually RUNNING this test rather
        // than shipping it #[ignore]d and unproven.
        cfg.password = pg
            .get_password()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        cfg.dbname = pg.get_dbname().map(str::to_string);
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .expect("test pool");
        // Tolerate an ALREADY-migrated database. `apply_migrations` is not safely
        // re-runnable — a second call against the same Postgres dies on
        // `type "cmk_algorithm" already exists` — so an unconditional `.expect()` makes
        // this test pass exactly once and fail on every re-run. What the test needs is
        // the SCHEMA, not to be the one who created it: assert the table is there.
        if let Err(e) = crate::db::apply_migrations(&pool).await {
            eprintln!("apply_migrations: {e:#} (continuing — DB may already be migrated)");
        }
        {
            let c = pool.get().await.expect("pg connection");
            let n: i64 = c
                .query_one(
                    "SELECT count(*) FROM information_schema.tables \
                     WHERE table_schema='public' AND table_name='tenant_audit_keys'",
                    &[],
                )
                .await
                .expect("schema probe")
                .get(0);
            assert_eq!(n, 1, "tenant_audit_keys must exist before the race runs");
        }

        // A FRESH tenant — the race only exists on the very first mint.
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        {
            let c = pool.get().await.unwrap();
            c.execute(
                "INSERT INTO tenants (id, workos_org_id) VALUES ($1, $2) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    tenant.as_uuid(),
                    &format!("org-audit004-{}", Uuid::new_v4()),
                ],
            )
            .await
            .unwrap();
        }

        // entitlements: None => the Audit-SKU gate is permissive, so both racers reach
        // the mint. Two INDEPENDENT stores so nothing in-process serializes them; only
        // Postgres does.
        let byok = Arc::new(byok);
        let a = TenantAuditKeyStore::new(pool.clone(), Arc::clone(&byok), None);
        let b = TenantAuditKeyStore::new(pool.clone(), Arc::clone(&byok), None);

        let (ta, tb) = (tenant.clone(), tenant.clone());
        let (ra, rb) = tokio::join!(
            tokio::spawn(async move { a.get_or_create(&ta).await.map(|k| k.public_key_bytes()) }),
            tokio::spawn(async move { b.get_or_create(&tb).await.map(|k| k.public_key_bytes()) }),
        );
        let pk_a = ra.expect("task a").expect("get_or_create a");
        let pk_b = rb.expect("task b").expect("get_or_create b");

        let client = pool.get().await.unwrap();
        let rows: i64 = client
            .query_one(
                "SELECT count(*) FROM tenant_audit_keys WHERE tenant_id = $1",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(rows, 1, "exactly one keypair row must persist for a tenant");

        assert_eq!(
            pk_a, pk_b,
            "AUDIT-004: concurrent first-callers must converge on the SAME persisted \
             keypair. Differing keys mean the loser kept its local, never-persisted key \
             and would sign audit rows the verifier can never pin."
        );

        // And the key both callers hold must be the one Postgres actually stores —
        // convergence on a shared-but-unpersisted key would still break the H1 pin.
        let stored: String = client
            .query_one(
                "SELECT public_key_b64 FROM tenant_audit_keys WHERE tenant_id = $1",
                &[tenant.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            stored,
            B64.encode(&pk_a),
            "the converged key must be the PERSISTED one (verifier H1 pin reads this row)"
        );
    }

    #[test]
    fn generate_and_sign() {
        let tenant = test_tenant();
        let kp = TenantAuditKeypair::generate(tenant).unwrap();
        let msg = b"test Merkle root hex string";
        let sig = kp.sign(msg);
        assert_eq!(sig.len(), 64, "Ed25519 signatures are always 64 bytes");
    }

    #[test]
    fn public_key_length() {
        let tenant = test_tenant();
        let kp = TenantAuditKeypair::generate(tenant).unwrap();
        let pub_key = kp.public_key_bytes();
        assert_eq!(pub_key.len(), 32, "Ed25519 public keys are always 32 bytes");
    }

    #[test]
    fn different_keys_per_generate() {
        let tenant = test_tenant();
        let kp1 = TenantAuditKeypair::generate(tenant.clone()).unwrap();
        let kp2 = TenantAuditKeypair::generate(tenant).unwrap();
        assert_ne!(
            kp1.public_key_bytes(),
            kp2.public_key_bytes(),
            "each generate() call must produce a unique keypair"
        );
    }

    // ---- ECDSA-P256 anchor keypair (ADR-062) ---------------------------

    #[test]
    fn anchor_generate_sign_and_verify_roundtrip() {
        // The full chain the verifier will exercise: sign the ANCHOR_ARTIFACT,
        // rebuild the SPKI, extract the point, verify the DER sig with ring.
        let kp = TenantAnchorKeypair::generate(test_tenant()).unwrap();
        let msg = b"tracelane-anchor-ecdsa-v1\x00\x11\x22\x33 merkle-root-bytes";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig[0], 0x30, "ECDSA sig must be DER (ASN.1 SEQUENCE)");
        let spki = kp.public_key_spki_der();
        let point = &spki[P256_SPKI_PREFIX.len()..]; // 65-byte uncompressed point
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            point,
        );
        pk.verify(msg, &sig)
            .expect("ECDSA anchor sig must verify against the reconstructed SPKI point");
    }

    #[test]
    fn anchor_spki_is_well_formed_p256() {
        let spki = TenantAnchorKeypair::generate(test_tenant())
            .unwrap()
            .public_key_spki_der();
        assert_eq!(
            spki.len(),
            91,
            "P-256 SPKI = 26-byte prefix + 65-byte point"
        );
        assert_eq!(&spki[..2], &[0x30, 0x59], "outer SEQUENCE, length 89");
        assert_eq!(
            spki[P256_SPKI_PREFIX.len()],
            0x04,
            "point starts with the uncompressed marker 0x04"
        );
    }

    #[test]
    fn anchor_keys_are_unique_per_generate() {
        let a = TenantAnchorKeypair::generate(test_tenant()).unwrap();
        let b = TenantAnchorKeypair::generate(test_tenant()).unwrap();
        assert_ne!(
            a.public_key_spki_der(),
            b.public_key_spki_der(),
            "each anchor generate() must produce a unique keypair"
        );
    }
}
