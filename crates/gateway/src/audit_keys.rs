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
                "SELECT encrypted_private_key FROM tenant_audit_keys WHERE tenant_id = $1",
                &[&tenant_id.as_uuid()],
            )
            .await
            .context("query tenant_audit_keys")?;

        if let Some(row) = row {
            let encrypted: String = row.get(0);
            return self.decrypt_and_parse(tenant_id.clone(), &encrypted);
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
            return self.decrypt_and_parse(tenant_id.clone(), &encrypted);
        }

        tracing::info!("generated new Ed25519 audit keypair for tenant");
        Ok(keypair)
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
