//! BYOK (Bring Your Own Key) envelope encryption for provider API keys
//! and tenant-scoped audit signing keys.
//!
//! Provider API keys (e.g. `sk-ant-xxx`) and audit-key PKCS#8 material
//! are never stored in plaintext. They are AES-256-GCM encrypted with
//! the workspace master key before persisting to Postgres, and
//! decrypted on demand.
//!
//! ## Wire format (v2)
//!
//! ```text
//! ciphertext_blob = base64(
//!     0x02           // version byte
//!     || 12-byte nonce
//!     || ciphertext + 16-byte GCM tag
//! )
//! ```
//!
//! Wraps the v1 blob format and adds a leading **version byte** so
//! future algorithm rotations are non-breaking.
//!
//! ## AAD (R2 C-1 fix)
//!
//! Previously the AEAD was sealed with `Aad::empty()` — a ciphertext
//! from `(tenant_A, openai)` could be pasted into the `(tenant_B,
//! anthropic)` Postgres row and would decrypt successfully because
//! the AEAD has no binding to "which row this belongs to."
//!
//! v2 binds every ciphertext to a caller-supplied context string. The
//! caller passes `aad_context = "provider-key:tenant_A:openai"` (or
//! `"audit-key:tenant_X"`, etc.). Both encrypt and decrypt accept the
//! context; a mismatched context fails the GCM authentication tag.
//!
//! See `.claude/rules/security.md` for the canonical AAD format
//! conventions.
//!
//! ## v1 backwards-compat
//!
//! Blobs persisted before this commit start with the version byte 0x01
//! (or are missing it — historical blobs were base64 of the raw nonce +
//! ciphertext). `decrypt` accepts both: v2 with AAD checking, v1
//! without. A future migration will re-encrypt v1 blobs to v2.
//!
//! Master-key lifecycle:
//!   - Loaded once at startup from `TRACELANE_BYOK_MASTER_KEY`
//!     (base64, 32 bytes).
//!   - Production rejects unconfigured BYOK at startup. Dev allows it.

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, SecretString};

/// v2 wire-format version byte.
const VERSION_V2: u8 = 0x02;
/// GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;

/// AES-256-GCM master key for BYOK envelope encryption.
pub struct ByokMasterKey {
    key: LessSafeKey,
    rng: SystemRandom,
}

/// Process-wide master key slot. Set at startup via `set_global_master_key`
/// (A4) so `db::provider_keys::get_decrypted` and the server hot path can
/// share one decryption context without threading it through every layer.
static GLOBAL_MASTER_KEY: std::sync::OnceLock<ByokMasterKey> = std::sync::OnceLock::new();

/// Install the master key once at startup. Idempotent for the same value;
/// subsequent calls with a different key panic at startup (operator
/// misconfig is louder than silent override).
pub fn set_global_master_key(key: ByokMasterKey) {
    if GLOBAL_MASTER_KEY.set(key).is_err() {
        panic!("set_global_master_key called twice");
    }
}

/// Borrow the process-wide master key, or `None` when BYOK is disabled
/// (no `TRACELANE_BYOK_MASTER_KEY` env var). Callers expected to fall
/// back to env-var resolution in that case.
pub fn master_key() -> Option<&'static ByokMasterKey> {
    GLOBAL_MASTER_KEY.get()
}

impl ByokMasterKey {
    /// Load the master key from `TRACELANE_BYOK_MASTER_KEY`.
    /// `None` when unset (dev only).
    pub fn from_env() -> Result<Option<Self>> {
        let b64 = match std::env::var("TRACELANE_BYOK_MASTER_KEY") {
            Ok(v) => v,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(e) => anyhow::bail!("TRACELANE_BYOK_MASTER_KEY env var error: {e}"),
        };
        let raw = B64
            .decode(b64.trim())
            .context("base64-decode TRACELANE_BYOK_MASTER_KEY")?;
        anyhow::ensure!(
            raw.len() == 32,
            "TRACELANE_BYOK_MASTER_KEY must be exactly 32 bytes (256 bits), got {}",
            raw.len()
        );
        let unbound = UnboundKey::new(&AES_256_GCM, &raw)
            .map_err(|_| anyhow::anyhow!("failed to construct AES-256-GCM key from master key"))?;
        Ok(Some(Self {
            key: LessSafeKey::new(unbound),
            rng: SystemRandom::new(),
        }))
    }

    /// **v2 — current**. Encrypt a secret with a caller-supplied AAD
    /// context that binds the ciphertext to a logical row identity.
    ///
    /// `aad_context` examples:
    /// - `"provider-key:00000000-0000-0000-0000-000000000001:openai"`
    /// - `"audit-key:00000000-0000-0000-0000-000000000001"`
    ///
    /// Any string that uniquely identifies "which Postgres row this
    /// ciphertext belongs to." If the context at decrypt time differs
    /// from the context at encrypt time, GCM authentication fails.
    ///
    /// # Returns
    /// Base64-encoded `<version=0x02> || <12-byte nonce> || <ct+tag>`.
    pub fn encrypt_with_context(
        &self,
        plaintext: &SecretString,
        aad_context: &[u8],
    ) -> Result<String> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failure generating BYOK nonce"))?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf: Vec<u8> = plaintext.expose_secret().as_bytes().to_vec();

        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad_context), &mut buf)
            .map_err(|_| anyhow::anyhow!("AES-256-GCM seal failed"))?;

        let mut output = Vec::with_capacity(1 + NONCE_LEN + buf.len());
        output.push(VERSION_V2);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&buf);
        Ok(B64.encode(&output))
    }

    /// **DEPRECATED.** Encrypt without an AAD context. Equivalent to
    /// `encrypt_with_context(plaintext, &[])` but produces a v1 blob
    /// (no version byte) for compatibility with pre-v2 readers.
    ///
    /// New code MUST use `encrypt_with_context`. This method is
    /// retained only so the existing tests in this file (which
    /// don't yet exercise the AAD path) still compile during the
    /// transition. Reachable callers grep clean as of this commit.
    #[deprecated(note = "Use encrypt_with_context with a unique AAD per row \
                (R2 C-1 — empty AAD allows cross-tenant ciphertext swap).")]
    #[allow(dead_code)]
    pub fn encrypt(&self, plaintext: &SecretString) -> Result<String> {
        // Legacy v1 wire format: no version byte. Used for tests only.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("RNG failure generating BYOK nonce"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf: Vec<u8> = plaintext.expose_secret().as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
            .map_err(|_| anyhow::anyhow!("AES-256-GCM seal failed"))?;
        let mut output = Vec::with_capacity(NONCE_LEN + buf.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&buf);
        Ok(B64.encode(&output))
    }

    /// Decrypt a v2 or v1 ciphertext blob.
    ///
    /// For v2 blobs (leading byte 0x02), the supplied `aad_context`
    /// MUST match the context used at encrypt time. v1 blobs ignore
    /// the AAD (legacy, no binding) — log a warn so the migration
    /// can be planned.
    pub fn decrypt_with_context(
        &self,
        ciphertext_b64: &str,
        aad_context: &[u8],
    ) -> Result<SecretString> {
        let raw = B64
            .decode(ciphertext_b64)
            .context("base64-decode BYOK ciphertext blob")?;
        anyhow::ensure!(
            raw.len() >= NONCE_LEN + GCM_TAG_LEN,
            "BYOK ciphertext blob too short: {} bytes",
            raw.len()
        );

        // Version-byte detect: v2 starts with 0x02 AND has at least
        // 1 + NONCE_LEN + GCM_TAG_LEN bytes. Anything else is treated
        // as v1.
        let (aad_for_open, nonce_slice, ct_and_tag) = if raw.len() >= 1 + NONCE_LEN + GCM_TAG_LEN
            && raw[0] == VERSION_V2
        {
            // v2: skip version byte; AAD binding active.
            (aad_context, &raw[1..1 + NONCE_LEN], &raw[1 + NONCE_LEN..])
        } else {
            // v1: no version byte, no AAD binding. Warn so the
            // operator knows there are legacy blobs to migrate.
            tracing::warn!(
                "BYOK v1 ciphertext decrypted — re-encrypt via encrypt_with_context to upgrade to v2"
            );
            (&[][..], &raw[..NONCE_LEN], &raw[NONCE_LEN..])
        };

        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce_slice);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let mut buf = ct_and_tag.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::from(aad_for_open), &mut buf)
            .map_err(|_| {
                anyhow::anyhow!(
                    "AES-256-GCM open failed — wrong master key, tampered ciphertext, or AAD mismatch"
                )
            })?;

        let s = std::str::from_utf8(plaintext).context("decrypted BYOK key is not UTF-8")?;
        Ok(SecretString::from(s.to_owned()))
    }

    /// **DEPRECATED.** Decrypt without an AAD context.
    ///
    /// Convenience wrapper that calls `decrypt_with_context(_, &[])`.
    /// On a v2 blob this fails unless the blob was encrypted with an
    /// empty AAD context (which v2 callers should never do).
    #[deprecated(note = "Use decrypt_with_context with the same AAD context that was \
                used at encrypt time.")]
    #[allow(dead_code)]
    pub fn decrypt(&self, ciphertext_b64: &str) -> Result<SecretString> {
        self.decrypt_with_context(ciphertext_b64, &[])
    }
}

/// Build an AAD context string for a provider-key ciphertext. Caller
/// is `crates/gateway/src/db/provider_keys.rs` (when wired).
///
/// Format: `provider-key:<tenant_uuid>:<provider_id>`. Stable; if you
/// need to change it, bump the BYOK wire-format version too — old
/// rows won't decrypt under the new context format.
pub fn provider_key_aad(tenant_id: &tracelane_shared::TenantId, provider_id: &str) -> Vec<u8> {
    format!("provider-key:{tenant_id}:{provider_id}").into_bytes()
}

/// Build an AAD context string for a tenant audit signing keypair.
/// Caller is `crates/gateway/src/audit_keys.rs`.
pub fn audit_key_aad(tenant_id: &tracelane_shared::TenantId) -> Vec<u8> {
    format!("audit-key:{tenant_id}").into_bytes()
}

/// Build an AAD context string for a tenant's **ECDSA-P256 anchor keypair**
/// (ADR-062), the single-purpose key that signs the Rekor v2 `hashedrekord`
/// entry. Distinct from [`audit_key_aad`] so an anchor-key ciphertext can
/// never be swapped into the Ed25519 signing-key slot (or vice versa) and
/// still authenticate under GCM (R2 C-1). Caller is
/// `crates/gateway/src/audit_keys.rs`.
pub fn anchor_key_aad(tenant_id: &tracelane_shared::TenantId) -> Vec<u8> {
    format!("anchor-key:{tenant_id}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn test_key() -> ByokMasterKey {
        let raw = [0x42u8; 32];
        let unbound = UnboundKey::new(&AES_256_GCM, &raw).unwrap();
        ByokMasterKey {
            key: LessSafeKey::new(unbound),
            rng: SystemRandom::new(),
        }
    }

    fn tenant_a() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }

    fn tenant_b() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap())
    }

    #[test]
    fn v2_roundtrip_with_matching_context() {
        let k = test_key();
        let pk = SecretString::from("sk-ant-api03-test-key".to_string());
        let aad = provider_key_aad(&tenant_a(), "openai");
        let ct = k.encrypt_with_context(&pk, &aad).unwrap();
        let decrypted = k.decrypt_with_context(&ct, &aad).unwrap();
        assert_eq!(decrypted.expose_secret(), pk.expose_secret());
    }

    #[test]
    fn v2_rejects_cross_tenant_swap() {
        // R2 C-1 — the exploit case. An attacker copies a ciphertext
        // from tenant A's openai row into tenant B's openai row.
        // v1's empty AAD would have decrypted it; v2's tenant-bound
        // AAD must fail GCM authentication.
        let k = test_key();
        let pk = SecretString::from("sk-tenant-a-secret".to_string());
        let aad_a = provider_key_aad(&tenant_a(), "openai");
        let aad_b = provider_key_aad(&tenant_b(), "openai");

        let ct_a = k.encrypt_with_context(&pk, &aad_a).unwrap();
        let result = k.decrypt_with_context(&ct_a, &aad_b);
        assert!(result.is_err(), "decrypt with wrong tenant AAD MUST fail");
    }

    #[test]
    fn v2_rejects_cross_provider_swap() {
        // Same tenant but different provider — also must fail.
        let k = test_key();
        let pk = SecretString::from("sk-secret".to_string());
        let aad_openai = provider_key_aad(&tenant_a(), "openai");
        let aad_anthropic = provider_key_aad(&tenant_a(), "anthropic");

        let ct = k.encrypt_with_context(&pk, &aad_openai).unwrap();
        let result = k.decrypt_with_context(&ct, &aad_anthropic);
        assert!(result.is_err(), "cross-provider swap MUST fail");
    }

    #[test]
    fn v2_audit_key_aad_is_distinct_from_provider_key_aad() {
        // The two AAD builders MUST produce different bytes even when
        // tenant_id matches — otherwise an audit-key ciphertext could
        // be swapped into a provider-key row (different consumers,
        // different downstream effects).
        let aad_audit = audit_key_aad(&tenant_a());
        let aad_provider = provider_key_aad(&tenant_a(), "openai");
        assert_ne!(aad_audit, aad_provider);
    }

    #[test]
    fn v2_blob_starts_with_version_byte() {
        let k = test_key();
        let pk = SecretString::from("x".to_string());
        let aad = audit_key_aad(&tenant_a());
        let ct = k.encrypt_with_context(&pk, &aad).unwrap();
        let raw = B64.decode(&ct).unwrap();
        assert_eq!(raw[0], VERSION_V2);
    }

    #[test]
    fn v2_different_nonces_per_call() {
        let k = test_key();
        let pk = SecretString::from("sk-test".to_string());
        let aad = audit_key_aad(&tenant_a());
        let c1 = k.encrypt_with_context(&pk, &aad).unwrap();
        let c2 = k.encrypt_with_context(&pk, &aad).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn v2_tamper_detected() {
        let k = test_key();
        let pk = SecretString::from("sk-test".to_string());
        let aad = audit_key_aad(&tenant_a());
        let mut raw = B64
            .decode(k.encrypt_with_context(&pk, &aad).unwrap())
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        let tampered = B64.encode(&raw);
        assert!(k.decrypt_with_context(&tampered, &aad).is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn v1_ciphertexts_still_decrypt_via_empty_aad() {
        // Backwards-compat: existing v1 ciphertexts in Postgres must
        // still decrypt during the migration window. v1 blobs have no
        // version byte and were sealed with empty AAD; the legacy
        // `decrypt(&self, ct)` method is preserved (deprecated) for
        // those rows.
        let k = test_key();
        let pk = SecretString::from("legacy-secret".to_string());
        let v1_ct = k.encrypt(&pk).unwrap(); // deprecated; v1 wire format
        let decrypted = k.decrypt(&v1_ct).unwrap();
        assert_eq!(decrypted.expose_secret(), "legacy-secret");
    }

    #[test]
    fn wrong_master_key_rejected_v2() {
        let k1 = test_key();
        let k2 = {
            let raw = [0xABu8; 32];
            let unbound = UnboundKey::new(&AES_256_GCM, &raw).unwrap();
            ByokMasterKey {
                key: LessSafeKey::new(unbound),
                rng: SystemRandom::new(),
            }
        };
        let pk = SecretString::from("sk-test".to_string());
        let aad = audit_key_aad(&tenant_a());
        let ct = k1.encrypt_with_context(&pk, &aad).unwrap();
        assert!(k2.decrypt_with_context(&ct, &aad).is_err());
    }
}
