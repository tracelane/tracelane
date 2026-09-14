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
//!
//! ```
//!
//! Wraps the v1 blob format and adds a leading **version byte** so
//! future algorithm rotations are non-breaking.
//!
//! ## Wire format (v3) — B-383 (a), 2026-09-12: a KEK id, so the key can ROTATE
//!
//! ```text
//! ciphertext_blob = base64(
//!     0x03           // version byte
//!     || kek_id      // 1 byte — which master key sealed this blob
//!     || 12-byte nonce
//!     || ciphertext + 16-byte GCM tag
//! )
//! ```
//!
//! Until v3 there was ONE process-wide master key and no id anywhere in the
//! blob: a new key could not decrypt old rows and nothing re-wrapped them, so
//! the key could never be rotated — a compromised KEK stayed the KEK. Now the
//! process holds a **ring** of keys by id, encrypts under the ACTIVE one, and
//! decrypts under whichever id the blob names. A v2 blob has no id and is, by
//! definition, KEK 0 (the only key that ever existed before v3).
//!
//! Configuration:
//!   - `TRACELANE_BYOK_MASTER_KEY` (base64, 32 bytes) — the legacy single key,
//!     loaded as KEK **0**. Still sufficient on its own; a ring built from it
//!     ALONE keeps writing **v2** blobs so a rollback to a pre-v3 gateway can
//!     still read everything written in between.
//!   - `TRACELANE_BYOK_MASTER_KEYS` = `<id>:<base64>,<id>:<base64>,…` — the
//!     ring. May include `0:` (or leave KEK 0 to the legacy var). When set,
//!     new blobs are **v3**.
//!   - `TRACELANE_BYOK_ACTIVE_KEK` — the id new encryptions use. Defaults to the
//!     HIGHEST id in the ring. Must name a loaded key (boot refusal otherwise).
//!
//! Rotation is `gateway byok-rotate` (see `crates/gateway/src/byok_rotate.rs`
//! and `runbooks/byok-kek-rotation.md`): add the new key to the ring, make it
//! active, deploy, re-wrap every row, then drop the old key from the ring.
//!
//! ## AAD (fix)
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
//! ## v1 is REJECTED (migration closed 2026-07-22)
//!
//! Historical v1 blobs (no version byte, empty AAD) are no longer
//! decryptable: prod was verified to hold zero v1 rows (provider_keys
//! and tenant_audit_keys all v2), so `decrypt_with_context` fails
//! closed on anything without the 0x02 version byte.
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
/// v3 wire-format version byte (v2 + a KEK id byte).
const VERSION_V3: u8 = 0x03;
/// GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;
/// The id a v2 blob (no id byte) is sealed under, by definition.
pub const LEGACY_KEK_ID: u8 = 0;

/// The KEK ring: every master key the process can DECRYPT under, by id, and
/// the one it ENCRYPTS under. See the module doc for the wire formats.
///
/// `Debug` prints the ids and the active id — never key material (the keys are
/// `ring::LessSafeKey`s, which carry no `Debug` of their bytes either).
pub struct ByokMasterKey {
    keys: std::collections::BTreeMap<u8, LessSafeKey>,
    active: u8,
    /// `true` once `TRACELANE_BYOK_MASTER_KEYS` is configured: new blobs carry
    /// the id byte (v3). A legacy-only ring keeps writing v2 for rollback safety.
    write_v3: bool,
    rng: SystemRandom,
}

/// Process-wide master key slot. Set at startup via `set_global_master_key`
/// (A4) so `db::provider_keys::get_decrypted` and the server hot path can
/// share one decryption context without threading it through every layer.
///
/// B-386: stays global — it must be reachable from `db::provider_keys::get_decrypted`,
/// which has no state handle, and moving it means threading a handle through the
/// BYOK API routes; deferred to the KEK-id work that touches the same code.
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

impl std::fmt::Debug for ByokMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ByokMasterKey")
            .field("keks", &self.loaded_keks())
            .field("active", &self.active)
            .field("write_v3", &self.write_v3)
            .finish_non_exhaustive()
    }
}

impl ByokMasterKey {
    /// Load the ring from the environment (`TRACELANE_BYOK_MASTER_KEY` as KEK 0,
    /// `TRACELANE_BYOK_MASTER_KEYS` as `id:base64,…`, `TRACELANE_BYOK_ACTIVE_KEK`).
    /// `None` when neither key variable is set (dev only).
    ///
    /// # Errors
    /// Fail-CLOSED on any malformed value: a key that is not 32 bytes, a
    /// duplicate id, an active id that is not loaded. A gateway that boots with
    /// half a ring would silently refuse every BYOK decrypt under the missing id.
    pub fn from_env() -> Result<Option<Self>> {
        let legacy = match std::env::var("TRACELANE_BYOK_MASTER_KEY") {
            Ok(v) => Some(v),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => anyhow::bail!("TRACELANE_BYOK_MASTER_KEY env var error: {e}"),
        };
        let ring = match std::env::var("TRACELANE_BYOK_MASTER_KEYS") {
            Ok(v) => Some(v),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => anyhow::bail!("TRACELANE_BYOK_MASTER_KEYS env var error: {e}"),
        };
        let active = match std::env::var("TRACELANE_BYOK_ACTIVE_KEK") {
            Ok(v) => Some(
                v.trim()
                    .parse::<u8>()
                    .context("TRACELANE_BYOK_ACTIVE_KEK must be an integer 0–255")?,
            ),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => anyhow::bail!("TRACELANE_BYOK_ACTIVE_KEK env var error: {e}"),
        };
        Self::from_values(legacy.as_deref(), ring.as_deref(), active)
    }

    /// The pure form of [`Self::from_env`], for tests and the rotate command.
    pub fn from_values(
        legacy_b64: Option<&str>,
        ring: Option<&str>,
        active: Option<u8>,
    ) -> Result<Option<Self>> {
        let mut keys = std::collections::BTreeMap::new();
        // The base64 seen per id, so a repeated id is refused when the BYTES
        // differ and accepted when it is the same key written twice — for EVERY
        // id, not only 0 (security review M-1, 2026-09-12: the first cut let
        // `0:X,0:Y` inside the ring silently keep whichever came second).
        let mut seen: std::collections::BTreeMap<u8, String> = std::collections::BTreeMap::new();
        if let Some(b64) = legacy_b64 {
            keys.insert(
                LEGACY_KEK_ID,
                Self::key_from_b64(b64, "TRACELANE_BYOK_MASTER_KEY")?,
            );
            seen.insert(LEGACY_KEK_ID, b64.trim().to_owned());
        }
        if let Some(ring) = ring {
            for entry in ring.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                let (id, b64) = entry.split_once(':').with_context(|| {
                    "TRACELANE_BYOK_MASTER_KEYS entries are `<id>:<base64>`; one has no `:`"
                        .to_string()
                })?;
                let id: u8 = id.trim().parse().with_context(|| {
                    format!("TRACELANE_BYOK_MASTER_KEYS: id {id:?} is not 0–255")
                })?;
                let key = Self::key_from_b64(b64, &format!("TRACELANE_BYOK_MASTER_KEYS id {id}"))?;
                if let Some(existing) = seen.get(&id) {
                    anyhow::ensure!(
                        existing == b64.trim(),
                        "KEK {id} is given twice with DIFFERENT values \
                         (TRACELANE_BYOK_MASTER_KEY / TRACELANE_BYOK_MASTER_KEYS) — refusing to \
                         guess which one sealed the rows"
                    );
                    continue; // the same key twice: idempotent
                }
                seen.insert(id, b64.trim().to_owned());
                keys.insert(id, key);
            }
        }
        if keys.is_empty() {
            anyhow::ensure!(
                active.is_none(),
                "TRACELANE_BYOK_ACTIVE_KEK is set but no master key is configured"
            );
            return Ok(None);
        }
        let highest = *keys.keys().next_back().expect("non-empty");
        let active = active.unwrap_or(highest);
        anyhow::ensure!(
            keys.contains_key(&active),
            "TRACELANE_BYOK_ACTIVE_KEK={active} names a KEK that is not loaded (loaded: {:?})",
            keys.keys().collect::<Vec<_>>()
        );
        Ok(Some(Self {
            keys,
            active,
            write_v3: ring.is_some(),
            rng: SystemRandom::new(),
        }))
    }

    fn key_from_b64(b64: &str, what: &str) -> Result<LessSafeKey> {
        let raw = B64
            .decode(b64.trim())
            .with_context(|| format!("base64-decode {what}"))?;
        anyhow::ensure!(
            raw.len() == 32,
            "{what} must be exactly 32 bytes (256 bits), got {}",
            raw.len()
        );
        let unbound = UnboundKey::new(&AES_256_GCM, &raw)
            .map_err(|_| anyhow::anyhow!("failed to construct AES-256-GCM key from {what}"))?;
        Ok(LessSafeKey::new(unbound))
    }

    /// The id new encryptions are sealed under.
    #[must_use]
    pub fn active_kek(&self) -> u8 {
        self.active
    }

    /// The ids this ring can decrypt under, ascending.
    #[must_use]
    pub fn loaded_keks(&self) -> Vec<u8> {
        self.keys.keys().copied().collect()
    }

    /// Which KEK sealed a blob, WITHOUT decrypting it: a v3 blob names it; a
    /// v2 blob is KEK 0 by definition; anything else is not ours (`None`).
    #[must_use]
    pub fn kek_id_of(ciphertext_b64: &str) -> Option<u8> {
        let raw = B64.decode(ciphertext_b64).ok()?;
        match raw.first() {
            Some(&VERSION_V3) if raw.len() >= 2 + NONCE_LEN + GCM_TAG_LEN => Some(raw[1]),
            Some(&VERSION_V2) if raw.len() >= 1 + NONCE_LEN + GCM_TAG_LEN => Some(LEGACY_KEK_ID),
            _ => None,
        }
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
    /// Base64-encoded `<0x03> || <kek_id> || <12-byte nonce> || <ct+tag>` under
    /// the ACTIVE KEK — or the v2 form `<0x02> || nonce || ct+tag` when the ring
    /// was built from the legacy single variable alone (rollback safety; the
    /// module doc says why).
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

        let key = self
            .keys
            .get(&self.active)
            .ok_or_else(|| anyhow::anyhow!("active KEK {} is not loaded", self.active))?;
        key.seal_in_place_append_tag(nonce, Aad::from(aad_context), &mut buf)
            .map_err(|_| anyhow::anyhow!("AES-256-GCM seal failed"))?;

        let mut output = Vec::with_capacity(2 + NONCE_LEN + buf.len());
        if self.write_v3 {
            output.push(VERSION_V3);
            output.push(self.active);
        } else {
            debug_assert_eq!(
                self.active, LEGACY_KEK_ID,
                "a legacy-only ring has one key: 0"
            );
            output.push(VERSION_V2);
        }
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&buf);
        Ok(B64.encode(&output))
    }

    /// Decrypt a v2 or v3 ciphertext blob.
    ///
    /// The supplied `aad_context` MUST match the context used at encrypt
    /// time. A v3 blob is opened under the KEK its id byte names; a v2 blob
    /// under KEK 0. Legacy v1 blobs (no version byte, empty AAD — no
    /// tenant/provider binding) are REJECTED: the migration window closed
    /// 2026-07-22 with prod verified to hold zero v1 rows.
    ///
    /// # Errors
    /// Fail-CLOSED: an id the ring does not hold is an error naming the id,
    /// never a fallback to another key.
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

        // Version-byte detect. v3: 0x03 || kek_id || nonce || ct+tag. v2: 0x02 ||
        // nonce || ct+tag, sealed under KEK 0. Anything else is a legacy v1 blob
        // and is rejected below.
        let (kek_id, nonce_slice, ct_and_tag) =
            if raw.len() >= 2 + NONCE_LEN + GCM_TAG_LEN && raw[0] == VERSION_V3 {
                (raw[1], &raw[2..2 + NONCE_LEN], &raw[2 + NONCE_LEN..])
            } else if raw.len() >= 1 + NONCE_LEN + GCM_TAG_LEN && raw[0] == VERSION_V2 {
                (LEGACY_KEK_ID, &raw[1..1 + NONCE_LEN], &raw[1 + NONCE_LEN..])
            } else {
                // v1 (no version byte) was sealed with EMPTY AAD — no tenant/
                // provider binding, so a DB-level ciphertext swap decrypts under
                // the wrong row. The migration window is CLOSED (prod
                // verified zero v1 rows, 2026-07-22): fail closed.
                anyhow::bail!(
                    "BYOK v1 ciphertext rejected — v1 blobs have no AAD binding \
                 (cross-tenant swap risk); re-encrypt via encrypt_with_context"
                );
            };
        let key = self.keys.get(&kek_id).ok_or_else(|| {
            anyhow::anyhow!(
                "BYOK blob is sealed under KEK {kek_id}, which this process does not hold \
                 (loaded: {:?}) — add it to TRACELANE_BYOK_MASTER_KEYS or re-wrap the row",
                self.loaded_keks()
            )
        })?;

        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce_slice);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let mut buf = ct_and_tag.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::from(aad_context), &mut buf)
            .map_err(|_| {
                anyhow::anyhow!(
                    "AES-256-GCM open failed — wrong master key, tampered ciphertext, or AAD mismatch"
                )
            })?;

        let s = std::str::from_utf8(plaintext).context("decrypted BYOK key is not UTF-8")?;
        Ok(SecretString::from(s.to_owned()))
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
/// still authenticate under GCM. Caller is
/// `crates/gateway/src/audit_keys.rs`.
pub fn anchor_key_aad(tenant_id: &tracelane_shared::TenantId) -> Vec<u8> {
    format!("anchor-key:{tenant_id}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    fn ring(entries: &[(u8, u8)], active: Option<u8>, write_v3: bool) -> ByokMasterKey {
        let mut keys = std::collections::BTreeMap::new();
        for (id, fill) in entries {
            let raw = [*fill; 32];
            let unbound = UnboundKey::new(&AES_256_GCM, &raw).unwrap();
            keys.insert(*id, LessSafeKey::new(unbound));
        }
        let highest = *keys.keys().next_back().unwrap();
        ByokMasterKey {
            keys,
            active: active.unwrap_or(highest),
            write_v3,
            rng: SystemRandom::new(),
        }
    }

    /// The legacy shape: one key, id 0, writing v2.
    fn test_key() -> ByokMasterKey {
        ring(&[(0, 0x42)], None, false)
    }

    fn b64_key(fill: u8) -> String {
        B64.encode([fill; 32])
    }

    // ── B-383 (a): the KEK ring ──

    #[test]
    fn a_v2_blob_still_decrypts_under_a_v3_ring_that_holds_kek_0() {
        // Every prod row today is v2. The ring that ships must read them.
        let legacy = test_key();
        let pk = SecretString::from("sk-live-before-rotation".to_string());
        let aad = provider_key_aad(&tenant_a(), "openai");
        let v2 = legacy.encrypt_with_context(&pk, &aad).unwrap();
        assert_eq!(ByokMasterKey::kek_id_of(&v2), Some(0));
        let ring = ring(&[(0, 0x42), (1, 0x77)], Some(1), true);
        assert_eq!(
            ring.decrypt_with_context(&v2, &aad)
                .unwrap()
                .expose_secret(),
            pk.expose_secret()
        );
    }

    #[test]
    fn a_v3_blob_names_its_kek_and_a_ring_without_that_kek_fails_closed() {
        let ring01 = ring(&[(0, 0x42), (1, 0x77)], Some(1), true);
        let pk = SecretString::from("sk-live-after-rotation".to_string());
        let aad = provider_key_aad(&tenant_a(), "openai");
        let v3 = ring01.encrypt_with_context(&pk, &aad).unwrap();
        let raw = B64.decode(&v3).unwrap();
        assert_eq!((raw[0], raw[1]), (VERSION_V3, 1));
        assert_eq!(ByokMasterKey::kek_id_of(&v3), Some(1));
        assert_eq!(
            ring01
                .decrypt_with_context(&v3, &aad)
                .unwrap()
                .expose_secret(),
            pk.expose_secret()
        );
        // KEK 0 alone (the pre-rotation process, or a ring that dropped 1) must refuse
        // by NAME, not fall through to trying another key.
        let only0 = ring(&[(0, 0x42)], None, true);
        let err = only0
            .decrypt_with_context(&v3, &aad)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sealed under KEK 1"), "{err}");
        // And a ring that holds id 1 under a DIFFERENT key fails the tag.
        let wrong1 = ring(&[(0, 0x42), (1, 0x99)], Some(1), true);
        assert!(wrong1.decrypt_with_context(&v3, &aad).is_err());
    }

    #[test]
    fn a_legacy_only_ring_keeps_writing_v2_for_rollback_safety() {
        let legacy = ByokMasterKey::from_values(Some(&b64_key(0x42)), None, None)
            .unwrap()
            .unwrap();
        assert_eq!(legacy.active_kek(), 0);
        let ct = legacy
            .encrypt_with_context(
                &SecretString::from("x".to_string()),
                &audit_key_aad(&tenant_a()),
            )
            .unwrap();
        assert_eq!(B64.decode(&ct).unwrap()[0], VERSION_V2);
    }

    #[test]
    fn the_ring_parses_and_refuses_the_three_misconfigurations() {
        // legacy var + ring with a new key: active defaults to the HIGHEST id.
        let r = ByokMasterKey::from_values(
            Some(&b64_key(0x42)),
            Some(&format!("1:{}", b64_key(0x77))),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.loaded_keks(), vec![0, 1]);
        assert_eq!(r.active_kek(), 1);
        // explicit active
        let r = ByokMasterKey::from_values(
            None,
            Some(&format!("0:{},1:{}", b64_key(0x42), b64_key(0x77))),
            Some(0),
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.active_kek(), 0);
        // (1) active names a key that is not loaded
        let e = ByokMasterKey::from_values(Some(&b64_key(0x42)), None, Some(3)).unwrap_err();
        assert!(e.to_string().contains("not loaded"), "{e}");
        // (2) a duplicate id with different bytes — inside the ring alone
        let e = ByokMasterKey::from_values(
            None,
            Some(&format!("1:{},1:{}", b64_key(0x77), b64_key(0x78))),
            None,
        )
        .unwrap_err();
        assert!(e.to_string().contains("DIFFERENT values"), "{e}");
        // (2b) KEK 0 twice INSIDE the ring, different bytes, no legacy var — the
        // case the first cut silently accepted (review M-1).
        let e = ByokMasterKey::from_values(
            None,
            Some(&format!("0:{},0:{}", b64_key(0x42), b64_key(0x43))),
            None,
        )
        .unwrap_err();
        assert!(e.to_string().contains("DIFFERENT values"), "{e}");
        // The same key written twice is idempotent, not an error.
        let r = ByokMasterKey::from_values(
            Some(&b64_key(0x42)),
            Some(&format!("0:{},0:{}", b64_key(0x42), b64_key(0x42))),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.loaded_keks(), vec![0]);
        // (3) KEK 0 given twice with different values, across the two variables
        let e = ByokMasterKey::from_values(
            Some(&b64_key(0x42)),
            Some(&format!("0:{}", b64_key(0x43))),
            None,
        )
        .unwrap_err();
        assert!(e.to_string().contains("DIFFERENT values"), "{e}");
        // nothing configured → None (dev)
        assert!(
            ByokMasterKey::from_values(None, None, None)
                .unwrap()
                .is_none()
        );
        // a 16-byte key
        let e = ByokMasterKey::from_values(Some(&B64.encode([1u8; 16])), None, None).unwrap_err();
        assert!(e.to_string().contains("32 bytes"), "{e}");
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
        // The exploit case. An attacker copies a ciphertext
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
    fn v1_ciphertexts_are_rejected() {
        // v1 blobs (no version byte, EMPTY AAD) allowed the
        // cross-tenant ciphertext swap. Prod was verified to hold ZERO v1
        // rows (2026-07-22: provider_keys 3/3 v2, tenant_audit_keys all
        // v2), so the migration window is closed and v1 fails closed.
        let k = test_key();
        // Build a v1 wire blob inline (the deleted legacy `encrypt()`
        // behavior) — the ONLY sanctioned `Aad::empty()` use, constructing
        // the attack artifact this test proves is now rejected.
        let mut nonce_bytes = [0u8; NONCE_LEN];
        k.rng.fill(&mut nonce_bytes).unwrap();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut buf = b"legacy-secret".to_vec();
        k.keys[&0]
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
            .unwrap();
        let mut raw = Vec::with_capacity(NONCE_LEN + buf.len());
        raw.extend_from_slice(&nonce_bytes);
        raw.extend_from_slice(&buf);
        let v1_ct = B64.encode(&raw);

        let err = k
            .decrypt_with_context(&v1_ct, &provider_key_aad(&tenant_a(), "openai"))
            .unwrap_err();
        assert!(
            err.to_string().contains("v1 ciphertext rejected"),
            "error names the v1 rejection: {err}"
        );
    }

    #[test]
    fn wrong_master_key_rejected_v2() {
        let k1 = test_key();
        let k2 = ring(&[(0, 0xAB)], None, false);
        let pk = SecretString::from("sk-test".to_string());
        let aad = audit_key_aad(&tenant_a());
        let ct = k1.encrypt_with_context(&pk, &aad).unwrap();
        assert!(k2.decrypt_with_context(&ct, &aad).is_err());
    }
}
