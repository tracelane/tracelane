//!
//! ## Scheme (ADR-042)
//!
//! API keys are `tlane_<base62>`; the part after the prefix is the *key body*.
//! Storage matches the canonical Drizzle/Neon shape (ADR-040): PK column `id`,
//! plus `key_prefix` (display), `lookup_hash`, `argon2id_phc`:
//!
//! 1. `lookup_hash = HMAC-SHA256(server_pepper, key_body)` — `bytea`.
//!    - Deterministic ⇒ UNIQUE index ⇒ ~1µs hot-path lookup.
//!    - Peppered ⇒ a DB dump alone cannot regenerate it. The pepper loads from
//!      `TRACELANE_APIKEY_PEPPER` (KMS-backed in prod); release binaries refuse
//!      to start without it.
//! 2. `argon2id_phc` — PHC string (per-row salt + m/t/p params).
//!    - Verified AFTER the lookup hits, so the slow KDF cost is paid once per
//!      legitimate request, never on a brute-force sweep. Defense in depth: even
//!      if the pepper leaks, Argon2id makes offline brute force expensive.
//!
//! The minter (`apps/web/app/api/settings/api-keys`) and this verifier MUST HMAC
//! with the **same** pepper. There is **no** legacy bare-SHA-256 fallback: prod
//! is minted onto this scheme (ADR-042), so every live row has `lookup_hash` +
//! `argon2id_phc`. A nullable `key_hash` column lingers for one row-drop window
//! and is removed in a follow-up migration; this module never reads or writes it.
//!
//! Argon2id alone can't be the lookup column because the per-row salt makes the
//! output non-deterministic — you'd have to load every row and KDF-verify each.
//! Peppered HMAC is the load-bearing ergonomic; Argon2id is the depth.
//!
//! Hot-path budget (CLAUDE.md): the lookup HMAC + index probe is well under the
//! gateway 5ms p50 overhead. Argon2id verify at the default params (~50ms) is
//! paid once per **authenticated** request; the auth result is cached upstream.

use anyhow::{Context as _, Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use secrecy::{ExposeSecret, SecretBox};
use std::sync::OnceLock;
use uuid::Uuid;

use tracelane_shared::TenantId;

// ---------------------------------------------------------------------
// Pepper
// ---------------------------------------------------------------------

/// Process-wide pepper key. Loaded once at startup from
/// `TRACELANE_APIKEY_PEPPER` and never logged. `SecretBox` zeroizes on
/// drop; the lock is `OnceLock` so the load is single-shot.
static PEPPER: OnceLock<SecretBox<[u8; 32]>> = OnceLock::new();

/// Initialize the process-wide pepper from `TRACELANE_APIKEY_PEPPER`.
///
/// Expects 64 hex chars (32 raw bytes) or 44 base64 chars. Anything
/// shorter is rejected — a 32-byte HMAC key is the minimum for the
/// strong-key bound in RFC 2104.
///
/// Idempotent: a second call with the same pepper is a no-op; a second
/// call with a different pepper returns an error so misconfiguration
/// surfaces loudly.
pub fn init_pepper(raw: &str) -> Result<()> {
    let bytes = decode_pepper(raw)?;
    let secret = SecretBox::new(Box::new(bytes));
    match PEPPER.set(secret) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Already initialized. Verify the value matches what's
            // installed; if it doesn't, refuse loudly.
            let current = PEPPER
                .get()
                .ok_or_else(|| anyhow!("pepper present-but-missing race"))?;
            if current.expose_secret() == &bytes {
                Ok(())
            } else {
                Err(anyhow!(
                    "init_pepper called twice with different values — refusing"
                ))
            }
        }
    }
}

fn decode_pepper(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 {
        // Try hex first.
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = hex_nibble(trimmed.as_bytes()[2 * i])
                .ok_or_else(|| anyhow!("pepper hex: non-hex char"))?;
            let lo = hex_nibble(trimmed.as_bytes()[2 * i + 1])
                .ok_or_else(|| anyhow!("pepper hex: non-hex char"))?;
            *byte = (hi << 4) | lo;
        }
        Ok(out)
    } else {
        // Try base64.
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
            .context("pepper is not 64-hex-chars or valid base64")?;
        if decoded.len() != 32 {
            return Err(anyhow!(
                "pepper must decode to exactly 32 bytes (got {})",
                decoded.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        Ok(out)
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn pepper() -> Result<&'static SecretBox<[u8; 32]>> {
    PEPPER
        .get()
        .ok_or_else(|| anyhow!("api-key pepper not initialized (call init_pepper at startup)"))
}

// ---------------------------------------------------------------------
// Key material primitives
// ---------------------------------------------------------------------

/// The two derived shapes stored for a key body: the peppered-HMAC lookup
/// (indexed) and the Argon2id PHC (KDF verify). Built off the hot path, at
/// key-creation time only.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub lookup_hash: [u8; 32],
    pub argon2id_phc: String,
}

impl KeyMaterial {
    /// Build the full `KeyMaterial` from a raw key body. Argon2id at
    /// default params (~50ms on a modest server) so call this off the
    /// hot path — at key creation time only.
    pub fn from_body(key_body: &str) -> Result<Self> {
        Ok(Self {
            lookup_hash: peppered_lookup(key_body)?,
            argon2id_phc: argon2id_hash(key_body)?,
        })
    }
}

/// Peppered HMAC-SHA256 of the key body. Deterministic, indexable, but
/// DB-dump-resistant because regenerating it requires the pepper.
pub fn peppered_lookup(key_body: &str) -> Result<[u8; 32]> {
    let p = pepper()?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, p.expose_secret());
    let tag = hmac::sign(&key, key_body.as_bytes());
    let mut buf = [0u8; 32];
    buf.copy_from_slice(tag.as_ref());
    Ok(buf)
}

/// Argon2id hash of the key body, returned as a PHC string
/// (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`). Default RustCrypto
/// params: m=19456 (19 MiB), t=2, p=1 — the OWASP recommendation as of
/// 2024 for "low latency, low memory" servers. Verification cost is
/// ~50ms on a modest server; this is acceptable because it's paid only
/// on successful peppered-HMAC hits.
pub fn argon2id_hash(key_body: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let phc = argon
        .hash_password(key_body.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2id hash: {e}"))?
        .to_string();
    Ok(phc)
}

/// Verify a key body against a stored PHC string. Constant-time inside
/// the `argon2` crate. Returns `Ok(true)` on match, `Ok(false)` on
/// mismatch, `Err` if the PHC string itself is malformed.
pub fn argon2id_verify(phc: &str, key_body: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(|e| anyhow!("argon2id PHC parse: {e}"))?;
    Ok(Argon2::default()
        .verify_password(key_body.as_bytes(), &parsed)
        .is_ok())
}

// ---------------------------------------------------------------------
// ---------------------------------------------------------------------

/// Base62 alphabet — digits, then upper, then lower. MUST match the web
/// minter (`apps/web/lib/api-key-hash.ts`) so a `tlane_` key looks identical
/// regardless of which surface minted it.
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// A key body is 32 random bytes rendered big-endian base62, left-padded to 43
/// chars (62^43 ≳ 2^256 ≥ any 32-byte value, so 43 is the fixed width).
const KEY_BODY_LEN: usize = 43;
/// Non-secret display prefix stored in `key_prefix` — the first chars of the
/// body (the UI shows `tlane_<prefix>…`). Matches the web `body.slice(0, 6)`.
const KEY_PREFIX_LEN: usize = 6;

/// Render 32 bytes as a big-endian base62 string, left-padded to
/// [`KEY_BODY_LEN`]. Byte-identical to the web minter's `toBase62`: interpret
/// the bytes as one 256-bit big-endian integer and repeatedly divmod 62.
fn to_base62(bytes: &[u8; 32]) -> String {
    let mut num = *bytes;
    let mut digits = Vec::with_capacity(KEY_BODY_LEN);
    while num.iter().any(|&b| b != 0) {
        let mut remainder = 0u16;
        for byte in num.iter_mut() {
            let acc = (remainder << 8) | u16::from(*byte);
            *byte = (acc / 62) as u8;
            remainder = acc % 62;
        }
        digits.push(BASE62[remainder as usize]);
    }
    // `digits` is least-significant-first; left-pad with '0' (base62 zero) then
    // reverse to most-significant-first — mirrors JS `padStart(43, "0")`.
    while digits.len() < KEY_BODY_LEN {
        digits.push(b'0');
    }
    digits.reverse();
    String::from_utf8(digits).expect("BASE62 is ASCII")
}

/// Generate a fresh key body (the part after the `tlane_` prefix): 32 CSPRNG
/// bytes as base62. Uses `ring`'s `SystemRandom` (the crypto RNG mandated by
/// CLAUDE.md — no `openssl`, no ad-hoc entropy).
///
/// # Errors
/// Fails only if the OS RNG is unavailable (`ring::error::Unspecified`).
fn generate_key_body() -> Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("system RNG unavailable while minting API key"))?;
    Ok(to_base62(&bytes))
}

/// A freshly minted key: the persisted row plus the one-time raw secret.
///
/// `raw_key` (`tlane_<body>`) is returned to the API caller exactly once and is
/// never stored or re-derivable — only its `lookup_hash`/`argon2id_phc` live in
/// the DB. It is a credential: never log it, never persist it.
#[derive(Debug)]
pub struct MintedKey {
    pub api_key: ApiKey,
    pub key_prefix: String,
    pub raw_key: String,
}

/// Mint a new API key end-to-end for `tenant_id`: generate the body, derive the
/// [`KeyMaterial`] (peppered HMAC + Argon2id), and insert the row. The Argon2id
/// KDF (~50ms) runs here, at creation time only — never on the request path.
///
/// cannot run the web minter's WASM Argon2 reliably, so the dashboard proxies
/// key creation here where RustCrypto Argon2 runs natively. The derived
/// material is byte-identical to the web minter (same pepper, same params), so
/// keys from either surface verify through `lookup_tenant_by_key_body`.
///
/// # Errors
/// RNG failure, pepper-not-initialized, Argon2id hashing, or the DB insert.
pub async fn mint(
    pool: &Pool,
    tenant_id: &TenantId,
    name: &str,
    minted_by: Option<&str>,
) -> Result<MintedKey> {
    let body = generate_key_body()?;
    let material = KeyMaterial::from_body(&body)?;
    let key_prefix: String = body.chars().take(KEY_PREFIX_LEN).collect();
    let api_key = create(pool, tenant_id, &material, name, &key_prefix, minted_by).await?;
    Ok(MintedKey {
        api_key,
        key_prefix,
        raw_key: format!("tlane_{body}"),
    })
}

// ---------------------------------------------------------------------
// Public data model
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ApiKey {
    /// The `id` PK column (uuid, DB-generated).
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

/// Insert a new API key. The caller has already generated the body and
/// derived the `KeyMaterial`; `key_prefix` is the non-secret display prefix
/// (e.g. the first chars of the body). The raw key is returned to the API
/// caller exactly once at creation time and is never re-derivable.
///
/// `id` is DB-generated (`gen_random_uuid()`); the row is returned.
///
/// NOTE: production minting happens in the web app
/// (`apps/web/app/api/settings/api-keys`); this gateway-side `create` is used by
/// integration tests and any future gateway-side mint path. Both must produce
/// identical `lookup_hash`/`argon2id_phc` from the key body.
pub async fn create(
    pool: &Pool,
    tenant_id: &TenantId,
    material: &KeyMaterial,
    name: &str,
    key_prefix: &str,
    minted_by: Option<&str>,
) -> Result<ApiKey> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let row = client
        .query_one(
            "INSERT INTO api_keys (tenant_id, name, lookup_hash, argon2id_phc, key_prefix, minted_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, tenant_id, name, created_at, last_used_at, revoked_at",
            &[
                tenant_id.as_uuid(),
                &name,
                &material.lookup_hash.as_slice(),
                &material.argon2id_phc,
                &key_prefix,
                &minted_by,
            ],
        )
        .await
        .context("INSERT INTO api_keys failed")?;
    Ok(ApiKey {
        id: row.get(0),
        tenant_id: row.get(1),
        name: row.get(2),
        created_at: row.get(3),
        last_used_at: row.get(4),
        revoked_at: row.get(5),
    })
}

/// Hot-path lookup. Returns `Ok(Some((tenant, api_key_id)))` on success — the
/// caller uses the row `id` (never a secret-derived value) for the `sub` claim
/// (ADR-042 / security review M-2). `Ok(None)` when no row matches (caller
/// surfaces 401), `Err` for real DB failures (caller surfaces 500).
///
/// Peppered lookup (`lookup_hash`) then Argon2id PHC verify. A row whose
/// `argon2id_phc` is NULL is rejected — the strong scheme always stores both,
/// so a NULL is a malformed/legacy row that must not authenticate without the
/// KDF check. `last_used_at` is updated best-effort on success.
pub async fn lookup_tenant_by_key_body(
    pool: &Pool,
    key_body: &str,
) -> Result<Option<(TenantId, Uuid)>> {
    let lookup = peppered_lookup(key_body)?;

    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;

    let row = client
        .query_opt(
            "SELECT tenant_id, id, argon2id_phc
             FROM api_keys
             WHERE lookup_hash = $1 AND revoked_at IS NULL",
            &[&lookup.as_slice()],
        )
        .await
        .context("SELECT api_keys by lookup_hash failed")?;

    let Some(row) = row else { return Ok(None) };

    let tenant_uuid: Uuid = row.get(0);
    let id: Uuid = row.get(1);
    let phc: Option<String> = row.get(2);

    // KDF verify — defense in depth. The peppered HMAC already authenticated,
    // but the strong scheme REQUIRES the Argon2id PHC: a row with a NULL or
    // have been re-minted).
    let phc_ok = match phc.as_deref() {
        Some(p) => match argon2id_verify(p, key_body) {
            Ok(ok) => ok,
            Err(e) => {
                // Malformed PHC on a lookup_hash hit = a corrupted/tampered row,
                // not a normal auth miss — surface it for operators. No key
                // material logged; only the row id (L-3).
                tracing::error!(
                    api_key_id = %id,
                    error = %e,
                    "argon2id PHC parse failed — possible DB-row corruption"
                );
                false
            }
        },
        None => false,
    };
    if !phc_ok {
        tracing::error!(
            api_key_id = %id,
            "lookup_hash matched but argon2id_phc missing/failed — rejecting"
        );
        return Ok(None);
    }

    touch_last_used(&client, id).await;
    Ok(Some((TenantId::from_jwt_claim(tenant_uuid), id)))
}

async fn touch_last_used(client: &deadpool_postgres::Client, id: Uuid) {
    let _ = client
        .execute(
            "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
            &[&id],
        )
        .await;
}

/// Revoke a key by id. Idempotent — repeated revoke is a no-op.
pub async fn revoke(pool: &Pool, id: Uuid) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "UPDATE api_keys SET revoked_at = NOW()
             WHERE id = $1 AND revoked_at IS NULL",
            &[&id],
        )
        .await
        .context("UPDATE api_keys revoke failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test_pepper() {
        // 32 zero bytes for tests. Real prod pepper comes from KMS.
        let _ = init_pepper(&"00".repeat(32));
    }

    #[test]
    fn peppered_lookup_is_deterministic_with_same_pepper() {
        init_test_pepper();
        let a = peppered_lookup("tlane-body-1").unwrap();
        let b = peppered_lookup("tlane-body-1").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, peppered_lookup("tlane-body-2").unwrap());
    }

    #[test]
    fn hmac_sha256_known_answer_matches_web_minter() {
        // Cross-impl KAT (ADR-042): ring HMAC-SHA256(32 zero bytes, "abc123")
        // must equal node `crypto.createHmac('sha256', zeros).update('abc123')`
        // used by the web minter (apps/web/lib/api-key-hash.ts) — so lookup_hash
        // agrees across the gateway verifier and the minter. Computed directly
        // (not via the global pepper) so it's order-independent in the test bin.
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        let tag = hmac::sign(&key, b"abc123");
        assert_eq!(
            hex::encode(tag.as_ref()),
            "a88e2d710bee460c0fd3561f2057706a7780cc5fc8d1005fd7cd7e34f453e499"
        );
    }

    #[test]
    fn argon2id_roundtrip_succeeds() {
        let phc = argon2id_hash("a-secret-key-body").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(argon2id_verify(&phc, "a-secret-key-body").unwrap());
    }

    #[test]
    fn argon2id_rejects_wrong_body() {
        let phc = argon2id_hash("right-body").unwrap();
        assert!(!argon2id_verify(&phc, "wrong-body").unwrap());
    }

    /// Cross-impl round-trip (ADR-042, Vercel→CF `hash-wasm` swap): a PHC minted
    /// by the dashboard's pure-WASM Argon2id (`apps/web/lib/api-key-hash.ts`)
    /// MUST verify byte-for-byte in this RustCrypto verifier — that is the exact
    /// production path (web mints, gateway verifies). A PHC-encoding drift here =
    /// silent key-verify failure for every new key (#81 class), so the hash-wasm
    /// output is frozen as a known-answer vector: params m=19456,t=2,p=1, tag 32B,
    /// salt = bytes 0..15. Regenerate via `apps/web` mint-vector if params change.
    #[test]
    fn rustcrypto_verifies_hashwasm_minted_phc() {
        const HASHWASM_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$qbMc+TooxRwdHvoqtALQowxdbkKLXf4ucwdZsgIIxg4";
        const KEY_BODY: &str = "rt-vector-key-body-do-not-use-in-prod";
        assert!(
            argon2id_verify(HASHWASM_PHC, KEY_BODY).unwrap(),
            "RustCrypto gateway verifier must accept a hash-wasm-minted PHC"
        );
        assert!(
            !argon2id_verify(HASHWASM_PHC, "wrong-body").unwrap(),
            "must still reject the wrong body against the hash-wasm-minted PHC"
        );
    }

    #[test]
    fn argon2id_includes_per_row_salt() {
        // Same body → two distinct PHC strings because the salt differs.
        let a = argon2id_hash("same-body").unwrap();
        let b = argon2id_hash("same-body").unwrap();
        assert_ne!(a, b, "salt should make outputs differ");
        // But both verify against the original body.
        assert!(argon2id_verify(&a, "same-body").unwrap());
        assert!(argon2id_verify(&b, "same-body").unwrap());
    }

    #[test]
    fn argon2id_verify_rejects_malformed_phc() {
        assert!(argon2id_verify("not-a-phc-string", "x").is_err());
    }

    #[test]
    fn key_material_carries_lookup_and_phc() {
        init_test_pepper();
        let m = KeyMaterial::from_body("body-1").unwrap();
        assert_eq!(m.lookup_hash.len(), 32);
        assert!(m.argon2id_phc.starts_with("$argon2id$"));
        // lookup_hash is deterministic for the same body…
        assert_eq!(m.lookup_hash, peppered_lookup("body-1").unwrap());
        // …and the PHC verifies the right body only.
        assert!(argon2id_verify(&m.argon2id_phc, "body-1").unwrap());
        assert!(!argon2id_verify(&m.argon2id_phc, "body-2").unwrap());
    }

    #[test]
    fn pepper_decode_accepts_hex_64() {
        let raw = "0".repeat(64);
        let out = decode_pepper(&raw).unwrap();
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn pepper_decode_accepts_base64() {
        // 32 zero bytes base64-encoded = 44 chars.
        let raw = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        let out = decode_pepper(&raw).unwrap();
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn pepper_decode_rejects_short_input() {
        assert!(decode_pepper("too-short").is_err());
        // Hex of 16 bytes (32 chars) — rejected: neither 64-hex nor base64-32-bytes.
        assert!(decode_pepper(&"a".repeat(32)).is_err());
    }

    #[test]
    fn to_base62_is_fixed_width_and_in_alphabet() {
        // All-zero and all-one bounds both render to exactly 43 base62 chars.
        for bytes in [[0u8; 32], [0xFFu8; 32]] {
            let s = to_base62(&bytes);
            assert_eq!(s.len(), KEY_BODY_LEN, "body must be {KEY_BODY_LEN} chars");
            assert!(
                s.bytes().all(|b| BASE62.contains(&b)),
                "every char must be in the base62 alphabet"
            );
        }
        assert_eq!(to_base62(&[0u8; 32]), "0".repeat(KEY_BODY_LEN));
    }

    #[test]
    fn to_base62_known_answer_matches_web_minter() {
        // Cross-impl KAT vs apps/web toBase62 (big-endian divmod 62, padStart 43):
        //   value 1  -> "0…01", value 61 -> "0…0z", value 62 -> "0…010".
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(to_base62(&one).ends_with("01"));
        assert_eq!(to_base62(&one).trim_start_matches('0'), "1");

        let mut sixty_one = [0u8; 32];
        sixty_one[31] = 61;
        assert_eq!(to_base62(&sixty_one).trim_start_matches('0'), "z");

        let mut sixty_two = [0u8; 32];
        sixty_two[31] = 62;
        assert_eq!(to_base62(&sixty_two).trim_start_matches('0'), "10");
    }

    #[test]
    fn generate_key_body_is_well_formed_and_unique() {
        let a = generate_key_body().unwrap();
        let b = generate_key_body().unwrap();
        assert_eq!(a.len(), KEY_BODY_LEN);
        assert!(a.bytes().all(|c| BASE62.contains(&c)));
        assert_ne!(a, b, "each mint must draw fresh entropy");
        // The stored prefix is the first KEY_PREFIX_LEN chars of the body.
        assert_eq!(
            &a.chars().take(KEY_PREFIX_LEN).collect::<String>(),
            &a[..KEY_PREFIX_LEN]
        );
    }
}
