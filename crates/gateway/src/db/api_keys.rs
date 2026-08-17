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
use moka::future::Cache;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use secrecy::{ExposeSecret, SecretBox};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
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
// ---------------------------------------------------------------------
//
// The measured gateway overhead was 62ms of Argon2id + PG round-trips on EVERY
// request (the module doc's "the auth result is cached upstream" was aspirational
// — no cache existed). This is that cache.
//
// Keyed by the peppered-HMAC lookup digest (`peppered_lookup(key_body)` — never
// the raw key, never a truncation); value = the resolved `(tenant_uuid, key_id)`.
// A HIT skips the PG SELECT + the ~50ms Argon2id verify: the digest is already
// peppered, so recomputing it and matching a cached entry authenticates the
// presented token (an attacker cannot produce a matching digest without the
// server pepper). Argon2id remains the depth-in-case-of-DB-leak layer, paid on
// every cache MISS.
//
// POSITIVES ONLY — a not-found/revoked key is never cached, so a fresh key works
// on its first request and a revoked key can only linger if it was cached BEFORE
// revocation.
//
// else. The previous comment here said the window was "closed immediately by the
// `key_revoked` NOTIFY", with the TTL as a mere backstop. That was false in
// production and the failure was systematic, not occasional: `pg_notify` reaches
// only listeners attached at that instant, the Neon compute autosuspends after 5
// min idle, and the revoking UPDATE is itself what wakes it — so on an idle system
// the NOTIFY fires on a fresh postmaster while the gateway's listener is still
// holding a socket it has not yet noticed is dead. Measured: 110 drop/reconnect
// cycles in 21.07 h. The NOTIFY path is now off by default
// (`entitlement_cache::control_plane_listen_enabled`).
//
// So the TTL is the revocation bound, it is stated as such, and it is 60s rather
// than the 900s that silently applied while we believed otherwise. Cost of the
// shorter TTL is one PG SELECT + one Argon2id verify per ACTIVE key per minute —
// paid only when a request actually arrives, because this cache is in-memory and
// positives-only. It therefore does not poll, and does not defeat Neon autosuspend
// (which was the whole point of dropping LISTEN).

/// What the auth cache stores: identity PLUS resolved capability (A13).
type CachedAuth = (Uuid, Uuid, tracelane_shared::api_scope::KeyScope);

static AUTH_CACHE_HIT_TOTAL: AtomicU64 = AtomicU64::new(0);
static AUTH_CACHE_MISS_TOTAL: AtomicU64 = AtomicU64::new(0);

const DEFAULT_AUTH_CACHE_TTL_SECS: u64 = 60;
/// Hard ceiling. A revocation window is a security property, so an env typo must
/// not be able to widen it past the value we previously (wrongly) shipped.
const MAX_AUTH_CACHE_TTL_SECS: u64 = 900;

/// Resolve the auth-cache TTL, clamped to `1..=900` seconds.
///
/// Fails CLOSED on garbage: an unparseable or out-of-range value falls back to the
/// 60s default rather than to the maximum, because this bounds how long a REVOKED
/// key keeps working.
///
/// Split from the env read so the policy is unit-testable without touching
/// process-global env — `docs/reference/TRAPS.md` §20: a test that mutates a
/// process-global races every other test that reads it, and the fix is not to
/// share it rather than to guard it.
fn parse_auth_cache_ttl(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| (1..=MAX_AUTH_CACHE_TTL_SECS).contains(s))
        .unwrap_or(DEFAULT_AUTH_CACHE_TTL_SECS)
}

fn auth_cache_ttl_secs() -> u64 {
    parse_auth_cache_ttl(
        std::env::var("TRACELANE_AUTH_CACHE_TTL_SECS")
            .ok()
            .as_deref(),
    )
}

fn auth_cache() -> &'static Cache<[u8; 32], CachedAuth> {
    static C: OnceLock<Cache<[u8; 32], CachedAuth>> = OnceLock::new();
    C.get_or_init(|| {
        Cache::builder()
            .max_capacity(50_000)
            // not a backstop behind a NOTIFY that does not arrive. Override with
            // TRACELANE_AUTH_CACHE_TTL_SECS when traffic makes the Argon2id cost
            // matter; clamped so a typo cannot produce an unbounded window.
            .time_to_live(Duration::from_secs(auth_cache_ttl_secs()))
            .build()
    })
}

/// Evict one cached auth result by its peppered-HMAC lookup digest. Called by the
/// `key_revoked` LISTEN handler when that listener is enabled — an OPTIMISATION
/// that shortens the window, never the bound. The bound is the TTL above (60s).
/// false in production for a structural reason, not an occasional one.
pub async fn invalidate(digest: [u8; 32]) {
    auth_cache().invalidate(&digest).await;
}

/// Snapshot `(hits, misses)` of the auth-result cache — for the health/metrics
/// surface (the loud hit-rate signal).
#[must_use]
pub fn auth_cache_stats() -> (u64, u64) {
    (
        AUTH_CACHE_HIT_TOTAL.load(Ordering::Relaxed),
        AUTH_CACHE_MISS_TOTAL.load(Ordering::Relaxed),
    )
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
    opts: MintOptions,
) -> Result<MintedKey> {
    let body = generate_key_body()?;
    let material = KeyMaterial::from_body(&body)?;
    let key_prefix: String = body.chars().take(KEY_PREFIX_LEN).collect();
    let api_key = create(
        pool,
        tenant_id,
        &material,
        name,
        &key_prefix,
        minted_by,
        &opts,
    )
    .await?;
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
    /// A13. `None` = the legacy full-surface key; see `api_scope::KeyScope`.
    pub scope: Option<Vec<String>>,
    /// A13. `None` = never expires.
    pub expires_at: Option<DateTime<Utc>>,
}

/// A13 mint options. Every field is optional at the wire, but the mint path
/// turns an omitted `scope` into an EXPLICIT full set rather than SQL NULL —
/// see [`mint`] for why that distinction is the whole point.
#[derive(Debug, Clone, Default)]
pub struct MintOptions {
    pub scope: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    /// USD/month. Carried as `f64` and bound as TEXT with a `::numeric` cast —
    /// tokio-postgres has no native NUMERIC mapping without pulling in
    /// `rust_decimal`, and the same bind-as-text-then-cast shape is already the
    /// house workaround for PG enums. Postgres does the parse, and
    /// `api_keys_budget_nonneg_chk` does the range check, so a bad value is a
    /// constraint violation rather than a silently truncated number.
    ///
    /// v1 RECORDS and REPORTS the budget; it does not enforce a cut-off. That is
    /// a separate ruling per the spec: refusing a paying customer's traffic on a
    /// budget mis-read is worse than the overspend.
    pub budget_usd_monthly: Option<f64>,
}

impl MintOptions {
    /// A13 — the ONE place the NULL-vs-explicit distinction is decided.
    ///
    /// Migration 0024's hand-off note is explicit that NULL-means-unrestricted is
    /// a BACKWARDS-COMPATIBILITY choice for the existing rows and "NOT a safe
    /// default for new ones". So a key minted without a stated scope is written
    /// with the FULL SET SPELLED OUT, never SQL NULL: identical authority to
    /// today, but recorded as a decision rather than inherited as an absence.
    /// `LegacyFullSurface` then means exactly one thing — "minted before A13" —
    /// instead of accumulating new members forever.
    ///
    /// Applied at the HTTP edge rather than inside [`mint`] so the response body
    /// reports what was actually stored. When it lived in `mint`, a caller that
    /// omitted `scope` got `"scope": null` back while the row held the full set —
    /// the API describing something other than the database.
    ///
    /// DEVIATION FROM THE NOTE, stated: it says the mint route must REQUIRE a
    /// scope. Requiring one would 400 every existing caller of `POST /v1/keys`
    /// the moment this deploys, the dashboard proxy included. The wire field
    /// stays optional and the DEFAULT is what changed; the property the note
    /// protects — no new key is silently unscoped — holds either way.
    #[must_use]
    pub fn with_default_scope(mut self) -> Self {
        self.scope = Some(self.scope.unwrap_or_else(|| {
            // `default_mint_set()`, NOT `all()`. Admin is opt-in and explicit,
            // always — an omitted scope must never grant workspace management.
            // Pinned by `omitted_scope_never_includes_admin`.
            tracelane_shared::api_scope::Scope::default_mint_set()
                .iter()
                .map(|s| s.as_slug().to_string())
                .collect()
        }));
        self
    }
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

/// Bind shape for `budget_usd_monthly`. **The `::text::` half is load-bearing.**
///
/// `budget_text` is an `Option<String>`. Written as a bare `$9::numeric`,
/// Postgres infers the parameter type as `numeric` and tokio-postgres refuses to
/// serialize a Rust `String` into it — `error serializing parameter 8` — **on
/// every call, including when the value is `None`**, because the type check
/// precedes any NULL handling. That shipped in `5ab66bd0` (A13, 2026-08-12) and
/// took `POST /v1/keys` down completely: every mint returned 500, the dashboard
/// showed 502, and **no customer could create an API key for two days.**
///
/// The fix is to bind as `text` and let the DB coerce. This is the *identical*
/// rule `db/tenants.rs`'s `PLAN_ENUM_CAST` already wrote down — *"NEVER write a
/// bare `$N::plan` for a string parameter"* — and the comment that introduced
/// this bug cited that very workaround while dropping the `::text::` half that
/// does the work. A lesson with no consumer on the second site.
///
/// Pinned by `tests::budget_numeric_cast_routes_through_text` and falsified for
/// real against Postgres by `budget_param_serialization_contract`.
const BUDGET_NUMERIC_CAST: &str = "::text::numeric";

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
    opts: &MintOptions,
) -> Result<ApiKey> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let budget_text: Option<String> = opts.budget_usd_monthly.map(|b| format!("{b:.4}"));
    let sql = format!(
        "INSERT INTO api_keys (tenant_id, name, lookup_hash, argon2id_phc, key_prefix, minted_by, \
                               scope, expires_at, budget_usd_monthly)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9{BUDGET_NUMERIC_CAST})
         RETURNING id, tenant_id, name, created_at, last_used_at, revoked_at, scope, expires_at"
    );
    let row = client
        .query_one(
            &sql,
            &[
                tenant_id.as_uuid(),
                &name,
                &material.lookup_hash.as_slice(),
                &material.argon2id_phc,
                &key_prefix,
                &minted_by,
                &opts.scope,
                &opts.expires_at,
                &budget_text,
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
        scope: row.get(6),
        expires_at: row.get(7),
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
) -> Result<Option<(TenantId, Uuid, tracelane_shared::api_scope::KeyScope)>> {
    let lookup = peppered_lookup(key_body)?;

    // fix B: warm-cache hit — the peppered-HMAC digest matched a previously
    // authenticated key. Skip the PG SELECT + the ~50ms Argon2id verify.
    if let Some((tenant, key_id, key_scope)) = auth_cache().get(&lookup).await {
        let hits = AUTH_CACHE_HIT_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
        let miss = AUTH_CACHE_MISS_TOTAL.load(Ordering::Relaxed);
        // Loud, bounded hit-rate signal (once per 1000 lookups).
        if (hits + miss).is_multiple_of(1000) {
            tracing::info!(
                hits,
                miss,
                hit_rate_pct = hits * 100 / (hits + miss).max(1),
                "api-key auth cache hit-rate"
            );
        }
        return Ok(Some((TenantId::from_jwt_claim(tenant), key_id, key_scope)));
    }
    AUTH_CACHE_MISS_TOTAL.fetch_add(1, Ordering::Relaxed);

    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;

    // A13: `scope` and `expires_at` are read HERE, in the same round-trip that
    // already authenticates the key — not re-derived per route. `expires_at` is
    // filtered in SQL alongside `revoked_at` so an expired key is indistinguishable
    // from a revoked one to everything downstream: same NULL row, same 401, no
    // second code path to keep in step.
    //
    // Enforced in the gateway rather than by the DB (no constraint can express
    // "reject at read time"), which means a clock skew between Neon and the
    // gateway is the failure mode — `now()` is Postgres's, so both sides of the
    // comparison come from the same clock. That is deliberate.
    let row = client
        .query_opt(
            "SELECT tenant_id, id, argon2id_phc, scope, expires_at
             FROM api_keys
             WHERE lookup_hash = $1
               AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > now())",
            &[&lookup.as_slice()],
        )
        .await
        .context("SELECT api_keys by lookup_hash failed")?;

    let Some(row) = row else { return Ok(None) };

    let tenant_uuid: Uuid = row.get(0);
    let id: Uuid = row.get(1);
    let phc: Option<String> = row.get(2);
    let scope_raw: Option<Vec<String>> = row.get(3);
    let key_scope = tracelane_shared::api_scope::KeyScope::from_column(scope_raw.as_deref());

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

    // Populate the warm cache for subsequent requests with this key (fix B).
    // A13: the SCOPE is cached with the identity. Caching only (tenant, key_id)
    // would force the caller to re-derive a capability it cannot see on a warm
    // hit — and the only available default is full-surface, which would be a
    // privilege escalation on every cached request.
    auth_cache()
        .insert(lookup, (tenant_uuid, id, key_scope.clone()))
        .await;
    // ponytail: last_used_at is refreshed only on the (cold) miss path — a
    // warm-cached key updates it at most every 15m (TTL refill). Fine for a
    // display field; a spawned touch per warm hit would put a PG write back on
    // every request, defeating the cache.
    touch_last_used(&client, id).await;
    Ok(Some((TenantId::from_jwt_claim(tenant_uuid), id, key_scope)))
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

    /// set wrong must land on the tighter value, never the looser one.
    #[test]
    fn auth_cache_ttl_defaults_to_sixty_seconds() {
        assert_eq!(parse_auth_cache_ttl(None), 60);
        assert_eq!(DEFAULT_AUTH_CACHE_TTL_SECS, 60);
    }

    #[test]
    fn auth_cache_ttl_honours_a_valid_override() {
        assert_eq!(parse_auth_cache_ttl(Some("120")), 120);
        assert_eq!(parse_auth_cache_ttl(Some(" 30 ")), 30);
        assert_eq!(parse_auth_cache_ttl(Some("900")), 900);
    }

    /// Fails CLOSED, and this is the discriminating half: every bad input must
    /// resolve to the 60s DEFAULT, not to `MAX`. An implementation that clamped
    /// (`min(v, MAX)`) would pass "too large" by returning 900 — a 15-minute
    /// in. These assertions fail against that implementation.
    #[test]
    fn auth_cache_ttl_rejects_garbage_toward_the_tighter_bound() {
        for bad in ["0", "901", "86400", "-1", "abc", "", "60s", "1e3"] {
            assert_eq!(
                parse_auth_cache_ttl(Some(bad)),
                DEFAULT_AUTH_CACHE_TTL_SECS,
                "{bad:?} must fall back to the 60s default, never to MAX"
            );
        }
        assert!(parse_auth_cache_ttl(Some("901")) < MAX_AUTH_CACHE_TTL_SECS);
    }

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

    /// The `budget_usd_monthly` bind MUST route through `text`. A bare
    /// `$9::numeric` makes Postgres infer the param as `numeric`, which
    /// tokio-postgres cannot serialize a `String` into — every mint 500s.
    /// Exact twin of `db::tenants::tests::plan_enum_cast_routes_through_text`;
    /// that rule existed and this site did not consume it.
    #[test]
    fn budget_numeric_cast_routes_through_text() {
        assert_eq!(BUDGET_NUMERIC_CAST, "::text::numeric");
        assert!(
            BUDGET_NUMERIC_CAST.contains("::text::"),
            "numeric binds carrying a String must serialize as text, not the bare numeric type"
        );
        let values = format!("VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9{BUDGET_NUMERIC_CAST})");
        assert!(values.contains("$9::text::numeric"), "must be text-routed");
        assert!(
            !values
                .replace("$9::text::numeric", "")
                .contains("::numeric"),
            "no bare `$N::numeric` may remain"
        );
    }

    /// Live contract against a real Postgres, the regression the unit suite
    /// cannot express. A bare `$1::numeric` MUST fail `Option<String>` ->
    /// numeric serialization (the shipped bug, and it fails for `None` too),
    /// and the text-routed form MUST round-trip. Read-only; no table writes.
    ///   POSTGRES_TEST_URL=postgres://... cargo test -p gateway --bins \
    ///     db::api_keys::tests::budget_param_serialization_contract -- --ignored
    #[tokio::test]
    #[ignore = "needs a real Postgres; set POSTGRES_TEST_URL"]
    async fn budget_param_serialization_contract() {
        let url = std::env::var("POSTGRES_TEST_URL").expect("POSTGRES_TEST_URL");
        let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let none: Option<String> = None;
        let some: Option<String> = Some("12.3400".to_string());
        // The shipped bug — and note it fails even for NULL, because the type
        // check precedes any NULL handling. That is why no input avoided it.
        assert!(
            client
                .query_one("SELECT $1::numeric", &[&none])
                .await
                .is_err(),
            "bare $1::numeric must fail Option<String> serialization, even for None"
        );
        assert!(
            client
                .query_one("SELECT $1::numeric", &[&some])
                .await
                .is_err(),
            "bare $1::numeric must fail Option<String> serialization for Some too"
        );
        // The fix.
        for v in [&none, &some] {
            client
                .query_one("SELECT $1::text::numeric", &[v])
                .await
                .expect("text-routed numeric must serialize and round-trip");
        }
    }
}
