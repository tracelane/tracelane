//! `provider_keys` table — per-tenant BYOK provider API keys on the
//! gateway hot path (A4 / R-launch).
//!
//! ## Threat model
//!
//! Pre-A4: every tenant was routed through the same env-var-resolved
//! provider key (single-tenant blast radius). The marketing claim in
//! SECURITY.md / CLAUDE.md ("BYOK only — provider API keys envelope-
//! encrypted at rest with AES-256-GCM via ring") was false for the
//! provider hot path.
//!
//! Post-A4: customers store one ciphertext per (tenant, provider)
//! family in this table. The gateway hot path:
//!   1. Look up `(tenant_id, provider_id)`. Hot-path cache via
//!      `BYOK_KEY_CACHE` (`arc-swap` + `DashMap`) keeps the cost to
//!      ~1us when the key is hot.
//!   2. On cache miss, query Postgres + decrypt with
//!      `ByokMasterKey::decrypt_with_context` bound to
//!      `provider_key_aad(tenant_id, provider_id)`.
//!   3. On full miss (no row, or pool unavailable), fall back to the
//!      legacy env-var path — back-compat for the migration window.
//!
//! Plaintext keys are wrapped in `secrecy::SecretString` and never
//! cloned into a `String`. The cache holds `SecretString` values so
//! `Zeroize`-on-drop applies.

use anyhow::{Context as _, Result, anyhow};
use deadpool_postgres::Pool;
use secrecy::SecretString;
use tokio_postgres::Row;
use uuid::Uuid;

use tracelane_shared::TenantId;

/// One row of `provider_keys`. `ciphertext_b64` is the BYOK v2 wire blob.
#[derive(Debug, Clone)]
pub struct ProviderKeyRow {
    // `tenant_id: Uuid` (deleted 2026-09-12, B-390) — never read by either
    // caller (`byok_api/provider_keys_api.rs`, `server.rs`); both already
    // scoped their query by tenant, so the row's own copy was redundant.
    // The SELECT column list and its `r.get(N)` positions are unchanged —
    // only the struct field and its assignment were removed.
    pub provider_id: String,
    pub ciphertext_b64: String,
    pub last4: String,
    pub saved_at: chrono::DateTime<chrono::Utc>,
    pub last_validation: Option<KeyValidation>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyValidation {
    pub status: String,
    pub reason: String,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<&Row> for ProviderKeyRow {
    type Error = anyhow::Error;
    fn try_from(r: &Row) -> Result<Self> {
        Ok(Self {
            provider_id: r.get(1),
            ciphertext_b64: r.get(2),
            last4: r.get(3),
            saved_at: r.get(4),
            last_validation: r
                .get::<_, Option<String>>(5)
                .map(|v| serde_json::from_str(&v))
                .transpose()?,
        })
    }
}

/// Insert / overwrite the per-(tenant, provider) ciphertext.
///
/// Caller is responsible for calling `ByokMasterKey::encrypt_with_context`
/// with `provider_key_aad(tenant_id, provider_id)` so the stored blob
/// is bound to the row it's written to.
pub async fn upsert(
    pool: &Pool,
    tenant_id: &TenantId,
    provider_id: &str,
    ciphertext_b64: &str,
    last4: &str,
) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "INSERT INTO provider_keys (tenant_id, provider_id, ciphertext_b64, last4)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, provider_id) DO UPDATE
                SET ciphertext_b64 = EXCLUDED.ciphertext_b64,
                    last4          = EXCLUDED.last4,
                    updated_at     = NOW()",
            &[tenant_id.as_uuid(), &provider_id, &ciphertext_b64, &last4],
        )
        .await
        .context("UPSERT provider_keys")?;
    Ok(())
}

/// Fetch the ciphertext for one (tenant, provider) pair. Returns
/// `Ok(None)` when there is no row — the caller falls back to the
/// legacy env-var path.
pub async fn get(
    pool: &Pool,
    tenant_id: &TenantId,
    provider_id: &str,
) -> Result<Option<ProviderKeyRow>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let row = client
        .query_opt(
            "SELECT tenant_id, provider_id, ciphertext_b64, last4, updated_at, NULL::text
             FROM provider_keys
             WHERE tenant_id = $1 AND provider_id = $2",
            &[tenant_id.as_uuid(), &provider_id],
        )
        .await
        .context("SELECT provider_keys")?;
    row.as_ref().map(ProviderKeyRow::try_from).transpose()
}

/// List every provider key registered for the tenant. Used by the
/// `GET /v1/byok/provider-keys` endpoint to render the settings panel.
pub async fn list(pool: &Pool, tenant_id: &TenantId) -> Result<Vec<ProviderKeyRow>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            "SELECT p.tenant_id, p.provider_id, p.ciphertext_b64, p.last4, p.updated_at,
                (SELECT (a.after_json -> 'validation')::text FROM admin_audit_log a
                 WHERE a.actor_workspace_id = p.tenant_id AND a.target_id = p.provider_id
                   AND a.target_type = 'provider_key' AND a.action = 'provider_key.validate'
                   AND (a.after_json ->> 'saved_at')::timestamptz = p.updated_at
                 ORDER BY a.occurred_at DESC, a.id DESC LIMIT 1)
             FROM provider_keys p
             WHERE p.tenant_id = $1
             ORDER BY p.provider_id",
            &[tenant_id.as_uuid()],
        )
        .await
        .context("SELECT provider_keys (list)")?;
    rows.iter().map(ProviderKeyRow::try_from).collect()
}

/// Record only a classified verdict for the exact version that was checked.
/// # Errors
/// Fail CLOSED on storage errors. A concurrent replacement returns false, so the
/// caller never labels the replacement with an older credential's result.
#[tracing::instrument(skip(pool, tenant, source, actor, result))]
pub async fn record_validation(
    pool: &Pool,
    tenant: &TenantId,
    source: &ProviderKeyRow,
    actor: &str,
    result: &KeyValidation,
) -> Result<bool> {
    let json = serde_json::to_string(
        &serde_json::json!({"saved_at": source.saved_at, "validation": result}),
    )?;
    let client = pool.get().await?;
    let written = client.execute(
        "INSERT INTO admin_audit_log (actor_user_id, actor_workspace_id, action, target_type, target_id, after_json)
         SELECT $4, tenant_id, 'provider_key.validate', 'provider_key', provider_id, $5::text::jsonb
         FROM provider_keys WHERE tenant_id = $1 AND provider_id = $2 AND updated_at = $3",
        &[tenant.as_uuid(), &source.provider_id, &source.saved_at, &actor, &json],
    ).await?;
    Ok(written == 1)
}

/// Delete a single provider key.
pub async fn delete(pool: &Pool, tenant_id: &TenantId, provider_id: &str) -> Result<()> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    client
        .execute(
            "DELETE FROM provider_keys WHERE tenant_id = $1 AND provider_id = $2",
            &[tenant_id.as_uuid(), &provider_id],
        )
        .await
        .context("DELETE provider_keys")?;
    Ok(())
}

/// Extract the last 4 chars of the plaintext for display. Used to render
/// `sk-…abcd` in the settings panel. Caller passes the plaintext borrowed
/// from a `SecretString`; we never log or persist anything else.
///
/// Correct for an **opaque API key**, where the tail is a stable, meaningful,
/// non-secret suffix. NOT correct for a structured credential — see
/// [`fingerprint_of`], which callers should prefer.
pub fn last4_of(plaintext: &str) -> String {
    let n = plaintext.chars().count();
    if n <= 4 {
        return "…".repeat(n);
    }
    plaintext.chars().skip(n - 4).collect()
}

/// A short, non-secret, human-matchable fingerprint for a stored credential.
///
/// `last4_of` assumes a credential is an opaque string — true for every
/// provider until the Vertex adapter introduced the first **structured** one, a
/// ~2.4KB service-account JSON. Its last four characters are `m"\n}` — the tail of
/// `"googleapis.com"`, a quote, an internal newline, and the closing brace. That
/// is the JSON's *syntax*: identical for every service account ever uploaded, so
/// it identifies nothing, and the newline lands raw in the settings UI. (The
/// upload's `.trim()` cannot help — the newline is interior, not trailing.)
///
/// For `vertex` we use the last 4 of the service account's **`private_key_id`**,
/// which is exactly the identifier Google shows in its own key list — so a
/// customer can match what we stored against the GCP console. It is a public key
/// *identifier*, not key material (`gcloud iam service-accounts keys list` prints
/// it), so surfacing 4 chars of it is no more disclosive than an API key's tail.
///
/// Falls back to `last4_of` for opaque keys and for any vertex blob we cannot
/// parse — a display field must never be the reason an upload fails.
pub fn fingerprint_of(provider_id: &str, plaintext: &str) -> String {
    if provider_id == "vertex"
        && let Some(id) = service_account_key_id(plaintext)
    {
        return last4_of(&id);
    }
    last4_of(plaintext)
}

/// Pull `private_key_id` out of a service-account JSON, if present and non-empty.
fn service_account_key_id(plaintext: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(plaintext).ok()?;
    let id = v.get("private_key_id")?.as_str()?;
    (!id.is_empty()).then(|| id.to_owned())
}

// ---------------------------------------------------------------------
// Hot-path cache (A4)
// ---------------------------------------------------------------------

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// **900s, raised from 300s (B-256).**
///
/// The comment this replaces claimed 300s was "long enough that the hot path
/// almost never hits Postgres". Measurement disproved it: production requests
/// arrive roughly every 400 SECONDS, so a 300-second entry was already expired
/// when the next request needed it, and the fetch-plus-decrypt cost **16.0-19.8ms
/// on every request** across three prod samples on 2026-08-18. The claim was not
/// merely optimistic, it was inverted — the hot path hit Postgres almost every
/// time. Where a comment and the measurement disagree, the comment is the defect.
const KEY_CACHE_TTL: Duration = Duration::from_secs(900);

/// Process-wide BYOK key cache. Keyed by `(tenant_uuid, provider_id)`.
/// Values hold `SecretString` so plaintext stays wrapped + zeroized on
/// drop.
///
/// **Raising the TTL does not widen the revocation window, because eviction is
/// explicit:** both provider-key write paths call [`invalidate`]
/// (`byok_api/provider_keys_api.rs`, on upsert and on delete), so a customer
/// rotating or removing a key takes effect on the NEXT request whatever this
/// value is. The TTL is the backstop for a change that did not come through
/// those routes.
///
/// **Its honest limit,** the same one the capability registry carries: that
/// invalidation is process-local. One gateway instance makes it complete; two
/// would make this TTL the cross-instance bound, and the fix then is a broadcast
/// invalidation rather than a different number here.
struct CachedKey {
    secret: Arc<SecretString>,
    fetched_at: Instant,
    /// B-568 F2: set by the ONE stale reader that claims the background refresh,
    /// cleared when that refresh fails (so the next reader retries). A renewed
    /// entry is a new `CachedKey`, so it starts unclaimed.
    refreshing: std::sync::atomic::AtomicBool,
}

impl CachedKey {
    fn new(secret: Arc<SecretString>) -> Self {
        Self {
            secret,
            fetched_at: Instant::now(),
            refreshing: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < KEY_CACHE_TTL
    }
}

type KeyCacheMap = DashMap<(Uuid, String), CachedKey>;

static BYOK_KEY_CACHE: OnceLock<Arc<ArcSwap<KeyCacheMap>>> = OnceLock::new();

fn cache() -> &'static Arc<ArcSwap<KeyCacheMap>> {
    BYOK_KEY_CACHE.get_or_init(|| Arc::new(ArcSwap::from_pointee(DashMap::new())))
}

/// Cache a freshly-decrypted plaintext. Caller has already done the
/// decrypt and built the `SecretString`. Keeping this split from the
/// decrypt step lets us compile this module without a dep on the
/// `byok` module (the `tests/postgres_tenant_integration.rs` harness
/// pulls `db/mod.rs` in via `#[path]` and would otherwise need `byok`
/// too).
/// Maximum cached provider keys. Entries hold a `SecretString`, so this also
/// bounds how much decrypted key material is resident at once — a reason to cap
/// it that has nothing to do with memory.
const MAX_CACHED_KEYS: usize = 50_000;

pub fn cache_decrypted(tenant_id: &TenantId, provider_id: &str, secret: Arc<SecretString>) {
    let map = cache().load();
    // BOUND THE MAP. Before this it grew without limit: entries left only via an
    // explicit `invalidate`, so every (tenant, provider) pair ever seen stayed
    // resident for the process lifetime, decrypted, even after going permanently
    // cold. Raising KEY_CACHE_TTL to 900s would have tripled how long each stale
    // entry lingered, so bounding this is a PRECONDITION of that raise, not a
    // separate improvement.
    //
    // Prune only when full, expired entries first. This runs on the cache-MISS
    // path — a hit returns before reaching here — so even the pruning case is
    // off the warm hot path.
    if map.len() >= MAX_CACHED_KEYS {
        map.retain(|_, entry| entry.is_fresh());
        if map.len() >= MAX_CACHED_KEYS {
            // Still full of LIVE entries. Skip caching rather than evict someone
            // else's key: this request then pays a fetch, which is a latency
            // cost it can attribute to itself. Evicting at random hands the same
            // cost to an unrelated tenant AND makes it unattributable.
            tracing::warn!(
                cached = map.len(),
                cap = MAX_CACHED_KEYS,
                "BYOK key cache is full of live entries — not caching this key; provider-key \
                 fetches will hit the control plane until entries expire"
            );
            return;
        }
    }
    map.insert(
        (*tenant_id.as_uuid(), provider_id.to_string()),
        CachedKey::new(secret),
    );
}

// ---------------------------------------------------------------------
// Stale-while-revalidate (B-568 F2, 2026-09-27)
// ---------------------------------------------------------------------
//
// THE PROBLEM. Prod traffic is sparse — the hourly dogfood and canary, and any
// customer who calls less often than every 15 minutes. Every such request found
// its key past `KEY_CACHE_TTL` and paid pool checkout + SELECT + decrypt on the
// request path (measured 16-20 ms warm-pool on 2026-08-18; with the pooler having
// closed its connections after idle, a fresh TCP + TLS + SCRAM to Frankfurt on
// top — `db/keepalive.rs`). The API-key and entitlement caches already serve a
// last-known answer and re-check off-path; this was the one control-plane read on
// the hot path that did not.
//
// THE MECHANISM. Past the TTL, and inside `TTL + key_stale_max()`, the last
// decrypted key is SERVED and exactly ONE background refresh (an `AtomicBool`
// claim on the entry) re-reads and re-decrypts the row:
//   • row present + decrypts   → the entry is renewed (fresh again)
//   • row gone, or no longer decrypts under its AAD → the entry is EVICTED, so the
//     NEXT request takes the inline path and is refused `provider_not_configured`
//     / `provider_key_unusable` — FAIL-CLOSED once the refresh has observed it
//   • the store could not be read → the entry keeps serving (inside the bound) and
//     the claim is released so the next request retries. A lookup error is "cannot
//     tell", not "revoked" — the same call the auth cache makes (B-303)
// A refresh result is applied ONLY if the entry is still the one it refreshed
// (`Arc::ptr_eq`): a customer's replace/delete through the API `invalidate`s, and
// a refresh that read the old row must never be written back over that.
//
// THE STALENESS BOUND, stated here as the spec requires. A key changed OUTSIDE the
// two BYOK write routes (which `invalidate` in-process, so they are immediate):
//   • is used by AT MOST the requests that arrive before the one refresh returns —
//     one control-plane round trip, milliseconds; then evicted or renewed;
//   • is never served once `KEY_CACHE_TTL + key_stale_max()` has passed since it
//     was last read from the store (default 900 s + 6 h), whatever happens.
// What is served is the SAME tenant's own key for the SAME provider — the AAD binds
// it to `(tenant, provider)` — so staleness can never cross a tenant boundary, and
// the operator's environment key is never involved (B-380 is untouched).
// Residency is unchanged: entries already stayed in memory until evicted or pruned
// at `MAX_CACHED_KEYS`; this changes whether an OLD entry is USED, not how long it
// lives.

/// Default for how long past `KEY_CACHE_TTL` a key may still be served while it is
/// re-checked: 6 h. Wider than the hourly dogfood/canary gap on purpose — a bound
/// shorter than the gap between a tenant's requests is B-256's defect again (the
/// entry is gone at exactly the moment it is needed).
const DEFAULT_KEY_STALE_MAX_SECS: u64 = 21_600;
/// Hard ceiling. An env typo must not be able to serve a key for days.
const MAX_KEY_STALE_MAX_SECS: u64 = 86_400;

/// `TRACELANE_BYOK_STALE_MAX_SECS`, clamped to `0..=86_400`. `0` turns
/// stale-while-revalidate OFF (exactly the pre-F2 cache). Garbage or an
/// out-of-range value falls back to the DEFAULT, never to the maximum.
///
/// Operator config, read once — like `TRACELANE_AUTH_CACHE_TTL_SECS` — and not a
/// `billing_policy` row: it bounds a security property of a cache the control
/// plane itself sits behind, and it is read before any control-plane round trip
/// could supply it (spec B-568 §2.3, the same argument as F2b).
fn parse_key_stale_max(raw: Option<&str>) -> Duration {
    Duration::from_secs(
        raw.and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s <= MAX_KEY_STALE_MAX_SECS)
            .unwrap_or(DEFAULT_KEY_STALE_MAX_SECS),
    )
}

fn key_stale_max() -> Duration {
    static B: OnceLock<Duration> = OnceLock::new();
    *B.get_or_init(|| {
        parse_key_stale_max(
            std::env::var("TRACELANE_BYOK_STALE_MAX_SECS")
                .ok()
                .as_deref(),
        )
    })
}

#[derive(Debug, PartialEq, Eq)]
enum Freshness {
    Fresh,
    Stale,
    Expired,
}

/// Pure so the bound is testable without aging an `Instant`.
fn classify(age: Duration, stale_max: Duration) -> Freshness {
    if age < KEY_CACHE_TTL {
        Freshness::Fresh
    } else if age < KEY_CACHE_TTL + stale_max {
        Freshness::Stale
    } else {
        Freshness::Expired
    }
}

/// Stale entries served while one refresh ran off-path — `/health`'s
/// `byok_cache.stale_served` (a counter, not a log line).
pub static BYOK_STALE_SERVED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Entries a refresh evicted because the key was gone or undecryptable —
/// `/health`'s `byok_cache.refresh_evicted`.
pub static BYOK_REFRESH_EVICTED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// What the stale-while-revalidate lookup found (B-568 F2).
pub enum CachedLookup {
    /// Inside the TTL. Serve it; nothing else to do.
    Fresh(Arc<SecretString>),
    /// Past the TTL, inside the staleness bound. Serve it. `refresh` is `true` for
    /// exactly ONE caller, which must spawn the re-read and report it back through
    /// [`complete_refresh`].
    Stale {
        secret: Arc<SecretString>,
        refresh: bool,
    },
    /// Nothing servable — resolve inline, on the request path.
    Miss,
}

/// What a background refresh observed.
pub enum RefreshOutcome {
    /// The row is there and decrypted — the re-read key.
    Renewed(Arc<SecretString>),
    /// No row, or it no longer decrypts under its AAD. Evict (fail-CLOSED).
    Gone,
    /// The store could not be read. Keep serving inside the bound; re-arm.
    Failed,
}

/// Hot-path lookup with stale-while-revalidate. See the block comment above.
///
/// Supersedes `lookup_cached` (fresh-only; deleted 2026-09-27, B-568 F2) — its one
/// caller, `server::dispatch::resolve_provider_key`, moved here. The warm path is
/// unchanged: the same one `DashMap` probe, plus an `elapsed()` comparison.
pub fn lookup_swr(tenant_id: &TenantId, provider_id: &str) -> CachedLookup {
    let map = cache().load();
    let Some(entry) = map.get(&(*tenant_id.as_uuid(), provider_id.to_string())) else {
        return CachedLookup::Miss;
    };
    match classify(entry.fetched_at.elapsed(), key_stale_max()) {
        Freshness::Fresh => CachedLookup::Fresh(Arc::clone(&entry.secret)),
        Freshness::Stale => {
            BYOK_STALE_SERVED_TOTAL.fetch_add(1, Ordering::Relaxed);
            let refresh = entry
                .refreshing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
            CachedLookup::Stale {
                secret: Arc::clone(&entry.secret),
                refresh,
            }
        }
        Freshness::Expired => CachedLookup::Miss,
    }
}

/// Apply a background refresh's result — but ONLY to the entry it refreshed.
/// If the entry was invalidated (a customer replaced or deleted the key through
/// the API) or replaced by a newer fill while the refresh was in flight, the
/// result is dropped: a refresh that read the old row must never overwrite that.
pub fn complete_refresh(
    tenant_id: &TenantId,
    provider_id: &str,
    served: &Arc<SecretString>,
    outcome: RefreshOutcome,
) {
    let map = cache().load();
    let key = (*tenant_id.as_uuid(), provider_id.to_string());
    match outcome {
        RefreshOutcome::Renewed(secret) => {
            if let Some(mut entry) = map.get_mut(&key)
                && Arc::ptr_eq(&entry.secret, served)
            {
                *entry = CachedKey::new(secret);
            }
        }
        RefreshOutcome::Gone => {
            if map
                .remove_if(&key, |_, entry| Arc::ptr_eq(&entry.secret, served))
                .is_some()
            {
                BYOK_REFRESH_EVICTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
        }
        RefreshOutcome::Failed => {
            if let Some(entry) = map.get(&key)
                && Arc::ptr_eq(&entry.secret, served)
            {
                entry.refreshing.store(false, Ordering::Release);
            }
        }
    }
}

#[cfg(test)]
fn cache_decrypted_at(
    tenant_id: &TenantId,
    provider_id: &str,
    secret: Arc<SecretString>,
    fetched_at: Instant,
) {
    cache().load().insert(
        (*tenant_id.as_uuid(), provider_id.to_string()),
        CachedKey {
            fetched_at,
            ..CachedKey::new(secret)
        },
    );
}

/// Invalidate one cache entry. Called after `upsert` / `delete` so a
/// fresh API call sees the change immediately rather than waiting on
/// TTL expiry.
pub fn invalidate(tenant_id: &TenantId, provider_id: &str) {
    cache()
        .load()
        .remove(&(*tenant_id.as_uuid(), provider_id.to_string()));
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    // ── B-568 F2: stale-while-revalidate ────────────────────────────────

    fn fresh_tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::new_v4())
    }

    fn secret(s: &str) -> Arc<SecretString> {
        Arc::new(SecretString::from(s.to_string()))
    }

    /// An entry just past the TTL — well inside the staleness bound.
    fn just_expired() -> Instant {
        Instant::now()
            .checked_sub(KEY_CACHE_TTL + Duration::from_secs(1))
            .expect("the monotonic clock must be older than the TTL for this test")
    }

    fn served(l: CachedLookup) -> (Option<String>, Option<bool>) {
        match l {
            CachedLookup::Fresh(s) => (Some(s.expose_secret().to_owned()), None),
            CachedLookup::Stale { secret, refresh } => {
                (Some(secret.expose_secret().to_owned()), Some(refresh))
            }
            CachedLookup::Miss => (None, None),
        }
    }

    /// Past the TTL the last key is SERVED (no round trip on the request path),
    /// and exactly ONE caller is told to refresh — a burst of sparse requests must
    /// not become a burst of control-plane reads.
    #[test]
    fn a_stale_key_is_served_and_exactly_one_refresh_is_claimed() {
        let t = fresh_tenant();
        cache_decrypted_at(&t, "openai", secret("sk-old"), just_expired());
        assert_eq!(
            served(lookup_swr(&t, "openai")),
            (Some("sk-old".into()), Some(true))
        );
        assert_eq!(
            served(lookup_swr(&t, "openai")),
            (Some("sk-old".into()), Some(false)),
            "a second stale read must NOT claim a second refresh"
        );
    }

    /// FAIL-CLOSED: once the refresh observes the key is gone (deleted, revoked,
    /// or no longer decryptable), the next request gets NOTHING from the cache
    /// and takes the inline path, which answers `NotConfigured` / `Unusable`.
    #[test]
    fn a_refresh_that_observes_the_key_gone_evicts_it() {
        let t = fresh_tenant();
        let old = secret("sk-deleted");
        cache_decrypted_at(&t, "openai", Arc::clone(&old), just_expired());
        let _ = lookup_swr(&t, "openai");
        complete_refresh(&t, "openai", &old, RefreshOutcome::Gone);
        assert_eq!(served(lookup_swr(&t, "openai")), (None, None));
    }

    /// A refresh that could not READ the store (Neon resuming) keeps serving the
    /// last key inside the staleness bound, and re-arms so the next request tries
    /// again — the lookup error is "cannot tell", not "revoked".
    #[test]
    fn a_failed_refresh_keeps_serving_and_rearms() {
        let t = fresh_tenant();
        let old = secret("sk-kept");
        cache_decrypted_at(&t, "openai", Arc::clone(&old), just_expired());
        let _ = lookup_swr(&t, "openai");
        complete_refresh(&t, "openai", &old, RefreshOutcome::Failed);
        assert_eq!(
            served(lookup_swr(&t, "openai")),
            (Some("sk-kept".into()), Some(true)),
            "a failed refresh must re-arm, or one Neon blip freezes the entry"
        );
    }

    /// A successful refresh makes the entry fresh with the RE-READ key — a key
    /// rotated out-of-band is picked up by the refresh, not served forever.
    #[test]
    fn a_renewed_refresh_serves_the_new_key_fresh() {
        let t = fresh_tenant();
        let old = secret("sk-before");
        cache_decrypted_at(&t, "openai", Arc::clone(&old), just_expired());
        let _ = lookup_swr(&t, "openai");
        complete_refresh(
            &t,
            "openai",
            &old,
            RefreshOutcome::Renewed(secret("sk-after")),
        );
        assert_eq!(
            served(lookup_swr(&t, "openai")),
            (Some("sk-after".into()), None)
        );
    }

    /// THE RACE: a customer replaces or deletes the key through the API (which
    /// `invalidate`s) while a refresh that read the OLD row is in flight. The
    /// refresh's answer must be DROPPED, never written back over the invalidation.
    #[test]
    fn a_refresh_that_raced_an_invalidation_is_dropped() {
        let t = fresh_tenant();
        let old = secret("sk-raced");
        cache_decrypted_at(&t, "openai", Arc::clone(&old), just_expired());
        let _ = lookup_swr(&t, "openai");
        invalidate(&t, "openai");
        complete_refresh(
            &t,
            "openai",
            &old,
            RefreshOutcome::Renewed(secret("sk-raced")),
        );
        assert_eq!(
            served(lookup_swr(&t, "openai")),
            (None, None),
            "a refresh must never resurrect an invalidated entry"
        );
        // …and a NEWER fill that landed after the invalidation is not clobbered.
        cache_decrypted(&t, "openai", secret("sk-new"));
        complete_refresh(&t, "openai", &old, RefreshOutcome::Gone);
        assert_eq!(
            served(lookup_swr(&t, "openai")),
            (Some("sk-new".into()), None)
        );
    }

    /// A fresh entry is served as fresh and claims no refresh; tenants never share.
    #[test]
    fn fresh_is_fresh_and_tenants_are_isolated() {
        let a = fresh_tenant();
        let b = fresh_tenant();
        cache_decrypted(&a, "openai", secret("sk-a"));
        assert_eq!(
            served(lookup_swr(&a, "openai")),
            (Some("sk-a".into()), None)
        );
        assert_eq!(served(lookup_swr(&b, "openai")), (None, None));
    }

    /// The staleness bound, as a pure function: fresh below the TTL, stale inside
    /// `TTL + stale_max`, expired at and past it — nothing is served forever.
    #[test]
    fn classify_bounds_staleness() {
        let max = Duration::from_secs(3_600);
        assert_eq!(classify(Duration::from_secs(10), max), Freshness::Fresh);
        assert_eq!(classify(KEY_CACHE_TTL, max), Freshness::Stale);
        assert_eq!(
            classify(KEY_CACHE_TTL + max - Duration::from_secs(1), max),
            Freshness::Stale
        );
        assert_eq!(classify(KEY_CACHE_TTL + max, max), Freshness::Expired);
        // A zero bound turns stale-while-revalidate OFF: exactly the pre-F2 cache.
        assert_eq!(classify(KEY_CACHE_TTL, Duration::ZERO), Freshness::Expired);
    }

    /// The operator bound is clamped and fails CLOSED to the default on garbage —
    /// an env typo must not be able to serve a key for days.
    #[test]
    fn the_stale_bound_parses_and_clamps() {
        let d = Duration::from_secs(DEFAULT_KEY_STALE_MAX_SECS);
        assert_eq!(parse_key_stale_max(None), d);
        assert_eq!(parse_key_stale_max(Some("nonsense")), d);
        assert_eq!(parse_key_stale_max(Some("999999999")), d);
        assert_eq!(parse_key_stale_max(Some("0")), Duration::ZERO);
        assert_eq!(parse_key_stale_max(Some(" 600 ")), Duration::from_secs(600));
    }

    #[test]
    fn last4_shows_last_four_chars() {
        assert_eq!(last4_of("sk-abcdef123456"), "3456");
        assert_eq!(last4_of("sk-ABCDE"), "BCDE");
    }

    #[test]
    fn last4_pads_when_input_too_short() {
        assert_eq!(last4_of(""), "");
        assert_eq!(last4_of("ab"), "……");
    }

    // ──: fingerprints for structured credentials ───────────────────────

    /// An obviously-fake service account shaped like the real thing. `key_id` is
    /// the `private_key_id` — a PUBLIC identifier (gcloud prints it), not key
    /// material.
    fn fake_sa(key_id: &str) -> String {
        format!(
            r#"{{"type":"service_account","project_id":"p","private_key_id":"{key_id}",
                 "private_key":"-----BEGIN PRIVATE KEY-----\nFAKEunittestonly\n-----END PRIVATE KEY-----\n",
                 "client_email":"sa@p.iam.gserviceaccount.com"}}"#
        )
    }

    /// THE REGRESSION: the raw tail of a service-account JSON is its
    /// closing syntax, not a fingerprint. Must be a clean 4 chars of the
    /// `private_key_id` — the value GCP's own console shows.
    #[test]
    fn vertex_fingerprint_comes_from_private_key_id_not_json_syntax() {
        let sa = fake_sa("a30fca87354a9e9de5053a319eb379728751ec0b");
        let fp = fingerprint_of("vertex", &sa);
        assert_eq!(fp, "ec0b", "must be the private_key_id tail, got {fp:?}");
        // The pre-fix behaviour, asserted explicitly so the bug can't come back.
        assert!(
            !fp.contains('\n') && !fp.contains('}') && !fp.contains('"'),
            "fingerprint must be printable — a newline mangles the settings UI: {fp:?}"
        );
    }

    /// The property the old code FAILED: every service-account JSON ends the same
    /// way, so `last4_of` collapsed them all to one value. Two different accounts
    /// must be distinguishable — that is the entire point of the field.
    #[test]
    fn two_service_accounts_have_different_fingerprints() {
        let a = fingerprint_of(
            "vertex",
            &fake_sa("1111111111111111111111111111111111111aaaa"),
        );
        let b = fingerprint_of(
            "vertex",
            &fake_sa("2222222222222222222222222222222222222bbbb"),
        );
        assert_ne!(a, b, "distinct accounts must not collide");
        // Demonstrate the defect being fixed: raw last4 DOES collide.
        assert_eq!(
            last4_of(&fake_sa("1111111111111111111111111111111111111aaaa")),
            last4_of(&fake_sa("2222222222222222222222222222222222222bbbb")),
            "sanity: raw last4 collides on JSON syntax — the reason fingerprint_of exists"
        );
    }

    /// Opaque keys are unchanged — the path that was always correct must not
    /// regress.
    #[test]
    fn opaque_keys_still_use_the_raw_tail() {
        assert_eq!(fingerprint_of("anthropic", "sk-ant-abcdefEgAA"), "EgAA");
        assert_eq!(fingerprint_of("openai", "sk-proj-abcdef1234"), "1234");
    }

    /// A display field must never fail an upload. An unparseable or key_id-less
    /// vertex blob degrades to the old behaviour rather than erroring.
    #[test]
    fn unparseable_vertex_blob_falls_back_instead_of_failing() {
        assert_eq!(fingerprint_of("vertex", "not json at all wxyz"), "wxyz");
        // Valid JSON, no private_key_id → fall back rather than panic.
        let no_id = r#"{"type":"service_account","project_id":"abcd"}"#;
        assert_eq!(fingerprint_of("vertex", no_id), last4_of(no_id));
    }
}
