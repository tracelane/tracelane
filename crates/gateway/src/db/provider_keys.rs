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
    pub tenant_id: Uuid,
    pub provider_id: String,
    pub ciphertext_b64: String,
    pub last4: String,
}

impl From<&Row> for ProviderKeyRow {
    fn from(r: &Row) -> Self {
        Self {
            tenant_id: r.get(0),
            provider_id: r.get(1),
            ciphertext_b64: r.get(2),
            last4: r.get(3),
        }
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
            "SELECT tenant_id, provider_id, ciphertext_b64, last4
             FROM provider_keys
             WHERE tenant_id = $1 AND provider_id = $2",
            &[tenant_id.as_uuid(), &provider_id],
        )
        .await
        .context("SELECT provider_keys")?;
    Ok(row.as_ref().map(ProviderKeyRow::from))
}

/// List every provider key registered for the tenant. Used by the
/// `GET /v1/byok/provider-keys` endpoint to render the settings panel.
pub async fn list(pool: &Pool, tenant_id: &TenantId) -> Result<Vec<ProviderKeyRow>> {
    let client = pool.get().await.map_err(|e| anyhow!("pool: {e}"))?;
    let rows = client
        .query(
            "SELECT tenant_id, provider_id, ciphertext_b64, last4
             FROM provider_keys
             WHERE tenant_id = $1
             ORDER BY provider_id",
            &[tenant_id.as_uuid()],
        )
        .await
        .context("SELECT provider_keys (list)")?;
    Ok(rows.iter().map(ProviderKeyRow::from).collect())
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
/// B-116: `last4_of` assumes a credential is an opaque string — true for every
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
use std::time::{Duration, Instant};

const KEY_CACHE_TTL: Duration = Duration::from_secs(300);

/// Process-wide BYOK key cache. Keyed by `(tenant_uuid, provider_id)`.
/// Values hold `SecretString` so plaintext stays wrapped + zeroized on
/// drop. TTL is 5 minutes — short enough that a customer revocation
/// (via DELETE on `provider_keys`) takes effect within the hour; long
/// enough that the hot path almost never hits Postgres.
struct CachedKey {
    secret: Arc<SecretString>,
    fetched_at: Instant,
}

impl CachedKey {
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
pub fn cache_decrypted(tenant_id: &TenantId, provider_id: &str, secret: Arc<SecretString>) {
    cache().load().insert(
        (*tenant_id.as_uuid(), provider_id.to_string()),
        CachedKey {
            secret,
            fetched_at: Instant::now(),
        },
    );
}

/// Hot-path cache lookup. Returns `Some` only when the entry is fresh.
pub fn lookup_cached(tenant_id: &TenantId, provider_id: &str) -> Option<Arc<SecretString>> {
    cache()
        .load()
        .get(&(*tenant_id.as_uuid(), provider_id.to_string()))
        .filter(|entry| entry.is_fresh())
        .map(|entry| Arc::clone(&entry.secret))
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

    // ── B-116: fingerprints for structured credentials ───────────────────────

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

    /// THE B-116 REGRESSION: the raw tail of a service-account JSON is its
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
