//! Customer-facing API-key mint endpoint.
//!
//! `POST /v1/keys` — mints a `tlane_<base62>` API key for the authenticated
//! tenant and returns the raw key exactly once. Mounted only when Postgres is
//! configured (`crate::db::global_pool().is_some()`), alongside the BYOK and
//! prompt-management routes.
//!
//! ## Why the gateway mints (not the dashboard)
//!
//! The dashboard runs on the Cloudflare Workers runtime, where the web minter's
//! WASM Argon2 (`hash-wasm`) fails at runtime — every "+ New key" click 500'd
//! . Minting here runs RustCrypto Argon2 natively and reuses the exact
//! same peppered-HMAC + Argon2id derivation as the verifier
//! (`crate::db::api_keys`), so keys stay byte-compatible: a key minted here
//! verifies through `lookup_tenant_by_key_body` unchanged, and any key minted by
//! the legacy web path (non-CF deploys) stays valid too.
//!
//! ## Tenant isolation
//!
//! The tenant id is sourced ONLY from `Claims.tenant_id`
//! (`crate::auth::validate_authorization`) — never a path, query, or body field.
//! The dashboard proxies the end-user's WorkOS JWT here; the JWT `org_id` →
//! internal-UUID bridge (ADR-042) yields the tenant the row is inserted under.

use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::api_keys::MintedKey;
use tracelane_shared::TenantId;

/// Upper bound on the user-supplied key name (defensive; the column is TEXT).
const MAX_KEY_NAME_LEN: usize = 128;

/// Mint seam — lets the handler be unit-tested without Postgres (real impl is
/// [`PgKeyMinter`]; tests use an in-module mock). Off the request hot path, so
/// `async_trait` is fine — CLAUDE.md bans it only on the gateway hot path.
#[async_trait::async_trait]
pub trait KeyMinter: Send + Sync {
    /// Mint a key for `tenant`, returning the row plus the one-time raw secret.
    /// `minted_by` is the WorkOS user id of the minting user (for §3
    /// key-revoke-on-member-removal); `None` for API-key / service auth.
    async fn mint(
        &self,
        tenant: &TenantId,
        name: &str,
        minted_by: Option<&str>,
        opts: crate::db::api_keys::MintOptions,
    ) -> Result<MintedKey>;
}

/// Production minter — inserts through the shared Postgres pool.
pub struct PgKeyMinter {
    pub pool: deadpool_postgres::Pool,
}

#[async_trait::async_trait]
impl KeyMinter for PgKeyMinter {
    async fn mint(
        &self,
        tenant: &TenantId,
        name: &str,
        minted_by: Option<&str>,
        opts: crate::db::api_keys::MintOptions,
    ) -> Result<MintedKey> {
        crate::db::api_keys::mint(&self.pool, tenant, name, minted_by, opts).await
    }
}

/// Router state — the mint seam behind an `Arc` (clone-cheap per request).
#[derive(Clone)]
pub struct KeyRoutesState {
    pub minter: Arc<dyn KeyMinter>,
}

/// `POST /v1/keys` request body.
#[derive(Debug, Deserialize)]
struct CreateKeyBody {
    name: String,
    /// A13. Omitted ⇒ the full set, spelled out (see `db::api_keys::mint`).
    /// An UNRECOGNISED slug is a 400 here rather than a silent drop: at mint
    /// time the caller is a human choosing capabilities, and quietly ignoring
    /// what they asked for would hand back a key that does less than the UI just
    /// told them it does. (At AUTH time the same slug denies silently — there
    /// the caller is a machine presenting a credential, and the safe answer is
    /// simply "not granted".)
    #[serde(default)]
    scope: Option<Vec<String>>,
    /// RFC3339. Must be in the future.
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    budget_usd_monthly: Option<f64>,
    /// GWY-43. Requests-per-minute ceiling for this one key. Omitted ⇒ the key
    /// inherits the tenant's plan tier, exactly as every key did before GWY-43.
    ///
    /// Wire type is `i64`, not `u32`, ON PURPOSE: a `u32` field makes serde
    /// refuse a negative before the handler runs, and the caller gets axum's
    /// 422 deserialization text instead of the 400 naming the field that the
    /// budget next to it returns. Taking the wider type keeps ONE validator,
    /// here, for every out-of-range value.
    #[serde(default)]
    rate_limit_rpm: Option<i64>,
}

/// `POST /v1/keys` response. camelCase to match the dashboard's `CreateResult`
/// (`apps/web/components/settings/ApiKeyManager.tsx`). `rawKey` is shown once.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateKeyResponse {
    id: String,
    name: String,
    key_prefix: String,
    /// RFC3339 UTC. `null` on a fresh key (matches the list `lastUsedAt`).
    last_used_at: Option<String>,
    created_at: String,
    raw_key: String,
    /// A13. `null` only for a pre-A13 key; every newly minted key is explicit.
    scope: Option<Vec<String>>,
    /// A13. RFC3339 UTC, `null` = never expires.
    expires_at: Option<String>,
    /// GWY-43. The ceilings as VALIDATED here and handed to the INSERT — echoed
    /// back so the 201 reports what the row holds rather than leaving the caller
    /// to assume its input survived. `null` = uncapped / plan default.
    budget_usd_monthly: Option<f64>,
    rate_limit_rpm: Option<i32>,
}

/// The known scope slugs, for every 400 this route emits.
///
/// ONE source for the list so the three refusals (omitted, empty, unknown) can
/// never disagree about the vocabulary — a caller told two different sets of
/// "known scopes" by two errors on the same route learns to trust neither.
fn known_scope_slugs() -> Vec<&'static str> {
    tracelane_shared::api_scope::Scope::all()
        .iter()
        .map(|s| s.as_slug())
        .collect()
}

/// Mount the mint route. Merged in `server.rs` when Postgres is configured.
pub fn routes() -> Router<KeyRoutesState> {
    Router::new().route("/v1/keys", post(create_key_handler))
}

/// Extract the validated claims from the `Authorization` header. Tenant
/// identity + role are sourced ONLY from a verified JWT / API key — never a
/// body or custom header (CLAUDE.md tenant-isolation invariant).
async fn claims_from_auth(
    headers: &HeaderMap,
) -> Result<crate::auth::Claims, (StatusCode, String)> {
    let header = headers.get("authorization").ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    let header_str = header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Authorization must be ASCII".into(),
        )
    })?;
    crate::auth::validate_authorization(header_str)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("auth failed: {e}")))
}

/// POST /v1/keys — mint an API key for the authenticated tenant.
///
/// 201 with `{id,name,keyPrefix,createdAt,lastUsedAt,rawKey}` on success; 401 if
/// unauthenticated; 400 on an empty/oversized name; 500 if minting fails. The
/// raw key is in the body once and is never logged.
#[tracing::instrument(skip(state, headers, body), fields(tenant_id = tracing::field::Empty))]
async fn create_key_handler(
    State(state): State<KeyRoutesState>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyBody>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), (StatusCode, String)> {
    let claims = claims_from_auth(&headers).await?;
    // IDENTITY_TEAM_SPEC §1: viewers cannot mint keys. Members + owners may
    // (API-key / dev auth is grandfathered). Gateway is the authoritative gate.
    if !claims.can_mint_keys() {
        return Err((
            StatusCode::FORBIDDEN,
            crate::auth::role_forbidden_json("member"),
        ));
    }
    let tenant = claims.tenant_id;
    tracing::Span::current().record("tenant_id", tenant.to_string());

    let name = body.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name must not be empty".into()));
    }
    if name.chars().count() > MAX_KEY_NAME_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("name must be at most {MAX_KEY_NAME_LEN} characters"),
        ));
    }

    // ── A13: validate scope / expiry / budget BEFORE minting ───────────────
    // Rejected here rather than at the DB so the caller gets a 400 naming the
    // problem instead of a 500 from a constraint violation.
    let scope = match body.scope {
        // R73 (founder ruling, 2026-08-22) — **AN OMITTED `scope` IS A 400.**
        //
        // This arm used to be `None => None`, with `.with_default_scope()` below
        // filling in `{chat, read, ingest}`. Migration 0024's hand-off note always
        // said the mint route must REQUIRE a scope; the deviation was taken on the
        // stated grounds that requiring one "would 400 every existing caller of
        // `POST /v1/keys` the moment this deploys, the dashboard proxy included."
        //
        // THAT REASON WAS MEASURED AND IS FALSE. Of 37 keys ever minted on prod,
        // 23 carry SQL NULL and 14 an explicit scope — and all 14 explicit ones are
        // revoked, so **zero live keys were minted through this default**. The
        // dashboard cannot reach the arm either: `ApiKeyManager.tsx` gates submit on
        // `scope.length > 0`, and the proxy forwards the field only when present.
        // Self-host cannot reach it at all — minting needs a Postgres control plane
        // that self-host does not run (`README.md:71`).
        //
        // Why REQUIRED beats a narrower default: a default is a decision made by
        // whoever wrote it, for every caller who never reads it. `chat` spends the
        // tenant's provider money, so the quiet path was handing out the one
        // capability with a bill attached. Refusing makes the caller state it.
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "scope is required — a key must state what it may do, because \
                     an omitted scope used to grant `chat`, which spends this \
                     workspace's provider budget. Pass e.g. \"scope\": [\"chat\", \
                     \"read\"]. Known scopes: {}",
                    known_scope_slugs().join(", ")
                ),
            ));
        }
        Some(raw) => {
            if raw.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "scope must not be empty — state at least one. Known scopes: {}",
                        known_scope_slugs().join(", ")
                    ),
                ));
            }
            let mut out = Vec::with_capacity(raw.len());
            for slug in &raw {
                let Some(parsed) = tracelane_shared::api_scope::Scope::from_slug(slug) else {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!(
                            "unknown scope {slug:?} — known scopes: {}",
                            known_scope_slugs().join(", ")
                        ),
                    ));
                };
                // Normalise + de-duplicate so the stored array is canonical.
                let slug = parsed.as_slug().to_string();
                if !out.contains(&slug) {
                    out.push(slug);
                }
            }
            Some(out)
        }
    };

    let expires_at = match body.expires_at.as_deref() {
        None => None,
        Some(raw) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("expires_at must be RFC3339: {e}"),
                    )
                })?
                .with_timezone(&chrono::Utc);
            // An already-expired key would authenticate nothing — almost
            // certainly a mistake, and silently minting a dead credential is
            // worse than refusing.
            if parsed <= chrono::Utc::now() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "expires_at must be in the future".into(),
                ));
            }
            Some(parsed)
        }
    };

    if let Some(b) = body.budget_usd_monthly
        && (!b.is_finite() || b < 0.0)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "budget_usd_monthly must be a finite, non-negative number".into(),
        ));
    }

    // GWY-43 — same shape as the budget check above, one difference: 0 is
    // REFUSED rather than accepted. A zero budget is a coherent (if useless)
    // ceiling, but a zero rate limit is a key that can never be used, and
    // `revoked_at` is how a key is switched off. `api_keys_rate_limit_rpm_positive_chk`
    // (migration 0029) says the same thing at the DB; catching it here turns a
    // constraint-violation 500 into a 400 that names the field. The ceiling is
    // `i32::MAX` because the column is `integer`.
    let rate_limit_rpm = match body.rate_limit_rpm {
        None => None,
        Some(rpm) => match i32::try_from(rpm) {
            Ok(v) if v > 0 => Some(v),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "rate_limit_rpm must be a whole number of requests per minute \
                         between 1 and {} — omit it to use the workspace plan limit",
                        i32::MAX
                    ),
                ));
            }
        },
    };

    let opts = crate::db::api_keys::MintOptions {
        scope,
        expires_at,
        budget_usd_monthly: body.budget_usd_monthly,
        rate_limit_rpm,
    };

    // Record the minting user (WorkOS `sub`) so §3 member-removal can revoke
    // exactly this user's keys. API-key / dev auth has an `apikey:`/`dev-stub`
    // sub — harmless to store; it just won't match a WorkOS user_id on removal.
    let minted_by = claims.sub.clone();
    let minted = state
        .minter
        .mint(&tenant, name, Some(&minted_by), opts)
        .await
        .map_err(|err| {
            // The error chain can reference internal state (pool, pepper); log it,
            // return a terse message. Never surface the raw key or key material.
            //
            // `{err:#}` — the ALTERNATE form — not `%err`. anyhow's plain Display
            // prints ONLY the outermost `.context()` string, so this line logged
            // `INSERT INTO api_keys failed` and discarded the cause. On 2026-08-14
            // that cause was `error serializing parameter 8` and recovering it
            // took four independent probes (schema replay, prepared-statement type
            // inspection, a scratch-table trigger falsification, and a standalone
            // tokio-postgres binding probe) against one line of output. `{:#}`
            // walks the chain and would have printed it first time.
            tracing::error!(error = %format!("{err:#}"), "API key mint failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create API key".into(),
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            id: minted.api_key.id.to_string(),
            name: minted.api_key.name,
            key_prefix: minted.key_prefix,
            last_used_at: None,
            created_at: minted.api_key.created_at.to_rfc3339(),
            raw_key: minted.raw_key,
            scope: minted.api_key.scope,
            expires_at: minted.api_key.expires_at.map(|t| t.to_rfc3339()),
            budget_usd_monthly: body.budget_usd_monthly,
            rate_limit_rpm,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::api_keys::ApiKey;
    use chrono::{DateTime, Utc};
    use std::sync::Mutex;
    use uuid::Uuid;

    const DEV_TENANT: &str = "00000000-0000-0000-0000-000000000001";

    /// Records the tenant it was asked to mint for so tests can prove the
    /// handler passes `Claims.tenant_id` (never a body/header value).
    struct MockKeyMinter {
        seen: Arc<Mutex<Vec<String>>>,
        /// A13: what the handler actually passed down, so a test can assert the
        /// VALIDATED+NORMALISED scope rather than just that minting happened.
        last_opts: Arc<Mutex<Option<crate::db::api_keys::MintOptions>>>,
    }
    #[async_trait::async_trait]
    impl KeyMinter for MockKeyMinter {
        async fn mint(
            &self,
            tenant: &TenantId,
            name: &str,
            _minted_by: Option<&str>,
            opts: crate::db::api_keys::MintOptions,
        ) -> Result<MintedKey> {
            self.seen.lock().unwrap().push(tenant.to_string());
            let scope = opts.scope.clone();
            let expires_at = opts.expires_at;
            *self.last_opts.lock().unwrap() = Some(opts);
            Ok(MintedKey {
                api_key: ApiKey {
                    id: Uuid::nil(),
                    tenant_id: *tenant.as_uuid(),
                    name: name.to_string(),
                    created_at: DateTime::<Utc>::from_timestamp(1_778_000_000, 0).unwrap(),
                    last_used_at: None,
                    revoked_at: None,
                    scope,
                    expires_at,
                },
                key_prefix: "AbC012".into(),
                raw_key: "tlane_MOCKKEYBODYdonotuseinprod".into(),
            })
        }
    }

    // ── A13: scope / expiry validation at the mint edge ────────────────────

    /// A minimal VALID scope, for the tests that are not about scope.
    ///
    /// R73 made `scope` required, so scope validation now short-circuits every
    /// other validator on the route. A test about expiry or budget that omitted
    /// scope would stop asserting what it was written to assert and start
    /// asserting the scope refusal — green for the wrong reason, which is the
    /// shape `docs/reference/TRAPS.md` §1 exists for.
    fn a_scope() -> Option<Vec<String>> {
        Some(vec!["chat".into()])
    }

    fn body_with(
        scope: Option<Vec<String>>,
        expires_at: Option<String>,
        budget: Option<f64>,
    ) -> CreateKeyBody {
        CreateKeyBody {
            name: "k".into(),
            scope,
            expires_at,
            budget_usd_monthly: budget,
            rate_limit_rpm: None,
        }
    }

    /// **An omitted `scope` is REFUSED with a 400 naming the field** — founder
    /// ruling R73, 2026-08-22.
    ///
    /// This test replaces `omitted_scope_is_recorded_explicitly_not_as_null`,
    /// which asserted the opposite (that omission stored `{chat, read, ingest}`)
    /// together with the hand-maintained literal pin
    /// `assert_eq!(got, vec!["chat", "ingest", "read"])`. **That pin going red is
    /// the design working**, and its own comment said so: it existed so a change
    /// to what "omitted" means would land on a human. It did.
    ///
    /// The pin's real lesson is kept and is now enforced structurally instead:
    /// it read `["admin", "chat", "ingest", "read"]` while `admin` was silently
    /// granted, and was GREEN the whole time, because it had been written to
    /// match the code rather than to state the intent. A default that no longer
    /// exists cannot be pinned to the wrong value.
    #[tokio::test]
    async fn omitted_scope_is_refused_with_400_naming_the_field() {
        let (state, seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, None, None)),
        )
        .await
        .expect_err("an omitted scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(
            err.1.contains("scope is required"),
            "the 400 must name the field — got {:?}",
            err.1
        );
        assert!(
            err.1.contains("chat"),
            "the 400 must list the known scopes — got {:?}",
            err.1
        );
        // THE DISCRIMINATING ASSERTION. A 400 that still minted would be the
        // worst of both: the caller is told no and a credential exists anyway.
        // Asserting the refusal message alone cannot tell those apart.
        assert!(
            seen.lock().expect("seen lock").is_empty(),
            "a refused mint must not reach the minter"
        );
    }

    /// **An omitted scope must NEVER grant `admin`.** `admin` is
    /// *"manage the workspace — mint/revoke keys, provider keys, settings"*, so a
    /// silent grant is the exact escalation `is_verified_owner()` was added to
    /// prevent (/PL-9b), reachable by KEY instead of by JWT.
    ///
    /// R73 makes this hold for a stronger reason than it used to: omission no
    /// longer grants anything at all. **The test is kept rather than deleted**
    /// because it states the PROPERTY, not the mechanism — if a default is ever
    /// reintroduced, this is what stops it carrying `admin` again, and it would
    /// go red on that change rather than on this one.
    #[tokio::test]
    async fn omitted_scope_never_includes_admin() {
        let (state, seen) = mock_state();
        let outcome = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(None, None, None)),
        )
        .await;
        match outcome {
            // Today: refused outright, so no scope is granted at all.
            Err((status, _)) => assert_eq!(status, StatusCode::BAD_REQUEST),
            // If a default is ever reintroduced, it must not carry `admin`.
            Ok((_status, Json(body))) => {
                let got = body.scope.expect("scope must not be null on a new key");
                assert!(
                    !got.iter().any(|s| s == "admin"),
                    "omitting `scope` must never grant admin — got {got:?}"
                );
            }
        }
        let _ = seen;
    }

    /// grantable when it is asked for BY NAME. Opt-in, not unavailable.
    #[tokio::test]
    async fn admin_scope_is_still_grantable_when_requested_explicitly() {
        let (state, _seen) = mock_state();
        let (status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec!["admin".into()]), None, None)),
        )
        .await
        .expect("an explicit admin scope must still mint");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            body.scope.expect("scope must not be null"),
            vec!["admin".to_string()]
        );
    }

    /// An unknown slug is a 400 naming the problem — never a silent drop that
    /// hands back a key doing less than the caller asked for.
    #[tokio::test]
    async fn unknown_scope_is_rejected_with_the_known_set() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec!["superuser".into()]), None, None)),
        )
        .await
        .expect_err("an unknown scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(
            err.1.contains("superuser"),
            "message must name the bad slug"
        );
        assert!(err.1.contains("chat"), "message must list the known scopes");
    }

    #[tokio::test]
    async fn scope_is_normalised_and_deduplicated() {
        let (state, _seen) = mock_state();
        let (_s, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(
                Some(vec!["READ".into(), " read ".into(), "chat".into()]),
                None,
                None,
            )),
        )
        .await
        .expect("mint should succeed");
        assert_eq!(
            body.scope,
            Some(vec!["read".to_string(), "chat".to_string()])
        );
    }

    /// `{}` is refused rather than stored: the DB CHECK would reject it anyway,
    /// and a 400 explaining the alternative beats a 500 from a constraint.
    #[tokio::test]
    async fn empty_scope_array_is_refused_with_guidance() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(Some(vec![]), None, None)),
        )
        .await
        .expect_err("an empty scope must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // R73: the old guidance was "omit it for a full-surface key". Omitting is
        // now itself a 400, so telling the caller to omit would route them into a
        // second refusal. The message must state the vocabulary instead.
        assert!(
            err.1.contains("at least one"),
            "must say a scope is needed — got {:?}",
            err.1
        );
        assert!(
            err.1.contains("chat"),
            "must list the known scopes — got {:?}",
            err.1
        );
    }

    /// Minting an already-dead credential is almost certainly a mistake, and
    /// silently doing it is worse than refusing.
    #[tokio::test]
    async fn past_expiry_is_refused() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(
                a_scope(),
                Some("2020-01-01T00:00:00Z".into()),
                None,
            )),
        )
        .await
        .expect_err("a past expiry must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("future"));
    }

    #[tokio::test]
    async fn malformed_expiry_is_a_400_not_a_500() {
        let (state, _seen) = mock_state();
        let err = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(a_scope(), Some("next tuesday".into()), None)),
        )
        .await
        .expect_err("a malformed expiry must be refused");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("RFC3339"));
    }

    #[tokio::test]
    async fn negative_and_nonfinite_budgets_are_refused() {
        for bad in [-1.0_f64, f64::NAN, f64::INFINITY] {
            let (state, _seen) = mock_state();
            let err = create_key_handler(
                State(state),
                bearer_headers(),
                Json(body_with(a_scope(), None, Some(bad))),
            )
            .await
            .expect_err("a bad budget must be refused");
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "budget {bad} must 400");
        }
    }

    // ── GWY-43: per-key rate limit at the mint edge ────────────────────────

    /// Every value the DB CHECK would reject must be a 400 HERE, naming the
    /// field. `0` is in the list on purpose: it is the one plausible-looking
    /// value a user might type meaning "off", and it would mint a key that can
    /// never serve a request.
    #[tokio::test]
    async fn zero_negative_and_oversized_rate_limits_are_refused() {
        for bad in [0_i64, -1, i64::from(i32::MAX) + 1] {
            let (state, seen) = mock_state();
            let mut body = body_with(a_scope(), None, None);
            body.rate_limit_rpm = Some(bad);
            let err = create_key_handler(State(state), bearer_headers(), Json(body))
                .await
                .expect_err("a bad rate limit must be refused");
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "rpm {bad} must 400");
            assert!(
                err.1.contains("rate_limit_rpm"),
                "message must name the field — got {:?}",
                err.1
            );
            assert!(
                seen.lock().unwrap().is_empty(),
                "no mint may happen on an invalid rate limit"
            );
        }
    }

    /// The point of the field: a valid value must reach the INSERT. Asserting
    /// only the 201 would pass even if the handler dropped it on the floor —
    /// which is precisely how `budget_usd_monthly` sat in the schema enforcing
    /// nothing (`db::api_keys::KeyAuth` doc). So assert what the minter was
    /// HANDED, and separately that the response echoes it.
    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn a_valid_rate_limit_reaches_the_minter_and_the_response() {
        let _g = DevAuthGuard::new();
        let (state, _seen, last_opts) = mock_state_capturing();
        let mut body = body_with(a_scope(), None, Some(25.0));
        body.rate_limit_rpm = Some(120);
        let (status, Json(out)) = create_key_handler(State(state), bearer_headers(), Json(body))
            .await
            .expect("mint should succeed");
        assert_eq!(status, StatusCode::CREATED);
        let opts = last_opts
            .lock()
            .unwrap()
            .clone()
            .expect("the minter must have been called");
        assert_eq!(opts.rate_limit_rpm, Some(120), "the INSERT must carry it");
        assert_eq!(opts.budget_usd_monthly, Some(25.0));
        assert_eq!(out.rate_limit_rpm, Some(120));
        assert_eq!(out.budget_usd_monthly, Some(25.0));
    }

    /// Omitting it stays omitted — `NULL` means "inherit the tenant's plan
    /// tier", and inventing a number here would silently cap every new key.
    #[tokio::test]
    async fn an_omitted_rate_limit_stays_null() {
        let (state, _seen, last_opts) = mock_state_capturing();
        let _created = create_key_handler(
            State(state),
            bearer_headers(),
            Json(body_with(a_scope(), None, None)),
        )
        .await
        .expect("mint should succeed");
        let opts = last_opts
            .lock()
            .unwrap()
            .clone()
            .expect("the minter must have been called");
        assert_eq!(opts.rate_limit_rpm, None);
    }

    fn mock_state() -> (KeyRoutesState, Arc<Mutex<Vec<String>>>) {
        let (state, seen, _opts) = mock_state_capturing();
        (state, seen)
    }

    /// Same mock, plus the handle on what the handler actually passed down —
    /// the only way to assert the VALIDATED options rather than just the 201.
    #[allow(clippy::type_complexity)]
    fn mock_state_capturing() -> (
        KeyRoutesState,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Option<crate::db::api_keys::MintOptions>>>,
    ) {
        let seen = Arc::new(Mutex::new(vec![]));
        let last_opts = Arc::new(Mutex::new(None));
        let state = KeyRoutesState {
            minter: Arc::new(MockKeyMinter {
                seen: seen.clone(),
                last_opts: last_opts.clone(),
            }),
        };
        (state, seen, last_opts)
    }

    /// Replicates the trace_reads dev-auth guard: the dev-stub claims path needs
    /// `WORKOS_CLIENT_ID` unset. Restores it on drop so the suite stays hermetic.
    struct DevAuthGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Option<String>,
    }
    impl DevAuthGuard {
        fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let saved = std::env::var("WORKOS_CLIENT_ID").ok();
            if saved.is_some() {
                unsafe {
                    std::env::remove_var("WORKOS_CLIENT_ID");
                }
            }
            Self { _lock, saved }
        }
    }
    impl Drop for DevAuthGuard {
        fn drop(&mut self) {
            if let Some(v) = &self.saved {
                unsafe {
                    std::env::set_var("WORKOS_CLIENT_ID", v);
                }
            }
        }
    }

    fn bearer_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer dev-token".parse().unwrap(),
        );
        h
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn mint_uses_claims_tenant_and_returns_raw_key() {
        let _g = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let (status, Json(body)) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(CreateKeyBody {
                name: "  prod-agent  ".into(),
                // R73: scope is required, and this test is about the TENANT bind
                // and name trimming — leaving it `None` would make it assert the
                // scope refusal instead, which is a different property.
                scope: a_scope(),
                expires_at: None,
                budget_usd_monthly: None,
                rate_limit_rpm: None,
            }),
        )
        .await
        .expect("mint should succeed");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.raw_key, "tlane_MOCKKEYBODYdonotuseinprod");
        assert_eq!(body.key_prefix, "AbC012");
        assert_eq!(body.name, "prod-agent", "name is trimmed before minting");
        assert!(body.last_used_at.is_none());
        // The tenant handed to the minter is the validated Claims tenant — never
        // a body/header value.
        assert_eq!(*seen.lock().unwrap(), vec![DEV_TENANT.to_string()]);
    }

    #[tokio::test]
    async fn mint_without_auth_is_401_and_never_mints() {
        let (state, seen) = mock_state();
        let (status, _msg) = create_key_handler(
            State(state),
            HeaderMap::new(), // no Authorization
            Json(CreateKeyBody {
                name: "x".into(),
                scope: None,
                expires_at: None,
                budget_usd_monthly: None,
                rate_limit_rpm: None,
            }),
        )
        .await
        .expect_err("must reject unauthenticated");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            seen.lock().unwrap().is_empty(),
            "no mint may happen on an auth failure"
        );
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn mint_rejects_blank_name() {
        let _g = DevAuthGuard::new();
        let (state, seen) = mock_state();
        let (status, _msg) = create_key_handler(
            State(state),
            bearer_headers(),
            Json(CreateKeyBody {
                name: "   ".into(),
                scope: None,
                expires_at: None,
                budget_usd_monthly: None,
                rate_limit_rpm: None,
            }),
        )
        .await
        .expect_err("blank name must be rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            seen.lock().unwrap().is_empty(),
            "no mint may happen on an invalid name"
        );
    }
}
