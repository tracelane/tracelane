//! `OBS-48` — shareable, unauthenticated public trace links.
//!
//! Four routes:
//!   POST   /v1/traces/{trace_id}/share          — mint a link (authed, `read` scope)
//!   GET    /v1/traces/{trace_id}/shares         — list this trace's active links (authed)
//!   DELETE /v1/traces/{trace_id}/shares/{id}    — revoke a link (authed)
//!   GET    /v1/share/{token}                    — the public page's data source (UNAUTHENTICATED)
//!
//! Mounted only when BOTH `CLICKHOUSE_URL` and a Postgres control plane are
//! configured (`server.rs`) — the first three routes read spans through the
//! SAME tenant-capped `TraceReader` the authenticated `/v1/traces/*` routes
//! use (SRE #20: every ClickHouse read runs at the tenant's OWN ADR-031 cap
//! tier), and all four need the `trace_shares` table (migration
//! `apps/web/db/migrations/0036_trace_shares.sql`, un-journaled — TRAPS §9).
//!
//! ## Tenant isolation
//!
//! For the three authed routes, `tenant_id` comes ONLY from `Claims.tenant_id`
//! — never a path, query, or body field, exactly like `trace_reads.rs`. For
//! the public route there is no `Claims` at all: the tenant comes from the
//! `trace_shares` ROW matched by `sha256(token)`, which is itself a trust
//! boundary established once, at mint time, by an authenticated request. That
//! resolved tenant id is constructed via `TenantId::from_jwt_claim` — the same
//! precedent `db::api_keys::lookup_tenant_by_key_body` already sets for a
//! non-literally-JWT but equally-authenticated source (a peppered-hash
//! Postgres lookup there; a token-hash Postgres lookup here).
//!
//! ## Fails CLOSED, with exactly one exception
//!
//! Every branch on this path denies on doubt: an unowned or unknown trace is
//! 404, a malformed/expired/revoked token is 404 (the SAME 404, so the three
//! cases are indistinguishable), a read failure is 502/500, never a
//! best-effort guess. The ONE fail-OPEN branch is the public route's
//! `view_count` increment — the "someone's Slack link happened to 500 the
//! click" is a strictly worse outcome than an undercounted view, and this is
//! the sole affordance `.claude/rules/logging.md` grants a fail-open write.
//!
//! ## Content never leaves this process
//!
//! The public route strips every content-bearing `attributes` key (§2
//! denylist below) from every span before serialising. There is no opt-in —
//! `docs/reference/TRAPS.md` §11 / this repo's honesty locks forbid a public
//! surface from carrying a customer's prompt or response under any
//! configuration.
//!
//! ## KNOWN SPEC-VS-CODE GAP: `rekor_entry_id`
//!
//! The spec (`specs/OBS-48-shareable-verified-trace-link.md` §2) asks this
//! route to echo `rekor_entry_id` from "the chain status row", but the PUBLIC
//! [`crate::trace_reads::TraceChainStatus`] returned by
//! `TraceReader::trace_chain_status` carries only `{chained, seq, anchored}`
//! — the raw Rekor id lives in the PRIVATE `ChainStatusRow` used internally by
//! `ClickHouseTraceReader` and is never surfaced past the `anchored: bool`
//! derivation (`trace_reads.rs:668-676` vs `:686-696`). Exposing it would mean
//! adding a field to `TraceChainStatus` in `trace_reads.rs`, which is
//! deliberately out of scope for this change (another agent's uncommitted
//! work lives in that file, per the build instructions). This route therefore
//! NEVER populates `rekor_entry_id` today — an honest omission, not a
//! fabricated value: the field is optional on the wire
//! (`rekor_entry_id?: string`) and `ShareLedgerBadge` already renders
//! correctly without it (the "anchored to a public transparency log" badge
//! text still shows; only the non-clickable Rekor-coordinate chip is absent).
//! Follow-up: add `pub rekor_entry_id: Option<String>` to `TraceChainStatus`
//! and thread it through `ClickHouseTraceReader::trace_chain_status`.

use anyhow::{Context as _, Result};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use chrono::{DateTime, Utc};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracelane_shared::TenantId;
use tracing::instrument;
use uuid::Uuid;

use crate::trace_reads::{SpanRow, TraceChainStatus, TraceReader};

/// Active-links-per-(tenant,trace) ceiling (spec §5).
const MAX_ACTIVE_SHARES_PER_TRACE: i64 = 10;
/// The only expiries the mint route accepts (spec §2/§5). `default` when
/// `expires_in_days` is omitted.
const ALLOWED_EXPIRY_DAYS: [i64; 3] = [7, 30, 90];
const DEFAULT_EXPIRY_DAYS: i64 = 30;
/// 256 bits (spec §5).
const TOKEN_BYTES: usize = 32;
/// Public-read limiter: 60 requests / IP / minute (spec §2/§5).
const RATE_LIMIT_WINDOW_SECS: i64 = 60;
const RATE_LIMIT_MAX_PER_WINDOW: u32 = 60;
/// Defensive bound on a raw path token before it is even hashed — a base64url
/// encoding of 32 bytes is 43 chars; this is a generous ceiling, not the
/// expected shape.
const MAX_TOKEN_LEN: usize = 256;

// ── Content denylist (spec §2) ───────────────────────────────────────────────

/// Exact key matches, stripped from every span's `attributes` JSON before it
/// reaches the public route. Copied verbatim from the spec table — do not
/// paraphrase or reorder derive meaning from this list; it IS the contract.
const DENYLIST_KEYS: &[&str] = &[
    "gen_ai_input_messages",
    "gen_ai_output_messages",
    "gen_ai_system_instructions",
    "request_json",
    "response_json",
    "user_prompt",
    "tool_input",
    "tool.output",
    "response.model_output",
    "system_prompt_preview",
    "user_system_prompt",
    "new_context",
    "full_command",
    "file_path",
];
/// Any key ENDING in one of these is also stripped (spec §2). Covers e.g.
/// `gen_ai_input_messages` a second time (already exact-listed — redundant is
/// safe) and any future `*_messages` / `*_json` / `*.body` attribute this list
/// was never updated to name.
const DENYLIST_SUFFIXES: &[&str] = &["_messages", "_json", ".body"];

fn is_content_key(key: &str) -> bool {
    DENYLIST_KEYS.contains(&key) || DENYLIST_SUFFIXES.iter().any(|suf| key.ends_with(suf))
}

/// Strip every content-bearing key from one span's `attributes` JSON string.
///
/// Fails CLOSED: a parse error or a non-object shape returns `"{}"` rather
/// than the untouched input — the untouched string is exactly what this
/// function exists to keep off the public route, so "I couldn't parse it" and
/// "there was nothing to strip" both resolve to "show nothing" rather than
/// "show everything".
fn strip_content(attributes_json: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(attributes_json) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.retain(|k, _| !is_content_key(k));
            serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_else(|_| "{}".into())
        }
        _ => "{}".into(),
    }
}

fn strip_spans_content(mut spans: Vec<SpanRow>) -> Vec<SpanRow> {
    for span in &mut spans {
        span.attributes = strip_content(&span.attributes);
    }
    spans
}

/// The root span's name: the span with no parent, tie-broken by the earliest
/// `start_time_us` — the same `argMinIf(name, start_time, parent_span_id IS
/// NULL)` definition `trace_reads.rs`'s own `root_name` column uses, computed
/// here in Rust because the public route reads spans (not `trace_summaries`,
/// which is tenant-list-scoped and does not carry a per-token join key).
/// Falls back to the earliest span overall if every span unexpectedly carries
/// a parent (must never panic on a shape it doesn't expect); `""` for zero
/// spans.
fn root_span_name(spans: &[SpanRow]) -> String {
    spans
        .iter()
        .filter(|s| s.parent_span_id.is_none())
        .min_by_key(|s| s.start_time_us)
        .or_else(|| spans.iter().min_by_key(|s| s.start_time_us))
        .map(|s| s.name.clone())
        .unwrap_or_default()
}

// ── Token ────────────────────────────────────────────────────────────────────

/// Mint a 256-bit token, base64url (no padding) — spec §5. Returns the RAW
/// token (shown to the owner exactly once) and its SHA-256 digest (the only
/// thing ever stored, and the only thing the public route can look up by).
///
/// The hash is computed over the ENCODED STRING, not the raw bytes: the
/// public route only ever sees the string form (a URL path segment), so
/// hashing anything else would make verification unable to reproduce it.
fn mint_token() -> Result<(String, Vec<u8>)> {
    let rng = ring::rand::SystemRandom::new();
    let mut raw = [0u8; TOKEN_BYTES];
    rng.fill(&mut raw)
        .map_err(|_| anyhow::anyhow!("RNG failure minting a share token"))?;
    let token = B64URL.encode(raw);
    let hash = hash_token(&token);
    Ok((token, hash))
}

fn hash_token(token: &str) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
        .as_ref()
        .to_vec()
}

// ── Storage seam ─────────────────────────────────────────────────────────────

/// `POST /v1/traces/{id}/share` response (spec §2).
#[derive(Debug, Clone, Serialize)]
pub struct ShareMintResult {
    pub id: String,
    pub token: String, // secret-field-ok: one-time reveal at mint; list row has no token (B-430)
    pub url: String,
    /// RFC3339.
    pub expires_at: String,
}

/// `GET /v1/traces/{id}/shares` row (spec §2) — no token, ever (only its hash
/// is stored; the raw token is shown once, at mint time).
#[derive(Debug, Clone, Serialize)]
pub struct ShareListRow {
    pub id: String,
    /// RFC3339.
    pub created_at: String,
    /// RFC3339.
    pub expires_at: String,
    pub view_count: i64,
}

/// What a valid public token resolves to — enough to read spans/chain and
/// bump the view counter. Never carries the token itself.
#[derive(Debug, Clone)]
pub struct ResolvedShare {
    pub tenant_id: TenantId,
    pub trace_id: String,
    /// RFC3339 — echoed on the public payload (spec §3 "expires in N days").
    pub expires_at: String,
}

/// Storage seam — lets the handlers be unit-tested without Postgres (real impl
/// is [`PgShareStore`]; tests use an in-module fake). Off the request hot
/// path, so `async_trait` is fine (CLAUDE.md bans it only on the gateway hot
/// path).
#[async_trait::async_trait]
pub trait ShareStore: Send + Sync {
    /// Insert a new share row IF `(tenant, trace_id)` is under the active-link
    /// cap. `Ok(None)` = at/over cap (caller returns 409). The cap check and
    /// the insert happen in the SAME statement in [`PgShareStore`], so there
    /// is no read-then-write window for the common case; a concurrent
    /// double-mint exactly at the boundary could still land 11 rows — an
    /// accepted benign race, not a tenant-isolation property (nothing crosses
    /// tenants here), the same shape every other count-then-insert cap in this
    /// codebase accepts.
    async fn mint(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        token_hash: &[u8],
        created_by: &str,
        expires_in_days: i64,
    ) -> Result<Option<(Uuid, String)>>;

    async fn list_active(&self, tenant: &TenantId, trace_id: &str) -> Result<Vec<ShareListRow>>;

    /// Soft-revoke (sets `revoked_at`; the row and its `view_count` survive).
    /// `Ok(true)` iff a row matching `(tenant, trace_id, id)` with no prior
    /// revoke was updated.
    async fn revoke(&self, tenant: &TenantId, trace_id: &str, id: Uuid) -> Result<bool>;

    /// Public lookup by token hash. `Ok(None)` covers missing, expired AND
    /// revoked — IDENTICALLY, by construction (the `WHERE` clause filters all
    /// three in [`PgShareStore`]), so the caller cannot distinguish them even
    /// by accident.
    async fn resolve(&self, token_hash: &[u8]) -> Result<Option<ResolvedShare>>;

    /// Best-effort. A failure here must NEVER fail the read it is attached to
    /// — the one fail-OPEN branch on this path (module header).
    async fn increment_view_count(&self, token_hash: &[u8]) -> Result<()>;

    /// The tenant's display name (`tenants.name`, nullable). `Ok(None)` for a
    /// missing row or a NULL column; the caller renders `""` either way (spec
    /// §2: "fall back to \"\" if absent").
    async fn workspace_name(&self, tenant: &TenantId) -> Result<Option<String>>;
}

/// Production store — the shared Postgres pool (`crate::db::global_pool()`).
pub struct PgShareStore {
    pub pool: deadpool_postgres::Pool,
}

#[async_trait::async_trait]
impl ShareStore for PgShareStore {
    async fn mint(
        &self,
        tenant: &TenantId,
        trace_id: &str,
        token_hash: &[u8],
        created_by: &str,
        expires_in_days: i64,
    ) -> Result<Option<(Uuid, String)>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        let expires_at: DateTime<Utc> = Utc::now() + chrono::Duration::days(expires_in_days);
        // The cap check (`active`) and the insert are ONE statement: a caller
        // over the cap gets no row back (RETURNING is empty), never a
        // check-then-insert race a second request could slip through between
        // two round trips.
        let row = client
            .query_opt(
                "WITH active AS (
                    SELECT count(*) AS n FROM trace_shares
                     WHERE tenant_id = $1 AND trace_id = $2
                       AND revoked_at IS NULL AND expires_at > now()
                 )
                 INSERT INTO trace_shares (tenant_id, trace_id, token_hash, created_by, expires_at)
                 SELECT $1, $2, $3, $4, $5
                  WHERE (SELECT n FROM active) < $6
                 RETURNING id, expires_at",
                &[
                    tenant.as_uuid(),
                    &trace_id,
                    &token_hash,
                    &created_by,
                    &expires_at,
                    &MAX_ACTIVE_SHARES_PER_TRACE,
                ],
            )
            .await
            .context("INSERT INTO trace_shares failed")?;
        Ok(row.map(|r| {
            let id: Uuid = r.get(0);
            let exp: DateTime<Utc> = r.get(1);
            (id, exp.to_rfc3339())
        }))
    }

    async fn list_active(&self, tenant: &TenantId, trace_id: &str) -> Result<Vec<ShareListRow>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        let rows = client
            .query(
                "SELECT id, created_at, expires_at, view_count
                   FROM trace_shares
                  WHERE tenant_id = $1 AND trace_id = $2
                    AND revoked_at IS NULL AND expires_at > now()
                  ORDER BY created_at DESC",
                &[tenant.as_uuid(), &trace_id],
            )
            .await
            .context("SELECT trace_shares (list) failed")?;
        Ok(rows
            .iter()
            .map(|r| {
                let id: Uuid = r.get(0);
                let created_at: DateTime<Utc> = r.get(1);
                let expires_at: DateTime<Utc> = r.get(2);
                ShareListRow {
                    id: id.to_string(),
                    created_at: created_at.to_rfc3339(),
                    expires_at: expires_at.to_rfc3339(),
                    view_count: r.get(3),
                }
            })
            .collect())
    }

    async fn revoke(&self, tenant: &TenantId, trace_id: &str, id: Uuid) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        let affected = client
            .execute(
                "UPDATE trace_shares
                    SET revoked_at = now()
                  WHERE id = $1 AND tenant_id = $2 AND trace_id = $3
                    AND revoked_at IS NULL",
                &[&id, tenant.as_uuid(), &trace_id],
            )
            .await
            .context("UPDATE trace_shares (revoke) failed")?;
        Ok(affected > 0)
    }

    async fn resolve(&self, token_hash: &[u8]) -> Result<Option<ResolvedShare>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        // Missing, expired AND revoked all fail this ONE predicate — the
        // caller cannot tell them apart even by accident (module header / spec
        // §2/§4).
        let row = client
            .query_opt(
                "SELECT tenant_id, trace_id, expires_at
                   FROM trace_shares
                  WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()",
                &[&token_hash],
            )
            .await
            .context("SELECT trace_shares (resolve) failed")?;
        Ok(row.map(|r| {
            let tenant_uuid: Uuid = r.get(0);
            let expires_at: DateTime<Utc> = r.get(2);
            ResolvedShare {
                // Precedent: `db::api_keys::lookup_tenant_by_key_body` already
                // uses `from_jwt_claim` for a non-literally-JWT but equally
                // authenticated source (there, a peppered-hash Postgres
                // lookup; here, a token-hash one) — see module header.
                tenant_id: TenantId::from_jwt_claim(tenant_uuid),
                trace_id: r.get(1),
                expires_at: expires_at.to_rfc3339(),
            }
        }))
    }

    async fn increment_view_count(&self, token_hash: &[u8]) -> Result<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        client
            .execute(
                "UPDATE trace_shares SET view_count = view_count + 1 WHERE token_hash = $1",
                &[&token_hash],
            )
            .await
            .context("UPDATE trace_shares (view_count) failed")?;
        Ok(())
    }

    async fn workspace_name(&self, tenant: &TenantId) -> Result<Option<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
        let row = client
            .query_opt(
                "SELECT name FROM tenants WHERE id = $1",
                &[tenant.as_uuid()],
            )
            .await
            .context("SELECT tenants.name failed")?;
        Ok(row.and_then(|r| r.get::<_, Option<String>>(0)))
    }
}

// ── Per-IP limiter (public route ONLY) ───────────────────────────────────────

struct RateWindow {
    start_secs: i64,
    count: u32,
}

/// Fixed-window, 60 req/min per client-IP key — spec §2/§5. The ONLY limiter
/// in the gateway keyed on IP rather than tenant, because this is the ONLY
/// unauthenticated route: every other limiter here is per-tenant because
/// every other route has a tenant.
///
/// Built on `moka::future::Cache` rather than `moka::sync::Cache`: the
/// `sync` cargo feature is not enabled for this crate's `moka` dependency
/// (`crates/gateway/Cargo.toml` enables only `future`), and enabling it is
/// outside this change's edit scope (Cargo.toml is not one of the files this
/// change touches). `future::Cache` is already an established dependency here
/// (`entitlement_cache.rs`, `semantic_cache.rs`, `online_eval.rs`) and this
/// handler is already `async`, so the `.await` costs nothing extra.
pub struct ShareRateLimiter {
    buckets: moka::future::Cache<String, Arc<Mutex<RateWindow>>>,
}

impl ShareRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: moka::future::Cache::builder()
                .max_capacity(200_000)
                .time_to_idle(Duration::from_secs((RATE_LIMIT_WINDOW_SECS as u64) * 3))
                .build(),
        }
    }

    /// `Some(retry_after_secs)` when `key` is over budget for the current
    /// window; `None` when the request is allowed.
    async fn check(&self, key: &str, now_secs: i64) -> Option<i64> {
        let entry = self
            .buckets
            .get_with(key.to_string(), async move {
                Arc::new(Mutex::new(RateWindow {
                    start_secs: now_secs,
                    count: 0,
                }))
            })
            .await;
        let mut w = entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now_secs - w.start_secs >= RATE_LIMIT_WINDOW_SECS {
            w.start_secs = now_secs;
            w.count = 0;
        }
        w.count += 1;
        if w.count > RATE_LIMIT_MAX_PER_WINDOW {
            Some((RATE_LIMIT_WINDOW_SECS - (now_secs - w.start_secs)).max(1))
        } else {
            None
        }
    }
}

impl Default for ShareRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Counters, not log lines (`.claude/rules/logging.md`: "a repeating condition
/// gets a COUNTER, not a line per occurrence" — a limiter hit on a public,
/// internet-reachable route is exactly the repeating condition that rule
/// names). Neither is wired to `crates/shared/src/degradation.rs`'s
/// `Degradation` registry: that enum's discriminants are a hand-pinned,
/// incident-tied list in a file outside this change's edit scope, so adding a
/// variant there is a deliberate follow-up, not a silent extension here. These
/// process-local atomics are the honest interim: present, inspectable, never a
/// per-request log line.
static RATE_LIMIT_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);
static VIEW_COUNT_INCREMENT_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The client identity a rate-limit bucket is keyed on: the FIRST hop of
/// `X-Forwarded-For`.
///
/// TRUST ASSUMPTION: this gateway sits behind Caddy in every deployment
/// topology it runs in (`admin_audit.rs`'s `ip_addr` doc carries the same
/// assumption for its audit rows), and Caddy sets/overwrites this header for
/// the real client connection — so the first hop is the value Caddy itself
/// observed, not one an attacker appended.
///
/// NO SOCKET-ADDRESS FALLBACK: axum's `ConnectInfo` extractor requires the
/// server to be served via `Router::into_make_service_with_connect_info`
/// (`axum::extract::connect_info`), and this gateway's `axum::serve(listener,
/// app)` call (`server.rs`) does not use it — wiring that up is a
/// wider-blast-radius change (it touches how EVERY route is served, not just
/// this module's mount) than this change's stated edit scope allows. A
/// request with no `X-Forwarded-For` (direct-to-gateway: local dev, a test
/// harness, or a misconfigured edge) is bucketed under one shared key instead
/// of left unlimited — the conservative direction: it under-serves a fleet of
/// direct callers sharing one bucket rather than exempting any of them from
/// the limit entirely.
fn client_ip_key(headers: &HeaderMap) -> String {
    // PROVEN WRONG ON PROD 2026-09-06, first deploy of this route: 130 requests
    // in 37 s from one client, zero 429s. Behind Cloudflare → Caddy the first
    // hop of `X-Forwarded-For` is a ROTATING Cloudflare edge address, so every
    // request landed in a fresh bucket and the limiter limited nothing.
    // Cloudflare puts the real client in `CF-Connecting-IP`; prefer it, fall
    // back to the XFF first hop for a non-Cloudflare edge, then the shared key.
    let first_non_empty = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    first_non_empty("cf-connecting-ip")
        .or_else(|| first_non_empty("x-forwarded-for"))
        .unwrap_or_else(|| "__direct__".to_string())
}

// ── Router state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ShareState {
    pub store: Arc<dyn ShareStore>,
    /// The SAME tenant-capped reader `trace_reads::routes()` uses (SRE #20) —
    /// one reader, one cap seam, never a second ClickHouse client for this
    /// data.
    pub reader: Arc<dyn TraceReader>,
    pub rate_limiter: Arc<ShareRateLimiter>,
    /// `TRACELANE_WEB_URL`, default `https://app.tracelane.dev`
    /// (`server.rs::Config`). Trimmed of a trailing slash at construction.
    pub web_base_url: String,
}

pub fn routes() -> Router<ShareState> {
    Router::new()
        .route("/v1/traces/{trace_id}/share", post(mint_share_handler))
        .route("/v1/traces/{trace_id}/shares", get(list_shares_handler))
        .route(
            "/v1/traces/{trace_id}/shares/{id}",
            axum::routing::delete(revoke_share_handler),
        )
        // UNAUTHENTICATED — see module header.
        .route("/v1/share/{token}", get(public_share_handler))
}

// ── Auth (mirrors `trace_reads.rs::authenticate` — see that file's own note
// on why this is duplicated rather than imported: it is a private fn there) ──

/// Validate `Authorization: Bearer <jwt|tlane_*>` and return the claims, or an
/// error `Response` (401/403). Identical contract to
/// `trace_reads::authenticate`: the tenant id is taken ONLY from these claims,
/// and a credential without the `read` scope is refused here rather than at
/// each handler.
async fn authenticate(headers: &HeaderMap) -> Result<crate::auth::Claims, Response> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth.is_empty() {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing Authorization header",
        ));
    }
    let claims = crate::auth::validate_authorization(auth)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "trace share auth failed");
            let (status, msg) = crate::auth::failure(&err);
            error_response(status, msg)
        })?;
    if !claims.allows_scope(tracelane_shared::api_scope::Scope::Read) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `read` scope");
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "This API key is not scoped to read recorded data. It needs the `read` scope.",
        ));
    }
    Ok(claims)
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn not_found_share() -> Response {
    // Missing, expired and revoked are the SAME body — spec §2/§4/§7 proof 3.
    error_response(StatusCode::NOT_FOUND, "trace not found")
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MintBody {
    #[serde(default)]
    expires_in_days: Option<i64>,
}

/// `POST /v1/traces/{trace_id}/share` — mint a public link.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn mint_share_handler(
    State(state): State<ShareState>,
    Path(trace_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MintBody>,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if trace_id.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "invalid trace id");
    }

    let expires_in_days = body.expires_in_days.unwrap_or(DEFAULT_EXPIRY_DAYS);
    if !ALLOWED_EXPIRY_DAYS.contains(&expires_in_days) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "expires_in_days must be 7, 30 or 90",
        );
    }

    // Verify the trace belongs to THIS tenant via the exact same tenant-bound,
    // tier-capped reader `/v1/traces/{id}/spans` uses. A foreign or unknown
    // trace id reads back empty — existence never leaks across tenants.
    //
    // BILL-01 / ADR-076 §2.3: `list_spans` (the `TraceReader` trait's real,
    // `ClickHouseTraceReader` implementation) already rehydrates any
    // content-addressed `$ref` before returning — the SAME rehydration
    // `trace_reads.rs`'s own spans route relies on. No separate call is
    // needed HERE because this handler never returns span CONTENT to
    // anyone; `spans` below is used only for its `is_empty()` existence
    // check.
    let spans = match state.reader.list_spans(&claims.tenant_id, &trace_id).await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = %err, "share mint: trace ownership read failed");
            return error_response(StatusCode::BAD_GATEWAY, "trace read failed");
        }
    };
    if spans.is_empty() {
        return not_found_share();
    }

    let (token, token_hash) = match mint_token() {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(error = %err, "share mint: token generation failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not mint a share link",
            );
        }
    };

    let minted = match state
        .store
        .mint(
            &claims.tenant_id,
            &trace_id,
            &token_hash,
            &claims.sub,
            expires_in_days,
        )
        .await
    {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(error = %err, "share mint: insert failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not mint a share link",
            );
        }
    };

    let Some((id, expires_at)) = minted else {
        return error_response(
            StatusCode::CONFLICT,
            "You have reached the maximum of 10 active links for this trace.",
        );
    };

    let url = format!("{}/s/{token}", state.web_base_url.trim_end_matches('/'));
    Json(ShareMintResult {
        id: id.to_string(),
        token,
        url,
        expires_at,
    })
    .into_response()
}

/// `GET /v1/traces/{trace_id}/shares` — the owner's active links.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn list_shares_handler(
    State(state): State<ShareState>,
    Path(trace_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if trace_id.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "invalid trace id");
    }

    match state.store.list_active(&claims.tenant_id, &trace_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "share list read failed");
            error_response(StatusCode::BAD_GATEWAY, "shares read failed")
        }
    }
}

/// `DELETE /v1/traces/{trace_id}/shares/{id}` — revoke a link.
#[instrument(skip_all, fields(tenant_id = tracing::field::Empty))]
async fn revoke_share_handler(
    State(state): State<ShareState>,
    Path((trace_id, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let claims = match authenticate(&headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::Span::current().record("tenant_id", tracing::field::display(&claims.tenant_id));

    if trace_id.len() < 8 {
        return error_response(StatusCode::BAD_REQUEST, "invalid trace id");
    }
    let Ok(share_id) = Uuid::parse_str(&id) else {
        return error_response(StatusCode::NOT_FOUND, "share not found");
    };

    match state
        .store
        .revoke(&claims.tenant_id, &trace_id, share_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "share not found"),
        Err(err) => {
            tracing::error!(error = %err, "share revoke failed");
            error_response(StatusCode::BAD_GATEWAY, "revoke failed")
        }
    }
}

/// `GET /v1/share/{token}` — response shape (spec §2). Field names/casing are
/// LOAD-BEARING: `apps/web/app/s/[token]/page.tsx`'s `SharePayload` type is
/// already built against this exact shape.
#[derive(Debug, Clone, Serialize)]
struct SharePayload {
    trace_id: String,
    root_name: String,
    /// RFC3339 — "now", the moment this view was served (spec §2 wireframe
    /// caption "Shared trace"; distinct from `created_at`, which this route
    /// never exposes).
    shared_at: String,
    /// RFC3339.
    expires_at: String,
    span_count: usize,
    spans: Vec<SpanRow>,
    chain: TraceChainStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    rekor_entry_id: Option<String>,
    workspace_name: String,
}

/// `GET /v1/share/{token}` — UNAUTHENTICATED. See module header for the
/// tenancy, fail-direction and content-stripping invariants.
#[instrument(skip_all)]
async fn public_share_handler(
    State(state): State<ShareState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    // Rate limit FIRST — before any Postgres or ClickHouse work, so a flood
    // costs this process a header parse and a cache lookup, nothing more.
    let ip_key = client_ip_key(&headers);
    let now_secs = chrono::Utc::now().timestamp();
    if let Some(retry_after) = state.rate_limiter.check(&ip_key, now_secs).await {
        RATE_LIMIT_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
        let mut resp = error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests, try again in a minute.",
        );
        if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return resp;
    }

    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return not_found_share();
    }

    let hash = hash_token(&token);
    let resolved = match state.store.resolve(&hash).await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "share resolve failed");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Could not load this trace right now",
            );
        }
    };
    let Some(share) = resolved else {
        return not_found_share();
    };
    let ResolvedShare {
        tenant_id,
        trace_id,
        expires_at,
    } = share;

    // Reads run at THIS tenant's OWN ADR-031 cap tier — the same reader, same
    // seam, same guarantee as every authenticated trace read (SRE #20).
    //
    // BILL-01 / ADR-076 §2.3: `list_spans` already rehydrates any
    // content-addressed `$ref` (same implementation `trace_reads.rs` uses).
    // That does not need a SEPARATE call here: `strip_spans_content` below
    // removes every content-bearing key from the PUBLIC payload regardless
    // of whether the value was real content or a still-`$ref` placeholder,
    // so this route's own content policy already dominates either way.
    let spans = match state.reader.list_spans(&tenant_id, &trace_id).await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = %err, "share spans read failed");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Could not load this trace right now",
            );
        }
    };
    let chain = match state.reader.trace_chain_status(&tenant_id, &trace_id).await {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(error = %err, "share chain status read failed");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Could not load this trace right now",
            );
        }
    }
    .unwrap_or(TraceChainStatus {
        chained: false,
        seq: None,
        anchored: false,
    });

    let workspace_name = match state.store.workspace_name(&tenant_id).await {
        Ok(n) => n.unwrap_or_default(),
        Err(err) => {
            // NOT fail-closed: a display name is cosmetic, and refusing the
            // whole page over it would be a worse failure than showing "".
            // A repeating condition is a COUNTER, not a line per occurrence
            // (.claude/rules/logging.md): `note()` rate-limits its own WARN and
            // surfaces count/first/last on /health.
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::TraceShareBestEffortWrite,
            );
            tracing::debug!(error = %err, "share workspace-name read failed; showing empty");
            String::new()
        }
    };

    // Best-effort, fail-OPEN — the ONE such branch on this path (module
    // header). A failure here counts, never fails the request, never logs
    // per-request (this branch only runs on an actual DB error, not on every
    // request).
    if let Err(err) = state.store.increment_view_count(&hash).await {
        VIEW_COUNT_INCREMENT_FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::TraceShareBestEffortWrite,
        );
        tracing::debug!(error = %err, "share view_count increment failed (best-effort, fail-open)");
    }

    let root_name = root_span_name(&spans);
    let span_count = spans.len();
    let spans = strip_spans_content(spans);

    Json(SharePayload {
        trace_id,
        root_name,
        shared_at: chrono::Utc::now().to_rfc3339(),
        expires_at,
        span_count,
        spans,
        chain,
        rekor_entry_id: None, // see module header "KNOWN SPEC-VS-CODE GAP"
        workspace_name,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── content stripping ────────────────────────────────────────────────

    #[test]
    fn strips_every_denylisted_key_and_every_suffix_case() {
        let attrs = serde_json::json!({
            "gen_ai_input_messages": "SECRET PROMPT",
            "gen_ai_output_messages": "SECRET RESPONSE",
            "gen_ai_system_instructions": "SECRET SYSTEM",
            "request_json": "{}",
            "response_json": "{}",
            "user_prompt": "hi",
            "tool_input": "rm -rf /",
            "tool.output": "done",
            "response.model_output": "text",
            "system_prompt_preview": "preview",
            "user_system_prompt": "sys",
            "new_context": "ctx",
            "full_command": "ls -la",
            "file_path": "/etc/passwd",
            // suffix-rule-only cases (not exact-listed above)
            "custom_thing_messages": "leak",
            "weird_json": "leak",
            "nested.body": "leak",
            // must survive
            "name": "chat.completions",
            "model": "gpt-4o",
            "tokens": 120,
            "cost": 0.004,
            "gen_ai.tool.name": "search",
            "gen_ai_agent_name": "planner",
        })
        .to_string();

        let stripped = strip_content(&attrs);
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        let obj = v.as_object().unwrap();

        for key in DENYLIST_KEYS {
            assert!(!obj.contains_key(*key), "{key} survived stripping");
        }
        for key in ["custom_thing_messages", "weird_json", "nested.body"] {
            assert!(
                !obj.contains_key(key),
                "{key} (suffix case) survived stripping"
            );
        }
        for key in [
            "name",
            "model",
            "tokens",
            "cost",
            "gen_ai.tool.name",
            "gen_ai_agent_name",
        ] {
            assert!(obj.contains_key(key), "{key} was wrongly stripped");
        }
    }

    #[test]
    fn strip_content_fails_closed_on_unparseable_attributes() {
        assert_eq!(strip_content("not json"), "{}");
        assert_eq!(strip_content("[1,2,3]"), "{}");
        assert_eq!(strip_content(""), "{}");
    }

    #[test]
    fn root_span_name_picks_the_parentless_earliest_span() {
        let spans = vec![
            span("child", Some("root"), "child.op", 500),
            span("root", None, "planner.run", 100),
        ];
        assert_eq!(root_span_name(&spans), "planner.run");
        assert_eq!(root_span_name(&[]), "");
    }

    fn span(id: &str, parent: Option<&str>, name: &str, start_us: i64) -> SpanRow {
        SpanRow {
            span_id: id.to_string(),
            parent_span_id: parent.map(str::to_string),
            name: name.to_string(),
            start_time: String::new(),
            end_time: String::new(),
            start_time_us: start_us,
            duration_us: 10,
            status_code: 0,
            status_message: String::new(),
            attributes: "{}".to_string(),
            aft_ids: vec![],
            intervention: 0,
        }
    }

    // ── token ────────────────────────────────────────────────────────────

    #[test]
    fn mint_token_hash_matches_hashing_the_returned_string() {
        let (token, hash) = mint_token().unwrap();
        assert_eq!(hash, hash_token(&token));
        // base64url, no padding: only URL-safe alphabet chars, never '='.
        assert!(!token.contains('='));
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn two_mints_never_collide() {
        let (t1, _) = mint_token().unwrap();
        let (t2, _) = mint_token().unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn client_ip_prefers_cf_connecting_ip_over_the_rotating_xff_edge_hop() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "172.71.0.9, 203.0.113.50".parse().unwrap(),
        );
        h.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
        assert_eq!(client_ip_key(&h), "198.51.100.7");
        let mut only_xff = HeaderMap::new();
        only_xff.insert("x-forwarded-for", "203.0.113.50, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip_key(&only_xff), "203.0.113.50");
        assert_eq!(client_ip_key(&HeaderMap::new()), "__direct__");
    }

    // ── rate limiter ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn allows_up_to_the_limit_then_blocks_with_retry_after() {
        let limiter = ShareRateLimiter::new();
        for i in 0..RATE_LIMIT_MAX_PER_WINDOW {
            assert!(
                limiter.check("1.2.3.4", 1_000).await.is_none(),
                "request {i} should be allowed"
            );
        }
        let blocked = limiter.check("1.2.3.4", 1_000).await;
        assert!(blocked.is_some(), "the 61st request must be blocked");
        assert!(blocked.unwrap() > 0);
    }

    #[tokio::test]
    async fn window_resets_after_60_seconds() {
        let limiter = ShareRateLimiter::new();
        for _ in 0..RATE_LIMIT_MAX_PER_WINDOW {
            assert!(limiter.check("5.6.7.8", 1_000).await.is_none());
        }
        assert!(limiter.check("5.6.7.8", 1_000).await.is_some());
        // A new window (>= 60s later) resets the count.
        assert!(
            limiter
                .check("5.6.7.8", 1_000 + RATE_LIMIT_WINDOW_SECS)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn different_ips_have_independent_buckets() {
        let limiter = ShareRateLimiter::new();
        for _ in 0..RATE_LIMIT_MAX_PER_WINDOW {
            assert!(limiter.check("9.9.9.9", 1_000).await.is_none());
        }
        assert!(limiter.check("9.9.9.9", 1_000).await.is_some());
        // A different IP is unaffected.
        assert!(limiter.check("10.10.10.10", 1_000).await.is_none());
    }

    #[test]
    fn client_ip_key_takes_the_first_xff_hop() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "203.0.113.9, 10.0.0.1, 10.0.0.2".parse().unwrap(),
        );
        assert_eq!(client_ip_key(&h), "203.0.113.9");
    }

    #[test]
    fn client_ip_key_falls_back_when_absent() {
        assert_eq!(client_ip_key(&HeaderMap::new()), "__direct__");
    }

    // ── fake reader + store, for handler-level tests ────────────────────

    struct FakeReader {
        spans_by_trace: HashMap<(String, String), Vec<SpanRow>>,
        chain_by_trace: HashMap<(String, String), TraceChainStatus>,
        seen_tenant: Mutex<Vec<String>>,
    }

    impl FakeReader {
        fn new() -> Self {
            Self {
                spans_by_trace: HashMap::new(),
                chain_by_trace: HashMap::new(),
                seen_tenant: Mutex::new(Vec::new()),
            }
        }
        fn with_trace(mut self, tenant: &str, trace_id: &str, spans: Vec<SpanRow>) -> Self {
            self.spans_by_trace
                .insert((tenant.to_string(), trace_id.to_string()), spans);
            self
        }
    }

    #[async_trait::async_trait]
    impl TraceReader for FakeReader {
        async fn list_traces(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::TraceListFilters,
        ) -> Result<Vec<crate::trace_reads::TraceSummaryRow>> {
            unimplemented!("not exercised by trace_share tests")
        }
        async fn list_trace_groups(
            &self,
            _t: &TenantId,
            _by: crate::trace_reads::TraceGroupBy,
            _f: &crate::trace_reads::TraceListFilters,
        ) -> Result<Vec<crate::trace_reads::TraceGroupRow>> {
            unimplemented!()
        }
        async fn list_spans(&self, tenant_id: &TenantId, trace_id: &str) -> Result<Vec<SpanRow>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self
                .spans_by_trace
                .get(&(tenant_id.to_string(), trace_id.to_string()))
                .cloned()
                .unwrap_or_default())
        }
        async fn count_traces(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::TraceListFilters,
        ) -> Result<u64> {
            unimplemented!()
        }
        async fn trace_chain_status(
            &self,
            tenant_id: &TenantId,
            trace_id: &str,
        ) -> Result<Option<TraceChainStatus>> {
            self.seen_tenant.lock().unwrap().push(tenant_id.to_string());
            Ok(self
                .chain_by_trace
                .get(&(tenant_id.to_string(), trace_id.to_string()))
                .cloned())
        }
        async fn trace_cost_rollup(
            &self,
            _t: &TenantId,
            _ids: &[String],
        ) -> Result<Vec<crate::trace_reads::TraceCostRow>> {
            unimplemented!()
        }
        async fn slo(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::SloFilters,
        ) -> Result<Vec<crate::trace_reads::SloRow>> {
            unimplemented!()
        }
        async fn slo_summary(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::SloFilters,
        ) -> Result<crate::trace_reads::SloSummary> {
            unimplemented!()
        }
        async fn slo_by_model(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::SloFilters,
        ) -> Result<Vec<crate::trace_reads::SloModelRow>> {
            unimplemented!()
        }
        async fn slo_timeseries(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::SloFilters,
            _bucket_hours: u32,
        ) -> Result<Vec<crate::trace_reads::SloTimePoint>> {
            unimplemented!()
        }
        async fn gateway_stats(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::GatewayStatsFilters,
        ) -> Result<Vec<crate::trace_reads::GatewayProviderRow>> {
            unimplemented!()
        }
        async fn cost_breakdown(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::CostFilters,
        ) -> Result<Vec<crate::trace_reads::CostRow>> {
            unimplemented!()
        }
        async fn latency_breakdown(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::GatewayStatsFilters,
        ) -> Result<(
            crate::trace_reads::LatencyTotalsRow,
            Vec<crate::trace_reads::LatencyModelRow>,
        )> {
            unimplemented!()
        }
        async fn guardrail_summary(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::GuardrailStatsFilters,
        ) -> Result<crate::trace_reads::GuardrailSummaryRow> {
            unimplemented!()
        }
        async fn guardrail_rails(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::GuardrailStatsFilters,
        ) -> Result<Vec<crate::trace_reads::GuardrailRailRow>> {
            unimplemented!()
        }
        async fn guardrail_verdicts(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::GuardrailVerdictListFilters,
        ) -> Result<Vec<crate::trace_reads::GuardrailVerdictListRow>> {
            unimplemented!()
        }
        async fn signatures(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::SignatureFilters,
        ) -> Result<Vec<crate::trace_reads::SignatureHitRow>> {
            unimplemented!()
        }
        async fn signatures_distinct_traces(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::SignatureFilters,
        ) -> Result<u64> {
            unimplemented!()
        }
        async fn list_sessions(
            &self,
            _t: &TenantId,
            _f: &crate::trace_reads::SessionListFilters,
        ) -> Result<Vec<crate::trace_reads::SessionSummaryRow>> {
            unimplemented!()
        }
        async fn session_traces(
            &self,
            _t: &TenantId,
            _session_id: &str,
        ) -> Result<Vec<crate::trace_reads::SessionTraceRow>> {
            unimplemented!()
        }
    }

    /// In-memory `ShareStore` — mirrors `PgShareStore`'s semantics (the cap,
    /// the identical-404 shape for missing/expired/revoked) without Postgres.
    struct FakeShareStore {
        rows: Mutex<Vec<FakeRow>>,
        workspace_names: HashMap<String, String>,
    }

    #[derive(Clone)]
    struct FakeRow {
        id: Uuid,
        tenant: TenantId,
        trace_id: String,
        token_hash: Vec<u8>,
        expires_at: DateTime<Utc>,
        revoked: bool,
        view_count: i64,
    }

    impl FakeShareStore {
        fn new() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
                workspace_names: HashMap::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl ShareStore for FakeShareStore {
        async fn mint(
            &self,
            tenant: &TenantId,
            trace_id: &str,
            token_hash: &[u8],
            _created_by: &str,
            expires_in_days: i64,
        ) -> Result<Option<(Uuid, String)>> {
            let mut rows = self.rows.lock().unwrap();
            let active = rows
                .iter()
                .filter(|r| {
                    &r.tenant == tenant
                        && r.trace_id == trace_id
                        && !r.revoked
                        && r.expires_at > Utc::now()
                })
                .count();
            if active as i64 >= MAX_ACTIVE_SHARES_PER_TRACE {
                return Ok(None);
            }
            let id = Uuid::new_v4();
            let expires_at = Utc::now() + chrono::Duration::days(expires_in_days);
            rows.push(FakeRow {
                id,
                tenant: tenant.clone(),
                trace_id: trace_id.to_string(),
                token_hash: token_hash.to_vec(),
                expires_at,
                revoked: false,
                view_count: 0,
            });
            Ok(Some((id, expires_at.to_rfc3339())))
        }

        async fn list_active(
            &self,
            tenant: &TenantId,
            trace_id: &str,
        ) -> Result<Vec<ShareListRow>> {
            let rows = self.rows.lock().unwrap();
            Ok(rows
                .iter()
                .filter(|r| {
                    &r.tenant == tenant
                        && r.trace_id == trace_id
                        && !r.revoked
                        && r.expires_at > Utc::now()
                })
                .map(|r| ShareListRow {
                    id: r.id.to_string(),
                    created_at: Utc::now().to_rfc3339(),
                    expires_at: r.expires_at.to_rfc3339(),
                    view_count: r.view_count,
                })
                .collect())
        }

        async fn revoke(&self, tenant: &TenantId, trace_id: &str, id: Uuid) -> Result<bool> {
            let mut rows = self.rows.lock().unwrap();
            for r in rows.iter_mut() {
                if r.id == id && &r.tenant == tenant && r.trace_id == trace_id && !r.revoked {
                    r.revoked = true;
                    return Ok(true);
                }
            }
            Ok(false)
        }

        async fn resolve(&self, token_hash: &[u8]) -> Result<Option<ResolvedShare>> {
            let rows = self.rows.lock().unwrap();
            Ok(rows
                .iter()
                .find(|r| r.token_hash == token_hash && !r.revoked && r.expires_at > Utc::now())
                .map(|r| ResolvedShare {
                    tenant_id: r.tenant.clone(),
                    trace_id: r.trace_id.clone(),
                    expires_at: r.expires_at.to_rfc3339(),
                }))
        }

        async fn increment_view_count(&self, token_hash: &[u8]) -> Result<()> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(r) = rows.iter_mut().find(|r| r.token_hash == token_hash) {
                r.view_count += 1;
            }
            Ok(())
        }

        async fn workspace_name(&self, tenant: &TenantId) -> Result<Option<String>> {
            Ok(self.workspace_names.get(&tenant.to_string()).cloned())
        }
    }

    fn dev_tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap())
    }
    fn other_tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap())
    }

    // `bearer_headers` (a `HeaderMap` test fixture, duplicated per-file across
    // this crate — `trace_reads.rs` and `key_routes.rs` each keep their own)
    // was deleted 2026-09-12 (B-390) — zero callers in this file specifically.

    /// Process-wide guard: dev-stub auth requires `WORKOS_CLIENT_ID` unset.
    /// Mirrors `trace_reads.rs`'s `DevAuthGuard` (private to that module's own
    /// test mod, hence re-implemented here rather than imported).
    struct DevAuthGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        saved: Option<String>,
    }
    impl DevAuthGuard {
        fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let _lock = LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    fn test_state(reader: Arc<FakeReader>, store: Arc<FakeShareStore>) -> ShareState {
        ShareState {
            store,
            reader,
            rate_limiter: Arc::new(ShareRateLimiter::new()),
            web_base_url: "https://app.tracelane.dev".to_string(),
        }
    }

    /// Real HTTP dispatch through the actual router — `axum_test::TestServer`
    /// is the harness this crate already uses (`server.rs`'s
    /// `both_methods_on_v1_traces_coexist`); there is no `tower::ServiceExt`
    /// dependency in this crate to build a `.oneshot()`-style harness with.
    fn test_server(reader: FakeReader, store: FakeShareStore) -> axum_test::TestServer {
        let state = test_state(Arc::new(reader), Arc::new(store));
        axum_test::TestServer::new(routes().with_state(state))
    }

    // ── mint: body validation + tenant isolation ────────────────────────

    #[tokio::test]
    async fn mint_rejects_an_expiry_outside_the_allowed_set() {
        let _g = DevAuthGuard::new();
        let reader = FakeReader::new().with_trace(
            &dev_tenant().to_string(),
            "trace-0001",
            vec![span("s1", None, "root", 0)],
        );
        let server = test_server(reader, FakeShareStore::new());

        let resp = server
            .post("/v1/traces/trace-0001/share")
            .add_header("authorization", "Bearer dev-token")
            .json(&serde_json::json!({ "expires_in_days": 14 }))
            .await;
        assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn mint_defaults_to_30_days_and_returns_a_working_url() {
        let _g = DevAuthGuard::new();
        let reader = FakeReader::new().with_trace(
            &dev_tenant().to_string(),
            "trace-0001",
            vec![span("s1", None, "root", 0)],
        );
        let server = test_server(reader, FakeShareStore::new());

        let resp = server
            .post("/v1/traces/trace-0001/share")
            .add_header("authorization", "Bearer dev-token")
            .json(&serde_json::json!({}))
            .await;
        assert_eq!(resp.status_code(), StatusCode::OK);
        let v: serde_json::Value = resp.json();
        assert!(v["token"].as_str().unwrap().len() > 10);
        assert_eq!(
            v["url"].as_str().unwrap(),
            format!(
                "https://app.tracelane.dev/s/{}",
                v["token"].as_str().unwrap()
            )
        );
    }

    #[tokio::test]
    async fn mint_404s_on_another_tenants_trace_and_writes_no_row() {
        let _g = DevAuthGuard::new();
        // The trace exists, but only under `other_tenant`, never the dev tenant
        // the bearer token authenticates as.
        let reader = FakeReader::new().with_trace(
            &other_tenant().to_string(),
            "trace-0001",
            vec![span("s1", None, "root", 0)],
        );
        let store = Arc::new(FakeShareStore::new());
        let state = test_state(Arc::new(reader), store.clone());
        let server = axum_test::TestServer::new(routes().with_state(state));

        let resp = server
            .post("/v1/traces/trace-0001/share")
            .add_header("authorization", "Bearer dev-token")
            .json(&serde_json::json!({}))
            .await;
        assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
        assert!(
            store.rows.lock().unwrap().is_empty(),
            "no row must be written"
        );
    }

    #[tokio::test]
    async fn mint_409s_over_the_active_link_cap() {
        let _g = DevAuthGuard::new();
        let tenant = dev_tenant();
        let reader = FakeReader::new().with_trace(
            &tenant.to_string(),
            "trace-0001",
            vec![span("s1", None, "root", 0)],
        );
        let store = FakeShareStore::new();
        for _ in 0..MAX_ACTIVE_SHARES_PER_TRACE {
            store
                .mint(&tenant, "trace-0001", b"x", "user_1", 30)
                .await
                .unwrap();
        }
        let server = test_server(reader, store);

        let resp = server
            .post("/v1/traces/trace-0001/share")
            .add_header("authorization", "Bearer dev-token")
            .json(&serde_json::json!({}))
            .await;
        assert_eq!(resp.status_code(), StatusCode::CONFLICT);
    }

    // ── public route: identical 404 for missing / expired / revoked ────

    #[tokio::test]
    async fn public_route_404s_identically_for_unknown_expired_and_revoked() {
        let tenant = dev_tenant();
        let store = FakeShareStore::new();

        // Expired.
        let (id_expired, _) = store
            .mint(&tenant, "trace-0001", b"expired", "u", 30)
            .await
            .unwrap()
            .unwrap();
        store
            .rows
            .lock()
            .unwrap()
            .iter_mut()
            .find(|r| r.id == id_expired)
            .unwrap()
            .expires_at = Utc::now() - chrono::Duration::days(1);

        // Revoked.
        let (id_revoked, _) = store
            .mint(&tenant, "trace-0001", b"revoked", "u", 30)
            .await
            .unwrap()
            .unwrap();
        store
            .revoke(&tenant, "trace-0001", id_revoked)
            .await
            .unwrap();

        let reader = FakeReader::new().with_trace(
            &tenant.to_string(),
            "trace-0001",
            vec![span("s1", None, "root", 0)],
        );
        let server = test_server(reader, store);

        // Three distinct causes (never minted, expired, revoked), fed through
        // the SAME `hash_token` path the handler itself uses — the point of
        // the proof is that all three produce the identical body/status, not
        // that any of them reproduces a specific stored hash.
        let mut bodies = Vec::new();
        for raw in ["definitely-unknown", "expired", "revoked"] {
            let resp = server.get(&format!("/v1/share/{raw}")).await;
            bodies.push((resp.status_code(), resp.json::<serde_json::Value>()));
        }
        assert!(bodies.iter().all(|(s, _)| *s == StatusCode::NOT_FOUND));
        assert_eq!(bodies[0].1, bodies[1].1);
        assert_eq!(bodies[1].1, bodies[2].1);
    }

    #[tokio::test]
    async fn public_route_strips_content_and_bumps_view_count() {
        let tenant = dev_tenant();
        let store = Arc::new(FakeShareStore::new());
        // Mint with a token whose hash we can reproduce: use the real
        // `mint_token()` so the handler's `hash_token(&token)` matches.
        let (token, hash) = mint_token().unwrap();
        store.rows.lock().unwrap().push(FakeRow {
            id: Uuid::new_v4(),
            tenant: tenant.clone(),
            trace_id: "trace-0001".to_string(),
            token_hash: hash,
            expires_at: Utc::now() + chrono::Duration::days(30),
            revoked: false,
            view_count: 0,
        });

        let mut leaky = span("s1", None, "root", 0);
        leaky.attributes = serde_json::json!({"gen_ai_input_messages": "SECRET"}).to_string();
        let reader =
            Arc::new(FakeReader::new().with_trace(&tenant.to_string(), "trace-0001", vec![leaky]));
        let state = test_state(reader, store.clone());
        let server = axum_test::TestServer::new(routes().with_state(state));

        let resp = server.get(&format!("/v1/share/{token}")).await;
        assert_eq!(resp.status_code(), StatusCode::OK);
        let v: serde_json::Value = resp.json();
        let attrs = v["spans"][0]["attributes"].as_str().unwrap();
        assert!(!attrs.contains("SECRET"));

        assert_eq!(store.rows.lock().unwrap()[0].view_count, 1);
    }

    #[tokio::test]
    async fn public_route_429s_on_the_61st_request_with_retry_after() {
        let tenant = dev_tenant();
        let store = FakeShareStore::new();
        let (token, hash) = mint_token().unwrap();
        store.rows.lock().unwrap().push(FakeRow {
            id: Uuid::new_v4(),
            tenant: tenant.clone(),
            trace_id: "trace-0001".to_string(),
            token_hash: hash,
            expires_at: Utc::now() + chrono::Duration::days(30),
            revoked: false,
            view_count: 0,
        });
        let reader = FakeReader::new().with_trace(
            &tenant.to_string(),
            "trace-0001",
            vec![span("s1", None, "root", 0)],
        );
        let server = test_server(reader, store);

        for i in 0..RATE_LIMIT_MAX_PER_WINDOW {
            let resp = server
                .get(&format!("/v1/share/{token}"))
                .add_header("x-forwarded-for", "203.0.113.50")
                .await;
            assert_eq!(
                resp.status_code(),
                StatusCode::OK,
                "request {i} should succeed"
            );
        }
        let resp = server
            .get(&format!("/v1/share/{token}"))
            .add_header("x-forwarded-for", "203.0.113.50")
            .await;
        assert_eq!(resp.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_some());
    }

    // ── list / revoke ────────────────────────────────────────────────────

    #[tokio::test]
    async fn revoked_share_is_absent_from_the_active_list() {
        let _g = DevAuthGuard::new();
        let tenant = dev_tenant();
        let store = FakeShareStore::new();
        let (id, _) = store
            .mint(&tenant, "trace-0001", b"a", "u", 30)
            .await
            .unwrap()
            .unwrap();
        let server = test_server(FakeReader::new(), store);

        let resp = server
            .delete(&format!("/v1/traces/trace-0001/shares/{id}"))
            .add_header("authorization", "Bearer dev-token")
            .await;
        assert_eq!(resp.status_code(), StatusCode::NO_CONTENT);

        let resp = server
            .get("/v1/traces/trace-0001/shares")
            .add_header("authorization", "Bearer dev-token")
            .await;
        let v: serde_json::Value = resp.json();
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn revoke_of_a_foreign_trace_id_404s() {
        let _g = DevAuthGuard::new();
        let tenant = dev_tenant();
        let store = FakeShareStore::new();
        let (id, _) = store
            .mint(&tenant, "trace-0001", b"a", "u", 30)
            .await
            .unwrap()
            .unwrap();
        let server = test_server(FakeReader::new(), store);

        // Right id, WRONG trace_id in the path.
        let resp = server
            .delete(&format!("/v1/traces/wrong-trace/shares/{id}"))
            .add_header("authorization", "Bearer dev-token")
            .await;
        assert_eq!(resp.status_code(), StatusCode::NOT_FOUND);
    }
}
