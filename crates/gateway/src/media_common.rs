//! `OG-06` — the plumbing the media routes (`media_routes`) and the files / batch routes
//! (`files_batches`) share. Nothing here is a route.
//!
//! ## The order every OG-06 route runs
//!
//! ```text
//! authenticate (BEFORE the body is read) → scope + entitlements + rate limit
//! (`admission::pre_body_gate`, H3) → a tenant upload slot + a share of the process byte
//! budget (`acquire_intake`, H3) → read the body, BOUNDED → admission
//! (`admission::admit_authenticated`: scope → parse → entitlements (the bucket is not charged
//! twice) → budgets (+ the H2 unpriced-under-budget refusal) → predictive → audit publish,
//! fail-CLOSED) → ZDR → the tenant's OWN BYOK key (fail-CLOSED) → request guardrails
//! (fail-CLOSED) → breaker / kill switch → upstream → span
//! ```
//!
//! Authentication moves ahead of the body read because these bodies run to hundreds of
//! megabytes: an unauthenticated caller must not be able to make the gateway buffer one.
//! (`admission::admit_authenticated` says why that is still the ONE pipeline.)
//!
//! ## What is shared
//!
//! the OpenAI-shaped refusal renderer, the credential + body intake, the upstream client
//! and sender (SSRF-validated, `.without_url()` on every transport error), the span
//! builder, the request-rail helper and the bounded multipart form scan.

use std::collections::HashMap;
use std::sync::OnceLock;

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use futures::StreamExt as _;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId, TracelaneSpan};
use uuid::Uuid;

use crate::admission::{Malformed, Refusal};
use crate::auth::{AuthPath, Claims};
use crate::multipart_scan::{Caps, Event, ScanError, Scanner};
use crate::openai_responses::{coded, openai_error};
use crate::providers::translation_policy::{self, MediaLimits};
use crate::server::AppState;

/// The header that names the provider for a request that carries no model (files,
/// batches). Default `openai`; the provider must carry the capability.
pub(crate) const PROVIDER_HEADER: &str = "x-tracelane-provider";

/// The provider a files / batches call goes to when the caller names none.
pub(crate) const DEFAULT_FILES_PROVIDER: &str = "openai";

// ── Refusals ─────────────────────────────────────────────────────────────────

/// Every OG-06 route renders its admission refusals the way `/v1/responses` does: the
/// OpenAI error shape (`{"error":{"message","type","code","param"}}`) every SDK parses.
pub(crate) fn refuse_openai(refusal: Refusal) -> Response {
    let status = refusal.status();
    match refusal {
        Refusal::MissingCredentials => coded(
            status,
            "missing_credentials",
            "missing credentials — send `Authorization: Bearer tlane_…`",
        ),
        Refusal::AuthFailed { message, .. } => coded(
            status,
            if status == StatusCode::SERVICE_UNAVAILABLE {
                "auth_unavailable"
            } else {
                "invalid_api_key"
            },
            message,
        ),
        Refusal::InsufficientScope => scope_refusal(),
        Refusal::Malformed(Malformed {
            code,
            message,
            detail,
        }) => {
            let param = detail
                .as_ref()
                .and_then(|d| d.pointer("/error/param"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let extra: Vec<(&str, Value)> = detail
                .as_ref()
                .and_then(|d| d.pointer("/error/extra"))
                .and_then(Value::as_object)
                .map(|m| m.iter().map(|(k, v)| (k.as_str(), v.clone())).collect())
                .unwrap_or_default();
            openai_error(status, code, &message, param.as_deref(), &extra)
        }
        Refusal::RateLimited { retry_after_secs } => rate_limited(retry_after_secs),
        Refusal::KeyBudgetExceeded {
            budget_usd,
            spent_usd,
        } => budget_error("key_budget_exceeded", budget_usd, spent_usd),
        Refusal::WorkspaceBudgetExceeded {
            budget_usd,
            spent_usd,
        } => budget_error("workspace_budget_exceeded", budget_usd, spent_usd),
        Refusal::PredictiveBlock { aft_id } => openai_error(
            status,
            "predictive_block",
            "request blocked by Tracelane predictive guardrail",
            None,
            &[("aft_id", json!(aft_id))],
        ),
        Refusal::AuditUnavailable => coded(
            status,
            "audit_unavailable",
            "the tamper-evident ledger is unavailable — this request was not served \
             because it could not be recorded",
        ),
        Refusal::Unpriced { code, message } => coded(status, code, &message),
        Refusal::Policy(d) => openai_error(
            status,
            d.code,
            &d.message,
            None,
            &crate::admission::policy_pairs(&d),
        ),
        Refusal::Control(c) => c.finish(openai_error(status, c.code, &c.message, None, &c.detail)),
    }
}

pub(crate) fn scope_refusal() -> Response {
    openai_error(
        StatusCode::FORBIDDEN,
        "insufficient_scope",
        "This API key is not scoped for this endpoint. It needs the `chat` scope; mint a \
         new key with it in Settings → API Keys.",
        None,
        &[("required_scope", json!("chat"))],
    )
}

pub(crate) fn rate_limited(retry_after_secs: u32) -> Response {
    let mut resp = openai_error(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "rate limit exceeded",
        None,
        &[("retry_after_secs", json!(retry_after_secs))],
    );
    crate::admission::insert_retry_after(&mut resp, retry_after_secs);
    resp
}

/// 402, not 429 — a budget ceiling is a hard stop no retry resolves.
fn budget_error(code: &str, budget_usd: f64, spent_usd: f64) -> Response {
    openai_error(
        StatusCode::PAYMENT_REQUIRED,
        code,
        "this credential has reached its monthly budget",
        None,
        &[
            ("budget_usd", json!(budget_usd)),
            ("spent_usd", json!(spent_usd)),
            ("resets_at", json!(crate::server::next_month_boundary_iso())),
        ],
    )
}

/// 413 with the limit, so the caller learns what to send instead.
pub(crate) fn too_large(what: &str, limit_bytes: usize) -> Response {
    openai_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
        &format!("{what} exceeds the {limit_bytes}-byte limit"),
        None,
        &[("limit_bytes", json!(limit_bytes))],
    )
}

/// A `Malformed` carrying a `param` (the field or part at fault).
pub(crate) fn malformed(code: &'static str, param: &str, message: impl Into<String>) -> Malformed {
    let message = message.into();
    Malformed {
        code,
        detail: Some(json!({ "error": { "message": message, "code": code, "param": param } })),
        message,
    }
}

/// 400 `unsupported_endpoint` naming the provider and the endpoint.
pub(crate) fn unsupported_endpoint(provider: &str, endpoint: &str) -> Malformed {
    malformed(
        "unsupported_endpoint",
        "model",
        format!(
            "provider `{provider}` does not serve `{endpoint}` through the gateway — its own \
             documentation shows no such endpoint at the OpenAI path (see /providers)"
        ),
    )
}

// ── Intake: credential, scope, bounded body ──────────────────────────────────

/// `Authorization: Bearer …` — what every OpenAI SDK sends.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// Validate the credential and the `chat` scope — BEFORE any body is read.
///
/// # Errors
/// Fail-CLOSED: a missing or invalid credential (401, or 503 when the key store is down),
/// or a key without the `chat` scope (403). The `Err` is the ready response.
pub(crate) async fn authenticate(headers: &HeaderMap) -> Result<(Claims, AuthPath), Response> {
    let Some(authorization) = bearer(headers) else {
        return Err(refuse_openai(Refusal::MissingCredentials));
    };
    let (claims, path) = crate::auth::validate_authorization_traced(&authorization)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "authentication failed");
            // OG-20: a policy refusal at authentication keeps its own code.
            refuse_openai(crate::admission::auth_refusal(&err))
        })?;
    if !claims.allows_scope(crate::auth::scope::Scope::Chat) {
        tracing::warn!(sub = %claims.sub, "api key lacks the `chat` scope — refusing");
        return Err(scope_refusal());
    }
    Ok((claims, path))
}

// ── H3: bounded intake (security review 2026-10-02) ──────────────────────────

/// A per-key concurrency limiter with a process-wide ceiling: at most `per_key` holders per
/// key and `process` in all. Shared by the upload intake (`H3`) and the realtime relay (`M4`).
/// The guard releases on drop, so a refused, failed or panicking request cannot leak a slot.
pub(crate) struct Slots {
    inner: parking_lot::Mutex<SlotsInner>,
}

#[derive(Default)]
struct SlotsInner {
    per_key: HashMap<Uuid, usize>,
    total: usize,
}

/// Which ceiling refused a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotRefusal {
    PerKey,
    Process,
    /// `L-2`: the process is inside its reserve, which only opens a key's FIRST slot.
    Reserved,
}

impl Slots {
    pub(crate) fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(SlotsInner::default()),
        }
    }

    /// Take a slot for `key`, or say which ceiling refused it. A ceiling of 0 refuses all
    /// (the fail-CLOSED reading of an unparseable table).
    ///
    /// # Errors
    /// The ceiling that is full.
    pub(crate) fn try_acquire(
        &'static self,
        key: Uuid,
        per_key: usize,
        process: usize,
    ) -> Result<SlotGuard, SlotRefusal> {
        self.try_acquire_reserving(key, per_key, process, 0)
    }

    /// [`Self::try_acquire`] with a RESERVE (`L-2`): the last `reserve` process slots only
    /// open a key's FIRST slot. Keys that already hold slots can take the process total to
    /// `process - reserve` between them and no further, so they cannot exhaust it — a key
    /// holding none still gets in until the whole cap is reached.
    ///
    /// # Errors
    /// The ceiling that is full.
    pub(crate) fn try_acquire_reserving(
        &'static self,
        key: Uuid,
        per_key: usize,
        process: usize,
        reserve: usize,
    ) -> Result<SlotGuard, SlotRefusal> {
        let mut g = self.inner.lock();
        if g.total >= process {
            return Err(SlotRefusal::Process);
        }
        let held = g.per_key.get(&key).copied().unwrap_or(0);
        if held >= per_key {
            return Err(SlotRefusal::PerKey);
        }
        if held > 0 && g.total >= process.saturating_sub(reserve) {
            return Err(SlotRefusal::Reserved);
        }
        g.per_key.insert(key, held + 1);
        g.total += 1;
        Ok(SlotGuard { slots: self, key })
    }

    /// Slots held for `key` right now (tests and diagnostics).
    #[cfg(test)]
    pub(crate) fn held(&self, key: Uuid) -> usize {
        self.inner.lock().per_key.get(&key).copied().unwrap_or(0)
    }
}

/// A held slot; dropping it releases the slot.
pub(crate) struct SlotGuard {
    slots: &'static Slots,
    key: Uuid,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut g = self.slots.inner.lock();
        g.total = g.total.saturating_sub(1);
        if let Some(n) = g.per_key.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.per_key.remove(&self.key);
            }
        }
    }
}

fn upload_slots() -> &'static Slots {
    static S: OnceLock<Slots> = OnceLock::new();
    S.get_or_init(Slots::new)
}

const MIB: usize = 1024 * 1024;

/// `H3` + `M-3`: the memory the media / files / batch routes may hold in buffered request
/// bodies — a process-wide budget of MiB permits, and a ledger of how much of it each tenant
/// holds (its SHARE is capped, so a few tenants cannot hold the whole budget).
pub(crate) struct ByteBudget {
    permits: std::sync::Arc<tokio::sync::Semaphore>,
    per_tenant: parking_lot::Mutex<HashMap<Uuid, usize>>,
    /// `MED-3`: MiB held by FREE tenants together. Changed only under the `per_tenant` lock,
    /// so a check and its grant cannot interleave with another growth.
    free_held: std::sync::atomic::AtomicUsize,
}

impl ByteBudget {
    pub(crate) fn new(mib: usize) -> Self {
        Self {
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                mib.min(tokio::sync::Semaphore::MAX_PERMITS),
            )),
            per_tenant: parking_lot::Mutex::new(HashMap::new()),
            free_held: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// MiB `tenant` holds right now (tests and diagnostics).
    #[cfg(test)]
    pub(crate) fn held_by(&self, tenant: Uuid) -> usize {
        self.per_tenant.lock().get(&tenant).copied().unwrap_or(0)
    }

    /// MiB of the process budget not reserved by anyone (tests and diagnostics).
    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// The process-wide byte budget for buffered bodies.
fn body_budget() -> &'static ByteBudget {
    static B: OnceLock<ByteBudget> = OnceLock::new();
    B.get_or_init(|| ByteBudget::new(translation_policy::media_limits().body_buffer_budget_mb))
}

/// MiB of the PROCESS budget `tenant` holds right now (tests).
#[cfg(test)]
pub(crate) fn process_budget_held_by(tenant: Uuid) -> usize {
    body_budget().held_by(tenant)
}

/// What the intake holds while a body is buffered and handled: the MiB of the byte budget
/// reserved SO FAR (it grows with the bytes received — [`IntakePermit::ensure`]) and one of
/// the tenant's upload slots. Everything releases when it drops — keep it alive until the
/// response is built; a refused, failed, timed-out or panicking request cannot leak a byte.
pub(crate) struct IntakePermit {
    budget: &'static ByteBudget,
    tenant: Uuid,
    /// MiB held — in the process semaphore (`bytes`) AND in the tenant's ledger entry.
    held_mib: usize,
    share_mib: usize,
    /// `M-F`: the process budget's reserve, and what one tenant may hold while drawing on it.
    reserve_mib: usize,
    reserve_tenant_max_mib: usize,
    /// `MED-3`: a free tenant's growth also counts against the free tenants' combined cap.
    free: bool,
    free_total_mib: usize,
    retry_after_secs: u64,
    bytes: Option<tokio::sync::OwnedSemaphorePermit>,
    _slot: SlotGuard,
}

impl IntakePermit {
    /// `M-3`: make the reservation cover `bytes` in total, growing it if needed.
    ///
    /// `M-F` (security re-review 2026-10-03): the last `reserve_mib` of the process budget are
    /// a RESERVE — a growth may take the budget's free MiB below it only while the tenant's
    /// total holding stays within `reserve_tenant_max_mib`. Tenants at their full share can
    /// no longer fill the budget between them (4 × a 1/4 share did), and a tenant holding
    /// nothing still gets a body of up to the allowance buffered. The share check, the
    /// reserve check and the semaphore grant happen under ONE lock, so concurrent growths
    /// cannot both pass a check only one of them fits.
    ///
    /// # Errors
    /// 429 `tenant_memory_share_exhausted` (with `Retry-After`) when the growth would take the
    /// tenant past its share of the budget; 503 `gateway_memory_busy` when the process budget
    /// cannot cover it now, or only out of the reserve this tenant may not draw on.
    /// Fail-CLOSED; what was already held stays held until drop.
    pub(crate) fn ensure(&mut self, bytes: usize) -> Result<(), Box<Response>> {
        let want = bytes.div_ceil(MIB).max(1);
        if want <= self.held_mib {
            return Ok(());
        }
        let more = want - self.held_mib;
        let granted = {
            let mut ledger = self.budget.per_tenant.lock();
            let held = ledger.get(&self.tenant).copied().unwrap_or(0);
            let after = held.saturating_add(more);
            if after > self.share_mib {
                drop(ledger);
                return Err(Box::new(busy(
                    StatusCode::TOO_MANY_REQUESTS,
                    "tenant_memory_share_exhausted",
                    &format!(
                        "this workspace's request bodies in flight would exceed its {} MiB share \
                         of the gateway's buffer — retry when an upload finishes",
                        self.share_mib
                    ),
                    self.retry_after_secs,
                )));
            }
            // MED-3: free tenants together stay within their combined cap.
            let free_held = self
                .budget
                .free_held
                .load(std::sync::atomic::Ordering::Relaxed);
            if self.free && free_held.saturating_add(more) > self.free_total_mib {
                drop(ledger);
                return Err(Box::new(busy(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway_memory_busy",
                    "free workspaces' share of the gateway's upload buffer is in use — retry \
                     shortly",
                    self.retry_after_secs,
                )));
            }
            let free_after = self.budget.permits.available_permits().saturating_sub(more);
            let into_reserve = free_after < self.reserve_mib;
            let granted = if into_reserve && after > self.reserve_tenant_max_mib {
                None
            } else {
                u32::try_from(more).ok().and_then(|n| {
                    std::sync::Arc::clone(&self.budget.permits)
                        .try_acquire_many_owned(n)
                        .ok()
                })
            };
            if granted.is_some() {
                ledger.insert(self.tenant, after);
                if self.free {
                    self.budget
                        .free_held
                        .fetch_add(more, std::sync::atomic::Ordering::Relaxed);
                }
            }
            granted
        };
        let Some(granted) = granted else {
            return Err(Box::new(busy(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway_memory_busy",
                "the gateway is holding as many request bodies as it safely can — retry shortly",
                self.retry_after_secs,
            )));
        };
        match self.bytes.as_mut() {
            Some(p) => p.merge(granted),
            None => self.bytes = Some(granted),
        }
        self.held_mib = want;
        Ok(())
    }

    /// `M-F`: give back what a buffer handed on no longer needs — the reservation shrinks to
    /// cover `bytes` (never below the one MiB a chunk in flight needs), in the process budget
    /// AND the tenant's ledger. A streamed upload calls it once its head has been handed to
    /// the upstream stream; the upload slot stays held until the permit drops.
    pub(crate) fn shrink_to(&mut self, bytes: usize) {
        let want = bytes.div_ceil(MIB).max(1);
        if want >= self.held_mib {
            return;
        }
        let give = self.held_mib - want;
        let Some(released) = self.bytes.as_mut().and_then(|p| p.split(give)) else {
            return;
        };
        drop(released);
        self.release_ledger(give);
        self.held_mib = want;
    }

    /// Append `chunk` to `out`, growing the reservation with the buffer's ALLOCATION (not
    /// just its length — a doubling `Vec` holds up to twice what it was given). `limit` is
    /// the route cap the caller already checked `out.len() + chunk.len()` against.
    pub(crate) fn append(
        &mut self,
        out: &mut Vec<u8>,
        chunk: &[u8],
        limit: usize,
    ) -> Result<(), Box<Response>> {
        let need = out.len() + chunk.len();
        if need > out.capacity() {
            let target = need
                .max(out.capacity().saturating_mul(2))
                .min(limit.max(need));
            self.ensure(target)?;
            out.reserve_exact(target - out.len());
        }
        out.extend_from_slice(chunk);
        Ok(())
    }

    fn release_ledger(&self, mib: usize) {
        let mut ledger = self.budget.per_tenant.lock();
        if self.free && mib > 0 {
            let _ = self.budget.free_held.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |h| Some(h.saturating_sub(mib)),
            );
        }
        if let Some(n) = ledger.get_mut(&self.tenant) {
            *n = n.saturating_sub(mib);
            if *n == 0 {
                ledger.remove(&self.tenant);
            }
        }
    }
}

impl Drop for IntakePermit {
    fn drop(&mut self) {
        // The semaphore permits release with `bytes`; the ledger entry is ours to undo.
        self.release_ledger(self.held_mib);
    }
}

/// 429/503 with `Retry-After` — "busy", never an OOM.
fn busy(status: StatusCode, code: &str, message: &str, retry_after_secs: u64) -> Response {
    let mut resp = openai_error(
        status,
        code,
        message,
        None,
        &[("retry_after_secs", json!(retry_after_secs))],
    );
    crate::admission::insert_retry_after(
        &mut resp,
        u32::try_from(retry_after_secs).unwrap_or(u32::MAX),
    );
    resp
}

/// `H3` + `M-3`: take one of the tenant's concurrent-upload slots and the FIRST MiB of the
/// process byte budget, before a byte of the body is read. The reservation then grows with
/// the bytes actually received ([`IntakePermit::ensure`], via [`read_body`]) — never the
/// route's worst case up front, which let a few slow chunked uploads hold the whole budget.
///
/// # Errors
/// 429 `too_many_concurrent_uploads` when the tenant is at its upload cap; 429
/// `tenant_memory_share_exhausted` when its share is spent; 503 `gateway_memory_busy` when
/// the process budget cannot cover the first MiB. Fail-CLOSED: a zero budget or share
/// (unparseable table) refuses every buffered read.
pub(crate) fn acquire_intake(
    tenant: &TenantId,
    tier: crate::clickhouse_query::PlanTier,
    limits: &MediaLimits,
) -> Result<IntakePermit, Box<Response>> {
    acquire_intake_in(body_budget(), tenant, tier, limits)
}

/// [`acquire_intake`] against an explicit budget (the process one, or a test's own).
///
/// # Errors
/// As [`acquire_intake`].
pub(crate) fn acquire_intake_in(
    budget: &'static ByteBudget,
    tenant: &TenantId,
    tier: crate::clickhouse_query::PlanTier,
    l: &MediaLimits,
) -> Result<IntakePermit, Box<Response>> {
    // Final re-review M-4 (2026-10-03): a FREE tenant (no control plane resolves to free —
    // `.claude/rules/tenancy.md`) gets the smaller share and its own reserve allowance (0 in
    // the table), so free workspaces, which cost nothing to create, cannot hold the budget AND
    // the reserve between them and lock a paying tenant out.
    let free = tier == crate::clickhouse_query::PlanTier::Free;
    let (share_mib, reserve_tenant_max_mib) = if free {
        (
            l.body_buffer_free_tenant_share_mb,
            l.body_buffer_free_reserve_tenant_max_mb,
        )
    } else {
        (
            l.body_buffer_tenant_share_mb,
            l.body_buffer_reserve_tenant_max_mb,
        )
    };
    let slot = upload_slots()
        .try_acquire(*tenant.as_uuid(), l.uploads_per_tenant_max, usize::MAX)
        .map_err(|_| {
            Box::new(busy(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_concurrent_uploads",
                &format!(
                    "this workspace already has {} uploads in progress — retry when one finishes",
                    l.uploads_per_tenant_max
                ),
                l.busy_retry_after_secs,
            ))
        })?;
    let mut permit = IntakePermit {
        budget,
        tenant: *tenant.as_uuid(),
        held_mib: 0,
        share_mib,
        reserve_mib: l.body_buffer_reserved_for_new_tenants_mb,
        reserve_tenant_max_mib,
        free,
        free_total_mib: l.body_buffer_free_tenants_total_mb,
        retry_after_secs: l.busy_retry_after_secs,
        bytes: None,
        _slot: slot,
    };
    permit.ensure(1)?;
    Ok(permit)
}

/// The declared `Content-Length`, when the caller sent one.
fn declared_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
}

/// `M-3`: a request body read with an IDLE bound (the longest gap between two chunks) and a
/// TOTAL bound (the whole read), both from the reference table — a client that trickles or
/// stalls cannot hold its reservation and its upload slot indefinitely.
pub(crate) struct BodyReader {
    stream: axum::body::BodyDataStream,
    idle: std::time::Duration,
    /// When the read began — the total bound counts from here.
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

/// Why [`BodyReader`] stopped short of the end of the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// No chunk for the idle bound.
    Stalled,
    /// The total bound passed.
    TooSlow,
    /// The transport failed.
    Unreadable,
}

impl ReadFailure {
    /// 408 `request_body_timeout` for either bound, 400 `invalid_request` for a failed read.
    pub(crate) fn response(self) -> Response {
        match self {
            Self::TooSlow => coded(
                StatusCode::REQUEST_TIMEOUT,
                "request_body_timeout",
                "the request body took too long to arrive in full — send it faster, or in \
                 smaller requests",
            ),
            Self::Stalled => coded(
                StatusCode::REQUEST_TIMEOUT,
                "request_body_timeout",
                "the request body stalled — no bytes arrived for too long",
            ),
            Self::Unreadable => coded(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the request body could not be read",
            ),
        }
    }
}

impl BodyReader {
    pub(crate) fn new(body: Body, l: &MediaLimits) -> Self {
        let started = tokio::time::Instant::now();
        Self {
            stream: body.into_data_stream(),
            idle: std::time::Duration::from_secs(l.body_read_idle_timeout_secs),
            started,
            deadline: started + std::time::Duration::from_secs(l.body_read_total_timeout_secs),
        }
    }

    /// `M-F`: re-bound the WHOLE read to `total_secs` from its first byte — for a body that
    /// stops being buffered and is streamed on (its reservation shrinks to one MiB), so the
    /// buffering bound no longer fits it. The idle bound is unchanged.
    pub(crate) fn set_total_timeout(&mut self, total_secs: u64) {
        self.deadline = self.started + std::time::Duration::from_secs(total_secs);
    }

    /// The next chunk, `None` at the end of the body.
    ///
    /// # Errors
    /// [`ReadFailure`] past either bound or on a failed read. Fail-CLOSED.
    pub(crate) async fn next(&mut self) -> Result<Option<Bytes>, ReadFailure> {
        let idle_at = tokio::time::Instant::now() + self.idle;
        let total_first = self.deadline <= idle_at;
        match tokio::time::timeout_at(idle_at.min(self.deadline), self.stream.next()).await {
            Err(_) if total_first => Err(ReadFailure::TooSlow),
            Err(_) => Err(ReadFailure::Stalled),
            Ok(None) => Ok(None),
            Ok(Some(Ok(chunk))) => Ok(Some(chunk)),
            Ok(Some(Err(_))) => Err(ReadFailure::Unreadable),
        }
    }

    /// [`Self::next`] with the failure as the ready response.
    ///
    /// # Errors
    /// 408 `request_body_timeout` past either bound; 400 `invalid_request` when the body
    /// cannot be read. Fail-CLOSED.
    pub(crate) async fn next_chunk(&mut self) -> Result<Option<Bytes>, Response> {
        self.next().await.map_err(ReadFailure::response)
    }
}

/// Read at most `cap` bytes of a request body into memory the `permit` covers.
///
/// A declared `Content-Length` over the cap is refused before a byte is read; a body with
/// none (chunked) is cut off the moment it passes the cap, never buffered past it. The
/// reservation grows with the buffer (`M-3`), and the read is bounded in time.
///
/// # Errors
/// 413 `payload_too_large` over the cap; 408 `request_body_timeout`; 429/503 when the
/// reservation cannot grow ([`IntakePermit::ensure`]); 400 `invalid_request` when the body
/// cannot be read. Fail-CLOSED; the caller drops `permit`, which releases everything.
pub(crate) async fn read_body(
    headers: &HeaderMap,
    body: Body,
    cap: usize,
    what: &str,
    permit: &mut IntakePermit,
    limits: &MediaLimits,
) -> Result<Bytes, Response> {
    if declared_length(headers).is_some_and(|n| n > cap) {
        return Err(too_large(what, cap));
    }
    let mut out: Vec<u8> = Vec::new();
    let mut reader = BodyReader::new(body, limits);
    while let Some(chunk) = reader.next_chunk().await? {
        if out.len() + chunk.len() > cap {
            return Err(too_large(what, cap));
        }
        permit.append(&mut out, &chunk, cap).map_err(|r| *r)?;
    }
    Ok(Bytes::from(out))
}

pub(crate) fn content_type_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// The caps the multipart scanner enforces, from the reference table.
pub(crate) fn scan_caps(l: &MediaLimits) -> Caps {
    Caps {
        text_field_max_bytes: l.multipart_text_field_max_bytes,
        max_parts: l.multipart_max_parts,
    }
}

// ── The multipart form, scanned ──────────────────────────────────────────────

/// What a fully-buffered multipart body contains: its text fields and the shape of its
/// file parts. Built by [`scan_form`]; the body itself is never re-encoded.
#[derive(Debug, Default)]
pub(crate) struct Form {
    pub fields: HashMap<String, String>,
    /// `(part name, filename, data bytes)`, in body order.
    pub files: Vec<(String, String, usize)>,
}

impl Form {
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

/// Scan a fully buffered multipart body.
///
/// A repeated text field is refused unless its name ends in `[]` (OpenAI's own spelling
/// for a repeated value): the provider's parser may keep the FIRST or the LAST, and the
/// gateway must not govern one `model` while the provider serves another.
///
/// # Errors
/// A [`ScanError`], or `Malformed("a text field is repeated")`.
pub(crate) fn scan_form(raw: &[u8], content_type: &str, caps: Caps) -> Result<Form, ScanError> {
    let mut scanner = Scanner::new(content_type, caps)?;
    let mut form = Form::default();
    let mut open: Option<(String, String, u64)> = None;
    for chunk in raw.chunks(64 * 1024) {
        for ev in scanner.push(chunk)? {
            match ev {
                Event::Field { name, value } => {
                    if form.fields.insert(name.clone(), value).is_some() && !name.ends_with("[]") {
                        return Err(ScanError::Malformed("a multipart text field is repeated"));
                    }
                }
                Event::FileStart {
                    name,
                    filename,
                    data_offset,
                } => open = Some((name, filename, data_offset)),
                Event::FileEnd { data_end } => {
                    if let Some((name, filename, start)) = open.take() {
                        let len =
                            usize::try_from(data_end.saturating_sub(start)).unwrap_or(usize::MAX);
                        form.files.push((name, filename, len));
                    }
                }
                Event::End => {}
            }
        }
    }
    scanner.finish()?;
    // L2 (security review 2026-10-02): a text field and a file part with the SAME name is the
    // same parser differential as a repeated field — the provider may read the file's bytes
    // where the gateway read (and governed) the field.
    if form
        .files
        .iter()
        .any(|(name, _, _)| form.fields.contains_key(name))
    {
        return Err(ScanError::Malformed(
            "a multipart text field and a file part share a name",
        ));
    }
    Ok(form)
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    fn caps() -> Caps {
        scan_caps(&translation_policy::media_limits())
    }

    /// L2 (security review 2026-10-02): a field and a file part with the same name is refused.
    #[test]
    fn l2_a_field_and_a_file_part_with_the_same_name_are_refused() {
        let (ct, body) = test_support::multipart(&[
            ("model", None, b"whisper-1"),
            ("model", Some("m.txt"), b"gpt-4o-transcribe"),
            ("file", Some("a.wav"), b"RIFF"),
        ]);
        assert!(scan_form(&body, &ct, caps()).is_err());
        // Must ACCEPT: distinct names.
        let (ct, body) = test_support::multipart(&[
            ("model", None, b"whisper-1"),
            ("file", Some("a.wav"), b"RIFF"),
        ]);
        assert!(scan_form(&body, &ct, caps()).is_ok());
    }

    /// M4 / H3: the shared slot limiter — per-key and process ceilings, released on drop.
    #[test]
    fn slots_enforce_both_ceilings_and_release_on_drop() {
        static S: OnceLock<Slots> = OnceLock::new();
        let s = S.get_or_init(Slots::new);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let g1 = s.try_acquire(a, 2, 3).expect("1");
        let g2 = s.try_acquire(a, 2, 3).expect("2");
        assert_eq!(s.try_acquire(a, 2, 3).err(), Some(SlotRefusal::PerKey));
        let g3 = s.try_acquire(b, 2, 3).expect("3");
        assert_eq!(s.try_acquire(b, 2, 3).err(), Some(SlotRefusal::Process));
        drop(g1);
        assert_eq!(s.held(a), 1);
        assert!(s.try_acquire(a, 2, 3).is_ok());
        drop((g2, g3));
        assert_eq!(s.held(b), 0);
    }

    /// L-2 (security re-review 2026-10-02): the process cap keeps a reserve that only opens a
    /// key's FIRST slot. A tenant that already holds sessions is refused inside the reserve
    /// while a tenant holding none still gets in — so tenants at their share cannot use the
    /// whole cap up between them.
    #[test]
    fn l2_a_tenant_at_its_share_is_refused_while_another_still_gets_a_first_slot() {
        static S: OnceLock<Slots> = OnceLock::new();
        let s = S.get_or_init(Slots::new);
        let (a, b, c, d) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        // process 6, per-key 10, reserve 2: keys already holding slots stop at 4 in total.
        let held_a: Vec<_> = (0..4)
            .map(|_| {
                s.try_acquire_reserving(a, 10, 6, 2)
                    .expect("a, outside the reserve")
            })
            .collect();
        assert_eq!(
            s.try_acquire_reserving(a, 10, 6, 2).err(),
            Some(SlotRefusal::Reserved),
            "a already holds slots: the reserve is not for it"
        );
        let gb = s
            .try_acquire_reserving(b, 10, 6, 2)
            .expect("b's FIRST slot comes out of the reserve");
        assert_eq!(
            s.try_acquire_reserving(b, 10, 6, 2).err(),
            Some(SlotRefusal::Reserved)
        );
        let gc = s
            .try_acquire_reserving(c, 10, 6, 2)
            .expect("c's first slot");
        assert_eq!(
            s.try_acquire_reserving(d, 10, 6, 2).err(),
            Some(SlotRefusal::Process),
            "the cap itself still holds"
        );
        drop((held_a, gb, gc));
        assert_eq!(s.held(a), 0);
    }

    // ── M-3 (security re-review 2026-10-02): the body budget ──────────────────

    const TEST_MIB: usize = 1024 * 1024;

    /// A budget of its own per test, so the process budget other tests use is untouched.
    fn test_budget(mib: usize) -> &'static ByteBudget {
        Box::leak(Box::new(ByteBudget::new(mib)))
    }

    fn test_limits(share_mb: usize, idle_secs: u64, total_secs: u64) -> MediaLimits {
        MediaLimits {
            body_buffer_tenant_share_mb: share_mb,
            body_read_idle_timeout_secs: idle_secs,
            body_read_total_timeout_secs: total_secs,
            // No reserve unless a test sets one (M-F), so the share / budget tests read alone.
            body_buffer_reserved_for_new_tenants_mb: 0,
            body_buffer_reserve_tenant_max_mb: 0,
            ..translation_policy::media_limits()
        }
    }

    /// M-F (security re-review 2026-10-03): with a share of 1/4 of the budget, four tenants
    /// at their full share used to hold ALL of it — every other tenant 503'd. The last
    /// `reserve` MiB are now kept for tenants holding little: the four can take the budget
    /// down to the reserve and no further, and a fifth tenant holding nothing still gets a
    /// body of up to the per-tenant reserve allowance buffered.
    #[test]
    fn m_f_four_tenants_at_full_share_cannot_lock_out_a_fifth_holding_nothing() {
        let budget = test_budget(64);
        let l = MediaLimits {
            body_buffer_reserved_for_new_tenants_mb: 8,
            body_buffer_reserve_tenant_max_mb: 4,
            ..test_limits(16, 30, 300)
        };
        let hogs: Vec<TenantId> = (0..4).map(|_| test_tenant()).collect();
        let mut permits = Vec::new();
        for (i, h) in hogs.iter().enumerate() {
            let Ok(mut p) =
                acquire_intake_in(budget, h, crate::clickhouse_query::PlanTier::Business, &l)
            else {
                panic!("hog {i} gets its first MiB");
            };
            // Each grows MiB by MiB toward its full share, as a body arriving would.
            for mib in 2..=16 {
                if p.ensure(mib * TEST_MIB).is_err() {
                    break;
                }
            }
            permits.push(p);
        }
        assert_eq!(
            budget.available(),
            8,
            "the hogs stopped exactly at the reserve line"
        );
        let held: usize = hogs.iter().map(|h| budget.held_by(*h.as_uuid())).sum();
        assert_eq!(held, 64 - budget.available(), "ledger and semaphore agree");
        // A hog cannot draw on the reserve.
        let Err(resp) = permits[3].ensure(16 * TEST_MIB) else {
            panic!("a tenant holding its share must not draw on the reserve");
        };
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // The fifth tenant, holding nothing, gets in — and up to the reserve allowance.
        let fifth = test_tenant();
        let Ok(mut p5) = acquire_intake_in(
            budget,
            &fifth,
            crate::clickhouse_query::PlanTier::Business,
            &l,
        ) else {
            panic!("a tenant holding nothing must not be locked out");
        };
        assert!(
            p5.ensure(4 * TEST_MIB).is_ok(),
            "a body within the reserve allowance is buffered"
        );
        assert!(
            p5.ensure(5 * TEST_MIB).is_err(),
            "past the allowance the reserve is not for one tenant"
        );
        drop((permits, p5));
        assert_eq!(budget.available(), 64, "everything comes back");
    }

    /// Final re-review M-4 (2026-10-03): the reserve could still be emptied by four small
    /// tenants, and free workspaces cost nothing to create — so N free workspaces could lock
    /// every paying customer out of media, files and batches. Now the tier decides: a FREE
    /// tenant has a smaller share and may NOT draw on the reserve at all, so however many free
    /// workspaces fill the budget, a paying tenant holding nothing still gets a body buffered.
    #[test]
    fn m4_free_workspaces_cannot_lock_a_paying_tenant_out() {
        use crate::clickhouse_query::PlanTier;
        let budget = test_budget(64);
        let l = MediaLimits {
            body_buffer_reserved_for_new_tenants_mb: 8,
            body_buffer_reserve_tenant_max_mb: 4,
            body_buffer_free_tenant_share_mb: 8,
            body_buffer_free_reserve_tenant_max_mb: 0,
            ..test_limits(16, 30, 300)
        };
        // Free hogs, each growing toward its (free) share, until the budget refuses them.
        let mut hogs = Vec::new();
        for _ in 0..16 {
            let t = test_tenant();
            let Ok(mut p) = acquire_intake_in(budget, &t, PlanTier::Free, &l) else {
                break;
            };
            for mib in 2..=16 {
                if p.ensure(mib * TEST_MIB).is_err() {
                    break;
                }
            }
            assert!(p.held_mib <= 8, "a free tenant stops at the free share");
            hogs.push(p);
        }
        assert_eq!(
            budget.available(),
            8,
            "free tenants never touch the reserve"
        );
        // Another FREE tenant holding nothing is refused — the reserve is not for it.
        let Err(resp) = acquire_intake_in(budget, &test_tenant(), PlanTier::Free, &l) else {
            panic!("a free tenant must not draw on the reserve");
        };
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // A PAYING tenant holding nothing still gets in, up to the reserve allowance.
        let Ok(mut paid) = acquire_intake_in(budget, &test_tenant(), PlanTier::Builder, &l) else {
            panic!("a paying tenant must not be locked out by free workspaces");
        };
        assert!(paid.ensure(4 * TEST_MIB).is_ok());
        drop((hogs, paid));
        assert_eq!(budget.available(), 64, "everything comes back");
    }

    /// LAST review MED-3 (2026-10-03): with only per-tenant shares, enough free workspaces
    /// still held everything outside the reserve, and a paying tenant was then held to the
    /// reserve allowance — locked out of any body larger than it (a full batch file). Free
    /// tenants now share ONE combined cap, so the room a paying tenant needs for a full body
    /// stays free however many free workspaces upload at once.
    #[test]
    fn med3_free_workspaces_together_cannot_crowd_out_a_paying_tenants_full_body() {
        use crate::clickhouse_query::PlanTier;
        let budget = test_budget(64);
        let l = MediaLimits {
            body_buffer_reserved_for_new_tenants_mb: 8,
            body_buffer_reserve_tenant_max_mb: 4,
            body_buffer_free_tenant_share_mb: 8,
            body_buffer_free_reserve_tenant_max_mb: 0,
            body_buffer_free_tenants_total_mb: 40,
            ..test_limits(16, 30, 300)
        };
        let mut hogs = Vec::new();
        for _ in 0..16 {
            let Ok(mut p) = acquire_intake_in(budget, &test_tenant(), PlanTier::Free, &l) else {
                break;
            };
            for mib in 2..=8 {
                if p.ensure(mib * TEST_MIB).is_err() {
                    break;
                }
            }
            hogs.push(p);
        }
        assert_eq!(
            64 - budget.available(),
            40,
            "free tenants together stop at their cap"
        );
        // A paying tenant still gets a FULL 16 MiB body (its share), not just the reserve.
        let Ok(mut paid) = acquire_intake_in(budget, &test_tenant(), PlanTier::Team, &l) else {
            panic!("the paying tenant gets in");
        };
        assert!(
            paid.ensure(16 * TEST_MIB).is_ok(),
            "a full body for the paying tenant"
        );
        drop((hogs, paid));
        assert_eq!(budget.available(), 64, "everything comes back");
    }

    /// M-F: `shrink_to` gives back what a handed-off buffer no longer needs — in the
    /// semaphore AND the tenant's ledger — and never below one MiB.
    #[test]
    fn m_f_shrink_returns_the_reservation_to_both_the_budget_and_the_ledger() {
        let budget = test_budget(64);
        let l = test_limits(32, 30, 300);
        let t = test_tenant();
        let mut p = acquire_intake_in(budget, &t, crate::clickhouse_query::PlanTier::Business, &l)
            .unwrap_or_else(|_| panic!("permit"));
        assert!(p.ensure(20 * TEST_MIB).is_ok());
        assert_eq!(budget.held_by(*t.as_uuid()), 20);
        p.shrink_to(0);
        assert_eq!(budget.held_by(*t.as_uuid()), 1);
        assert_eq!(budget.available(), 63);
        assert!(p.ensure(3 * TEST_MIB).is_ok(), "it can grow again");
        assert_eq!(budget.available(), 61);
        drop(p);
        assert_eq!(budget.available(), 64);
        assert_eq!(budget.held_by(*t.as_uuid()), 0);
    }

    fn test_tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::new_v4())
    }

    /// M-3: a chunked body that sends a little and then stalls is cut by the IDLE timeout with
    /// a 408, and everything it reserved comes back when the permit drops.
    #[tokio::test]
    async fn m3_a_stalled_chunked_body_is_cut_by_the_idle_timeout_and_releases_its_reservation() {
        let budget = test_budget(64);
        let t = test_tenant();
        let l = test_limits(32, 1, 30);
        let mut permit =
            acquire_intake_in(budget, &t, crate::clickhouse_query::PlanTier::Business, &l)
                .unwrap_or_else(|_| panic!("permit"));
        let first: Result<Bytes, std::io::Error> = Ok(Bytes::from(vec![b'x'; 3 * TEST_MIB]));
        let body =
            Body::from_stream(futures::stream::iter(vec![first]).chain(futures::stream::pending()));
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_body(
                &HeaderMap::new(),
                body,
                100 * TEST_MIB,
                "the body",
                &mut permit,
                &l,
            ),
        )
        .await
        .expect("the read must be cut by the idle timeout, not hang");
        let Err(resp) = read else {
            panic!("a stalled body is refused")
        };
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        let v: Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), 1 << 16)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(v["error"]["code"], json!("request_body_timeout"));
        assert!(
            budget.held_by(*t.as_uuid()) >= 3,
            "the received bytes were reserved"
        );
        drop(permit);
        assert_eq!(
            budget.held_by(*t.as_uuid()),
            0,
            "the tenant's share is released"
        );
        assert_eq!(budget.available(), 64, "the process budget is whole again");
    }

    /// M-3: a body that keeps trickling — never idle long enough to trip the idle bound — is
    /// cut by the TOTAL timeout.
    #[tokio::test]
    async fn m3_a_trickling_body_is_cut_by_the_total_timeout() {
        let budget = test_budget(16);
        let t = test_tenant();
        let l = test_limits(8, 1, 2);
        let mut permit =
            acquire_intake_in(budget, &t, crate::clickhouse_query::PlanTier::Business, &l)
                .unwrap_or_else(|_| panic!("permit"));
        let trickle = futures::stream::unfold((), |()| async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            Some((Ok::<_, std::io::Error>(Bytes::from_static(b"x")), ()))
        });
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_body(
                &HeaderMap::new(),
                Body::from_stream(trickle),
                TEST_MIB,
                "the body",
                &mut permit,
                &l,
            ),
        )
        .await
        .expect("the read must be cut by the total timeout, not run on");
        let Err(resp) = read else {
            panic!("a trickling body is refused")
        };
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        drop(permit);
        assert_eq!(budget.available(), 16);
    }

    /// M-3: the reservation grows with the bytes RECEIVED — one MiB before a byte is read, a
    /// few MiB for a few MiB of body — never the route's 100 MiB worst case up front.
    #[tokio::test]
    async fn m3_the_reservation_grows_with_the_bytes_received_not_the_cap() {
        let budget = test_budget(256);
        let t = test_tenant();
        let l = test_limits(200, 30, 300);
        let mut permit =
            acquire_intake_in(budget, &t, crate::clickhouse_query::PlanTier::Business, &l)
                .unwrap_or_else(|_| panic!("permit"));
        assert_eq!(
            budget.held_by(*t.as_uuid()),
            1,
            "one MiB before the body is read"
        );
        let chunks: Vec<Result<Bytes, std::io::Error>> = (0..48)
            .map(|_| Ok(Bytes::from(vec![b'y'; 64 * 1024])))
            .collect();
        let raw = read_body(
            &HeaderMap::new(),
            Body::from_stream(futures::stream::iter(chunks)),
            100 * TEST_MIB,
            "the body",
            &mut permit,
            &l,
        )
        .await
        .unwrap_or_else(|r| panic!("read refused: {}", r.status()));
        assert_eq!(raw.len(), 3 * TEST_MIB);
        let held = budget.held_by(*t.as_uuid());
        assert!(
            (3..=6).contains(&held),
            "3 MiB received ⇒ 3..=6 MiB reserved (the buffer's allocation), got {held}"
        );
        assert_eq!(budget.available(), 256 - held, "ledger and semaphore agree");
    }

    /// M-3: one tenant cannot reserve past its SHARE of the budget — 429 with `Retry-After`
    /// while plenty of the process budget is left — and another tenant still gets through.
    #[tokio::test]
    async fn m3_one_tenant_cannot_pass_its_share_while_another_still_gets_through() {
        let budget = test_budget(64);
        let l = test_limits(8, 30, 300);
        let (a, b) = (test_tenant(), test_tenant());
        let mut pa = acquire_intake_in(budget, &a, crate::clickhouse_query::PlanTier::Business, &l)
            .unwrap_or_else(|_| panic!("a"));
        assert!(pa.ensure(8 * TEST_MIB).is_ok(), "a, within its share");
        let Err(resp) = pa.ensure(9 * TEST_MIB) else {
            panic!("a reservation past the tenant's share must be refused")
        };
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get("retry-after").is_some());
        // A second upload from the same tenant cannot take what the first left of the share.
        assert!(
            acquire_intake_in(budget, &a, crate::clickhouse_query::PlanTier::Business, &l).is_err(),
            "the share counts every upload the tenant has in flight"
        );
        // …and a body read that would pass it is refused the same way, mid-read.
        let mut pb = acquire_intake_in(budget, &b, crate::clickhouse_query::PlanTier::Business, &l)
            .unwrap_or_else(|_| panic!("b"));
        assert!(
            pb.ensure(8 * TEST_MIB).is_ok(),
            "another tenant is unaffected"
        );
        drop(pa);
        assert_eq!(budget.held_by(*a.as_uuid()), 0);
        assert_eq!(budget.held_by(*b.as_uuid()), 8);
    }

    /// H3 (kept under M-3): growth the PROCESS budget cannot cover is a 503 with
    /// `Retry-After` — never an attempt to buffer — and leaks nothing.
    #[test]
    fn h3_growth_past_the_process_budget_is_refused_and_leaks_nothing() {
        let budget = test_budget(4);
        let l = test_limits(64, 30, 300);
        let t = test_tenant();
        let mut p = acquire_intake_in(budget, &t, crate::clickhouse_query::PlanTier::Business, &l)
            .unwrap_or_else(|_| panic!("permit"));
        let Err(resp) = p.ensure(5 * TEST_MIB) else {
            panic!("a reservation larger than the whole budget cannot be granted");
        };
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get("retry-after").is_some());
        assert_eq!(
            budget.held_by(*t.as_uuid()),
            1,
            "the refused growth was rolled back"
        );
        drop(p);
        assert_eq!(budget.available(), 4);
        assert_eq!(budget.held_by(*t.as_uuid()), 0);
    }
}

// ── Routing and capability ───────────────────────────────────────────────────

/// Resolve `model` to a provider that serves `capability`, fail-CLOSED.
///
/// # Errors
/// 400 `unroutable_model` (no provider owns the model — there is no default provider) or
/// 400 `unsupported_endpoint` (the provider's catalog row has no such capability).
pub(crate) fn provider_for(
    model: &str,
    capability: &str,
    endpoint: &str,
) -> Result<&'static str, Malformed> {
    let Some(provider_id) = crate::providers::ProviderRegistry::provider_id_for_model(model) else {
        return Err(Malformed {
            code: "unroutable_model",
            message: format!(
                "no provider is configured for model `{model}` — check the model name"
            ),
            detail: None,
        });
    };
    if provider_serves(provider_id, capability) {
        Ok(provider_id)
    } else {
        Err(unsupported_endpoint(provider_id, endpoint))
    }
}

/// Does `provider_id` serve `capability`? Catalog rows by their doc-derived column; the
/// native Cohere adapter serves rerank only (its `POST /v2/rerank`).
pub(crate) fn provider_serves(provider_id: &str, capability: &str) -> bool {
    if provider_id == "cohere" {
        return capability == "rerank";
    }
    crate::providers::catalog::by_id(provider_id).is_some_and(|d| d.has_capability(capability))
}

/// The provider a files / batches call targets: `x-tracelane-provider` or `openai`.
///
/// # Errors
/// 400 `unsupported_endpoint` when the named provider lacks `capability` (or is not a
/// catalog provider at all).
pub(crate) fn provider_from_header(
    headers: &HeaderMap,
    capability: &str,
    endpoint: &str,
) -> Result<&'static str, Box<Response>> {
    let wanted = match headers.get(PROVIDER_HEADER) {
        None => DEFAULT_FILES_PROVIDER,
        Some(v) => v.to_str().unwrap_or(""),
    };
    let Some(def) =
        crate::providers::catalog::by_id(wanted).filter(|d| d.has_capability(capability))
    else {
        let m = unsupported_endpoint(&wanted.chars().take(64).collect::<String>(), endpoint);
        return Err(Box::new(refuse_openai(Refusal::Malformed(Malformed {
            detail: Some(
                json!({ "error": { "message": m.message, "code": m.code, "param": PROVIDER_HEADER } }),
            ),
            ..m
        }))));
    };
    Ok(def.id)
}

// ── Upstream ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub(crate) enum ClientKind {
    /// Media routes: `media_timeout_secs`.
    Media,
    /// Files / batches: `files_timeout_secs` (a half-gigabyte upload is not a 5-minute call).
    Files,
}

/// Two process-wide clients (connection reuse), from `safe_client_builder` (redirects
/// disabled); every URL is still `validate_url`'d before the call.
///
/// # Errors
/// Fail-CLOSED: `Err` only if no client can be built; never an unguarded one.
fn upstream_client(kind: ClientKind) -> anyhow::Result<&'static reqwest::Client> {
    static MEDIA: OnceLock<reqwest::Client> = OnceLock::new();
    static FILES: OnceLock<reqwest::Client> = OnceLock::new();
    let (cell, secs) = match kind {
        ClientKind::Media => (
            &MEDIA,
            translation_policy::media_limits().media_timeout_secs,
        ),
        ClientKind::Files => (
            &FILES,
            translation_policy::media_limits().files_timeout_secs,
        ),
    };
    if let Some(c) = cell.get() {
        return Ok(c);
    }
    // A table that did not parse reads 0 s: refuse rather than build a client that
    // times out instantly (or never).
    anyhow::ensure!(secs > 0, "media timeouts are not configured");
    let built = crate::ssrf_guard::safe_client_builder()
        .timeout(std::time::Duration::from_secs(secs))
        .build()?;
    Ok(cell.get_or_init(|| built))
}

/// `{base}/v1/{segments…}?{query}` for a catalog provider, or `{cohere v2 base}/{segments…}`
/// for the native Cohere adapter. Segments are PUSHED (percent-encoded), never concatenated.
///
/// # Errors
/// Fail-CLOSED on a provider with no adapter or an unparseable base URL.
pub(crate) fn upstream_url(
    state: &AppState,
    provider_id: &str,
    segments: &[&str],
    query: &[(String, String)],
) -> anyhow::Result<reqwest::Url> {
    let base = if provider_id == "cohere" {
        state
            .providers
            .cohere
            .base_url()
            .trim_end_matches('/')
            .to_owned()
    } else if let Some(p) = state.providers.compat(provider_id) {
        format!("{}/v1", p.base_url.trim_end_matches('/'))
    } else {
        anyhow::bail!("provider '{provider_id}' has no adapter for this endpoint");
    };
    let mut url = reqwest::Url::parse(&base)?;
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("provider base URL cannot carry a path"))?;
        path.pop_if_empty();
        for s in segments {
            path.push(s);
        }
    }
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    Ok(url)
}

pub(crate) enum UpstreamBody {
    None,
    Bytes(Bytes),
    /// Streamed to the provider as it arrives (file uploads).
    Stream(reqwest::Body),
}

/// One request to a provider with the tenant's own key.
pub(crate) struct Upstream<'a> {
    pub deadlines: crate::routing::deadlines::Budget,
    pub client: ClientKind,
    pub method: reqwest::Method,
    pub provider_id: &'a str,
    pub segments: &'a [&'a str],
    pub query: &'a [(String, String)],
    pub caller_headers: &'a HeaderMap,
    pub content_type: Option<&'a str>,
    pub body: UpstreamBody,
    pub key: &'a secrecy::SecretString,
}

/// Send `up`.
///
/// SSRF: `validate_url` before the call, `safe_client_builder` for the client; the
/// caller's own credential never leaves (`forwarded_request_headers` withholds it and
/// any value carrying a Tracelane key shape).
///
/// # Errors
/// Fail-CLOSED on an SSRF refusal, a client-build failure or a transport failure. A
/// non-2xx is `Ok` — the caller maps it (D7: [`crate::openai_responses::relay_upstream_error`]).
pub(crate) async fn send(state: &AppState, up: Upstream<'_>) -> anyhow::Result<reqwest::Response> {
    let url = upstream_url(state, up.provider_id, up.segments, up.query)?;
    crate::ssrf_guard::validate_url(url.as_str()).await?;
    let mut req = upstream_client(up.client)?.request(up.method, url);
    for (name, value) in crate::openai_responses::forwarded_request_headers(up.caller_headers) {
        req = req.header(name, value);
    }
    // The key is exposed exactly once, at the header build.
    req = req.bearer_auth(up.key.expose_secret());
    if let Some(ct) = up.content_type {
        req = req.header(axum::http::header::CONTENT_TYPE, ct);
    }
    req = match up.body {
        UpstreamBody::None => req,
        UpstreamBody::Bytes(b) => req.body(b),
        UpstreamBody::Stream(s) => req.body(s),
    };
    up.deadlines
        .scope(crate::routing::deadlines::send(req))
        .await
}

/// The 502 for a transport failure (nothing about the cause is echoed).
pub(crate) fn provider_unavailable() -> Response {
    coded(
        StatusCode::BAD_GATEWAY,
        "provider_unavailable",
        "the provider did not serve this request",
    )
}

/// The response headers a 2xx relays: the content type and the provider's own request id /
/// rate-limit headers. Never `content-length` (the body may be re-chunked) or a cookie.
pub(crate) fn relayed_success_headers(
    upstream: &reqwest::Response,
) -> Vec<(axum::http::HeaderName, HeaderValue)> {
    upstream
        .headers()
        .iter()
        .filter(|(n, _)| {
            n.as_str() == "content-type"
                || crate::openai_responses::is_relayed_response_header(n.as_str())
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect()
}

// ── Request guardrails over a text ───────────────────────────────────────────

/// Why the request rails refused a media request.
pub(crate) struct RailRefusal {
    /// The span error reason / `dispatch_guard.abort` code.
    pub code: &'static str,
    pub aft: Option<&'static str>,
    pub response: Response,
}

/// A one-message `ChatRequest` carrying `text` — the SHAPE the rails are defined over.
/// The synthetic request exists only to be scanned: it is never sent anywhere.
pub(crate) fn text_view(model: &str, texts: &[&str]) -> ChatRequest {
    ChatRequest {
        model: model.to_owned(),
        messages: texts
            .iter()
            .map(|t| Message {
                role: Role::User,
                content: MessageContent::Text((*t).to_owned()),
                tool_call_id: None,
                tool_calls: None,
            })
            .collect(),
        ..Default::default()
    }
}

/// Run the request-side rails over `texts` (prompt, speech input, rerank query and
/// documents) — the SAME engine call `/v1/chat/completions` makes.
///
/// A media request body cannot be rewritten (a multipart body is forwarded verbatim; a
/// rerank body has structure), so a `Redact` decision REFUSES here exactly as `Block`
/// does: the caller is told which rail fired and removes the text, rather than the gateway
/// silently sending a different request than the one the caller made.
///
/// # Errors
/// Fail-CLOSED: a block / redact decision (403 `guardrail_block`) or a verdict that could
/// not be recorded (503 `audit_unavailable`).
pub(crate) async fn run_request_rails(
    state: &AppState,
    claims: &Claims,
    correlation_id: ulid::Ulid,
    model: &str,
    texts: &[&str],
    conversation_id: Option<String>,
) -> Result<(), RailRefusal> {
    use crate::guardrail::{Decision, Outcome};
    let request = text_view(model, texts);
    let gr = state
        .guardrail
        .evaluate_request(crate::guardrail::RequestInputs {
            tenant_id: &claims.tenant_id,
            api_key_id: Some(claims.sub.as_str()),
            project_id: claims.governance.as_ref().and_then(|g| g.project_id),
            correlation_id,
            request: &request,
            rag_context: Vec::new(),
            session: crate::guardrail::SessionState::fresh(conversation_id),
            actor: claims.sub.as_str(),
            egress_json: None,
        })
        .await;
    if gr.audit_publish_failed {
        tracing::error!(
            correlation_id = %correlation_id,
            "guardrail verdict audit publish failed — refusing request (fail-closed)"
        );
        return Err(RailRefusal {
            code: "audit_unavailable",
            aft: None,
            response: coded(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "the guardrail verdict could not be recorded — this request was not served",
            ),
        });
    }
    if gr.is_block() || gr.outcome.decision == Decision::Redact {
        let firing = gr
            .outcome
            .records
            .iter()
            .find(|r| r.outcome.outcome == Outcome::Block)
            .or_else(|| {
                gr.outcome
                    .records
                    .iter()
                    .find(|r| r.outcome.outcome == Outcome::Redact)
            });
        let rail = firing.map_or("guardrail", |r| r.rail);
        let reason = firing
            .and_then(|r| r.outcome.reason_code)
            .unwrap_or("guardrail_block");
        tracing::warn!(rail, reason_code = reason, correlation_id = %correlation_id, "media request blocked by inline guardrail");
        return Err(RailRefusal {
            code: "guardrail_block",
            aft: crate::guardrail::rails::r3_tool_safety::reason_to_aft(reason),
            response: openai_error(
                StatusCode::FORBIDDEN,
                "guardrail_block",
                "request blocked by Tracelane inline guardrail — remove the flagged text and retry",
                None,
                &[
                    ("rail", json!(rail)),
                    ("reason_code", json!(reason)),
                    ("correlation_id", json!(correlation_id.to_string())),
                ],
            ),
        });
    }
    Ok(())
}

// ── Spans ────────────────────────────────────────────────────────────────────

/// What a media span records beyond the common attributes.
pub(crate) struct MediaSpanFacts<'a> {
    pub operation: &'static str,
    pub endpoint: &'static str,
    pub input_tokens: u32,
    pub output_tokens: u32,
    /// `(attribute, value)` unit facts: `tracelane.usage.images_generated`, ….
    pub units: Vec<(&'static str, Value)>,
    /// Cost from the per-unit table, used only when no token price applied.
    pub unit_cost_usd: Option<f64>,
    pub error_reason: Option<&'a str>,
    pub timing: Option<crate::server::GatewayTiming>,
}

/// The span for one media / files / batch call. One definition of the common attribute
/// set (`build_gateway_span`), with the OTel GenAI operation name this route owns.
#[allow(clippy::too_many_arguments)]
pub(crate) fn media_span(
    tenant_id: &TenantId,
    trace_id: Uuid,
    parent_span_id: Option<Uuid>,
    provider_id: &str,
    model: &str,
    identity: &crate::server::CallerIdentity,
    start_time: chrono::DateTime<chrono::Utc>,
    api_key_id: Option<&str>,
    facts: MediaSpanFacts<'_>,
) -> TracelaneSpan {
    let mut span = crate::server::build_gateway_span(
        tenant_id,
        trace_id,
        parent_span_id,
        model,
        identity,
        start_time,
        facts.input_tokens,
        facts.output_tokens,
        None,
        crate::server::SpanUsageMeta::default(),
        None,
        facts.timing,
        facts.error_reason,
        api_key_id,
    );
    // The ROUTED provider, not a guess from the model string: files and batches carry no model.
    span.attributes.gen_ai_system = Some(provider_id.to_owned());
    span.attributes.gen_ai_provider_name = Some(provider_id.to_owned());
    span.name = format!("gen_ai.{}", facts.operation);
    span.attributes.gen_ai_operation_name = Some(facts.operation.to_owned());
    span.attributes
        .extra
        .insert("tracelane.media.endpoint".into(), json!(facts.endpoint));
    for (k, v) in facts.units {
        span.attributes.extra.insert(k.into(), v);
    }
    // A token price (`pricing::cost_usd`, applied inside `build_gateway_span`) wins; the
    // per-unit table fills in only when none applied. Neither ⇒ cost stays `None` and the
    // call is counted as unpriced — never 0.
    if span.attributes.gen_ai_usage_cost.is_none()
        && let Some(c) = facts.unit_cost_usd
    {
        span.attributes.gen_ai_usage_cost = Some(c);
        span.attributes.tracelane_usage_cost_origin = Some("computed".to_owned());
    }
    span
}

/// Publish a span and count its cost against the key and workspace budgets.
pub(crate) fn publish(state: &AppState, api_key_id: Option<&str>, span: TracelaneSpan) {
    crate::server::record_key_spend(api_key_id, &span);
    crate::server::spawn_span_publish(state, span);
}

// ── JSON helpers ─────────────────────────────────────────────────────────────

pub(crate) fn str_field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// A provider key for `provider_id` — the tenant's OWN, fail-CLOSED, each failure mapped
/// to the response that tells the customer what to DO. `Err` is `(response, abort code)`;
/// the `bool` is whether the lookup was a control-plane round trip (a cold request).
pub(crate) async fn tenant_key(
    tenant_id: &TenantId,
    provider_id: &str,
) -> (
    Result<std::sync::Arc<secrecy::SecretString>, (Response, &'static str)>,
    bool,
) {
    let (res, cold) = crate::openai_responses::provider_key(tenant_id, provider_id).await;
    (
        res.map_err(|(status, code, message)| {
            tracing::warn!(provider = provider_id, code, "provider key unresolvable");
            (coded(status, code, &message), code)
        }),
        cold,
    )
}

// ── Test support ─────────────────────────────────────────────────────────────

/// Fixtures the OG-06 route tests share (`media_routes`, `files_batches`). Debug-only for the
/// reason `handler_harness` is: wiremock binds loopback and the SSRF bypass is debug-only.
#[cfg(all(test, debug_assertions))]
pub(crate) mod test_support {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use axum::http::{HeaderMap, HeaderValue};
    use tracelane_shared::TenantId;
    use uuid::Uuid;

    use crate::server::AppState;

    pub(crate) fn tenant() -> TenantId {
        TenantId::from_jwt_claim(Uuid::new_v4())
    }

    pub(crate) fn claims_for(t: &TenantId) -> crate::auth::Claims {
        crate::auth::Claims {
            tenant_id: t.clone(),
            sub: format!("apikey:{}", Uuid::new_v4()),
            auth_method: crate::auth::AuthMethod::ApiKey,
            role: None,
            key_scope: crate::auth::scope::KeyScope::LegacyFullSurface,
            budget_usd_monthly: None,
            rate_limit_rpm: None,
            budget_reset: crate::spend::BudgetReset::Monthly,
            governance: None,
        }
    }

    pub(crate) fn scoped_claims(
        t: &TenantId,
        scopes: &[crate::auth::scope::Scope],
    ) -> crate::auth::Claims {
        crate::auth::Claims {
            key_scope: crate::auth::scope::KeyScope::Scoped(
                scopes.iter().copied().collect::<BTreeSet<_>>(),
            ),
            ..claims_for(t)
        }
    }

    /// Present `claims` to every credential check on this thread until the guard drops.
    pub(crate) fn as_claims(claims: crate::auth::Claims) -> crate::auth::test_claims::Guard {
        crate::auth::test_claims::Guard::set(claims)
    }

    pub(crate) fn key_for(t: &TenantId, provider: &str) -> String {
        format!(
            "unit-test-{provider}-key-{}-do-not-use",
            &t.to_string()[..8]
        )
    }

    pub(crate) fn install_byok(t: &TenantId, provider: &'static str) {
        crate::db::provider_keys::cache_decrypted(
            t,
            provider,
            Arc::new(secrecy::SecretString::from(key_for(t, provider))),
        );
    }

    /// `Authorization: Bearer …` plus an `x-trace-id`, so the span is readable.
    pub(crate) fn traced(trace: Uuid) -> HeaderMap {
        let mut h = crate::handler_harness::authed();
        h.insert(
            "x-trace-id",
            HeaderValue::from_str(&trace.to_string()).expect("header"),
        );
        h
    }

    /// A state whose catalog adapters (`openai`, `together`, `groq`, `xai`, `mistral`) and the
    /// Cohere adapter all point at `base`.
    pub(crate) fn state_for(base: &str) -> AppState {
        let mut reg = crate::providers::ProviderRegistry::new().expect("registry");
        for p in ["openai", "together", "groq", "xai", "mistral"] {
            reg.set_compat_base_url_for_test(p, base.to_owned())
                .expect("compat adapter");
        }
        reg.cohere = crate::providers::CohereProvider::for_base_url(base).expect("cohere");
        crate::handler_harness::test_state(reg)
    }

    /// [`state_for`] with an entitlement cache granting the R2 secrets/PII rail to every
    /// tenant — the guardrail engine reads entitlements through ITS OWN handle, so it is
    /// rebuilt over the same cache, as `server::run` wires both in production.
    pub(crate) fn r2_state(base: &str) -> AppState {
        let mut state = state_for(base);
        let cache = Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
            move |_tenant| {
                Box::pin(async move {
                    Ok(crate::entitlement_cache::ResolvedEntitlements {
                        f_guardrail_r2: true,
                        ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
                    })
                })
                    as std::pin::Pin<
                        Box<
                            dyn std::future::Future<
                                    Output = anyhow::Result<
                                        crate::entitlement_cache::ResolvedEntitlements,
                                    >,
                                > + Send,
                        >,
                    >
            },
        )));
        state.guardrail = Arc::new(crate::guardrail::GuardrailEngine::new(
            Arc::clone(&state.audit_chain),
            None,
            Some(Arc::clone(&cache)),
            Arc::new(crate::guardrail::capability::CapabilityRegistry::new()),
        ));
        state.entitlements = Some(cache);
        state
    }

    /// A secret shaped like a real one (R2 flags it) that is not one.
    pub(crate) const SECRET: &str =
        "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// `multipart/form-data` with boundary `TLBOUNDARY7`: `(name, Some(filename) | None, data)`.
    pub(crate) fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> (String, Vec<u8>) {
        let mut b = Vec::new();
        for (name, filename, data) in parts {
            b.extend_from_slice(b"--TLBOUNDARY7\r\n");
            match filename {
                Some(f) => b.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                    )
                    .as_bytes(),
                ),
                None => b.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                ),
            }
            b.extend_from_slice(data);
            b.extend_from_slice(b"\r\n");
        }
        b.extend_from_slice(b"--TLBOUNDARY7--\r\n");
        ("multipart/form-data; boundary=TLBOUNDARY7".to_owned(), b)
    }

    pub(crate) fn headers_with(mut h: HeaderMap, name: &'static str, value: &str) -> HeaderMap {
        h.insert(name, HeaderValue::from_str(value).expect("header value"));
        h
    }

    pub(crate) async fn body_bytes(resp: axum::response::Response) -> axum::body::Bytes {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body")
    }

    pub(crate) async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&body_bytes(resp).await).expect("JSON body")
    }

    pub(crate) async fn nothing_reached(server: &wiremock::MockServer) -> bool {
        server
            .received_requests()
            .await
            .is_some_and(|r| r.is_empty())
    }
}
