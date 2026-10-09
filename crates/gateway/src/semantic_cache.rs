//! `GWY-24` — semantic response cache.
//!
//! ## The prior KILL, and what changed
//!
//! `specs/GWY-25` killed the exact-match cache on four grounds, and the sharpest
//! was *"a cached response that is not re-recorded produces a trace gap — the
//! exact failure the product exists to prevent."*
//!
//! **That is answered by PLACEMENT, not by argument.** The lookup replaces only
//! the dispatch expression in `chat_completions_handler`. Everything above it has
//! already run: auth, quota, both budget ceilings, detection, guardrails, and the
//! fail-CLOSED audit publish. `audit.rs` states the invariant — *"the audit
//! product does not serve unrecorded requests"* — and a hit is served AFTER the
//! ledger append, not instead of it. A hit is a first-class span carrying
//! `semantic_cache_hit`, the similarity, and a pointer to the trace it reused.
//! The recorder sees strictly more, not less.
//!
//! `GWY-25`'s other objection — *"making it record anyway removes most of the
//! saving"* — was false for this architecture: recording is an async NATS publish
//! off the response path, so it removes ≈0% of the saving. That spec reasoned
//! about a system whose recording was synchronous. This one's is not.
//!
//! ## Two tiers, and why the cheap one exists
//!
//! ```text
//! request ─► [exact]   blake3 of the canonical request, in-process moka
//!             │ hit ─► serve. No embedding, no network, no ClickHouse.
//!             │ miss
//!             ▼
//!            [semantic] embed → ClickHouse cosineDistance, prefiltered on
//!                       (tenant, model, params_hash), LIMIT max_scan_entries
//! ```
//!
//! The exact tier is not a second feature — it is what stops a byte-identical
//! repeat from paying for an embedding round trip. Agent traffic is full of
//! byte-identical repeats.
//!
//! ## What this costs, measured rather than assumed
//!
//! The ClickHouse scan is LINEAR and was measured on the live prod server
//! (24.12.6.70) via `system.query_log`, three runs each:
//!
//! | dims | 1,000 | 10,000 | 50,000 |
//! |---|---|---|---|
//! | 1536 | 3 ms | 16 ms | 50 ms |
//! | 512  | —    | 8 ms  | 22 ms |
//!
//! So `max_scan_entries` IS the latency ceiling, not a memory guard, and 512
//! dims is the default because the other 8 ms buys nothing at a 0.95 threshold.
//!
//! The embedding is a NETWORK call — there is no local embedding model anywhere
//! in the Rust tree (`candle`/`fastembed`/`ort` appear in no manifest). That is
//! the dominant cost and the reason a semantic hit cannot be as cheap as the
//! brief hoped.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context as _, Result};
use clickhouse::Client as ClickhouseClient;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use tracelane_shared::{ChatRequest, MessageContent, TenantId};
use uuid::Uuid;

use crate::providers::ProviderRegistry;
use crate::server::config::SemanticCacheConfig;

/// Caller control of Tracelane response reuse; provider prompt caching is separate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CacheControl {
    #[default]
    Default,
    Bypass,
    Use,
    Ttl(u32),
}

#[derive(Clone, Copy, Debug)]
pub struct CacheRefusal {
    pub status: axum::http::StatusCode,
    pub code: &'static str,
}
impl CacheRefusal {
    pub fn response(self, anthropic: bool) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        let kind = if self.status == axum::http::StatusCode::FORBIDDEN {
            "permission_error"
        } else {
            "invalid_request_error"
        };
        let error = serde_json::json!({"type":kind,"code":self.code,"message":self.code});
        let body = if anthropic {
            serde_json::json!({"type":"error","error":error})
        } else {
            serde_json::json!({"error":error})
        };
        (self.status, axum::Json(body)).into_response()
    }
}

impl CacheControl {
    pub fn parse(headers: &axum::http::HeaderMap) -> std::result::Result<Self, CacheRefusal> {
        let bad = CacheRefusal {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "invalid_cache_control",
        };
        let mut values = headers.get_all("x-tracelane-cache").iter();
        let Some(value) = values.next() else {
            return Ok(Self::Default);
        };
        if values.next().is_some() {
            return Err(bad);
        }
        let value = value.to_str().map_err(|_| bad)?.trim();
        match value {
            "bypass" => Ok(Self::Bypass),
            "use" => Ok(Self::Use),
            _ => {
                let raw = value.strip_prefix("ttl=").ok_or(bad)?;
                if raw.is_empty() || !raw.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(bad);
                }
                let hours = raw.parse::<u32>().map_err(|_| bad)?;
                if hours == 0 {
                    return Err(bad);
                }
                Ok(Self::Ttl(hours))
            }
        }
    }
    /// Resolve the caller's request header against the workspace's settings.
    ///
    /// Order of refusals (unchanged by OG-51): the plan (`403 cache_control_not_entitled`),
    /// the route (`409 cache_control_unsupported_route`), then whether the cache is on for
    /// THIS request at all (`409 response_cache_disabled`: no operator block, the workspace
    /// or the key switched it off, or — the privacy default — the workspace records no
    /// content and never opted in). A request header can narrow or bypass; it can never turn
    /// on a cache the workspace did not.
    pub fn resolve(
        self,
        entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
        cache: Option<&SemanticCache>,
        supported: bool,
        who: &crate::cache_controls::CacheCaller<'_>,
    ) -> std::result::Result<CachePolicy, CacheRefusal> {
        use crate::cache_controls as cc;
        use axum::http::StatusCode;
        if self == Self::Bypass {
            return Ok(CachePolicy {
                bypass: true,
                ..CachePolicy::default()
            });
        }
        let plan = entitlements
            .filter(|e| e.f_cache_control && e.cache_ttl_hours > 0)
            .map(|e| e.cache_ttl_hours);
        let loaded = entitlements.map(|e| &*e.cache);
        let key_cfg = who
            .key_id
            .and_then(|k| loaded.and_then(|l| l.keys.get(&k)).copied());
        let state = cc::enabled(
            cache.is_some(),
            loaded,
            key_cfg.as_ref(),
            plan.is_some(),
            who.captured,
        );
        if self == Self::Default {
            // The privacy default (and an explicit `off`): no lookup, no store, and no header —
            // the caller asked nothing, so there is nothing to answer.
            if !state.on || !supported {
                return Ok(CachePolicy {
                    bypass: !state.on,
                    quiet: true,
                    ..CachePolicy::default()
                });
            }
            return Ok(Self::workspace_policy(
                cache, loaded, plan, key_cfg, who, None,
            ));
        }
        // `use` / `ttl=`.
        let plan = plan.ok_or(CacheRefusal {
            status: StatusCode::FORBIDDEN,
            code: "cache_control_not_entitled",
        })?;
        if !supported {
            return Err(CacheRefusal {
                status: StatusCode::CONFLICT,
                code: "cache_control_unsupported_route",
            });
        }
        if !state.on {
            return Err(CacheRefusal {
                status: StatusCode::CONFLICT,
                code: "response_cache_disabled",
            });
        }
        let requested = match self {
            Self::Ttl(n) => Some(n),
            _ => None,
        };
        let mut policy = Self::workspace_policy(cache, loaded, Some(plan), key_cfg, who, requested);
        if policy.ttl_hours.is_none() {
            // `use` with no workspace TTL: the plan/operator/ceiling minimum, as before.
            let (ttl, binding) = effective_ttl(requested, None, Some(plan), cache);
            policy.ttl_hours = Some(ttl);
            policy.binding = binding;
        }
        Ok(policy)
    }

    /// The policy of a request the cache is ON for: the effective TTL (only when a request
    /// header or the workspace sets one), the namespace and the epochs folded into the hashes.
    fn workspace_policy(
        cache: Option<&SemanticCache>,
        loaded: Option<&crate::db::cache_settings::Loaded>,
        plan: Option<u32>,
        key_cfg: Option<crate::db::cache_settings::KeyCache>,
        who: &crate::cache_controls::CacheCaller<'_>,
        requested: Option<u32>,
    ) -> CachePolicy {
        use crate::cache_controls as cc;
        let ws = loaded.map(|l| l.settings).unwrap_or_default();
        let mut policy = CachePolicy::default();
        // The workspace TTL counts only while the plan grants cache control.
        if let (Some(ws_ttl), Some(_)) = (ws.ttl_hours, plan) {
            let (ttl, binding) = effective_ttl(requested, Some(ws_ttl), plan, cache);
            policy.ttl_hours = Some(ttl);
            policy.binding = binding;
        } else if let Some(n) = requested {
            let (ttl, binding) = effective_ttl(Some(n), None, plan, cache);
            policy.ttl_hours = Some(ttl);
            policy.binding = binding;
        }
        policy.semantic = ws.semantic;
        let by = cc::effective_namespace(ws.namespace_by, key_cfg.and_then(|k| k.namespace_by));
        let ns = cc::namespace(by, who);
        if ns == cc::NamespaceValue::Unavailable {
            // The namespace the workspace chose has no value for this request: never widen.
            policy.bypass = true;
            policy.quiet = true;
            return policy;
        }
        let epochs = loaded.map_or_else(Vec::new, |l| {
            l.applicable_epochs(who.project_id, who.key_id, who.model)
        });
        if let Some(fold) = cc::fold(&ns, who.namespace_header, &epochs) {
            policy.fold = Some(fold);
        }
        policy
    }
}

/// The effective TTL: the minimum of the caller's request, the workspace's own, the plan, the
/// operator and the table's ceiling — and the name of what bound it. A tie names the
/// non-request candidates that tie (`plan,operator`); the ceiling is named only when it
/// alone binds.
fn effective_ttl(
    requested: Option<u32>,
    workspace: Option<u32>,
    plan: Option<u32>,
    cache: Option<&SemanticCache>,
) -> (u32, &'static str) {
    let operator = cache.map(|c| c.config().ttl_hours());
    let ceiling = crate::cache_controls::config().ttl_ceiling_hours;
    let others = [workspace, plan, operator];
    let floor = others.iter().flatten().copied().min().unwrap_or(ceiling);
    let effective = requested.unwrap_or(u32::MAX).min(floor).min(ceiling);
    let tied = |v: Option<u32>| v == Some(effective);
    let binding = match (tied(workspace), tied(plan), tied(operator)) {
        (true, true, true) => "workspace,plan,operator",
        (true, true, false) => "workspace,plan",
        (true, false, true) => "workspace,operator",
        (true, false, false) => "workspace",
        (false, true, true) => "plan,operator",
        (false, true, false) => "plan",
        (false, false, true) => "operator",
        (false, false, false) => {
            if ceiling == effective && requested.is_none_or(|r| r > effective) {
                "ceiling"
            } else {
                "requested"
            }
        }
    };
    (effective, binding)
}

#[derive(Clone, Copy, Debug)]
pub struct CachePolicy {
    bypass: bool,
    ttl_hours: Option<u32>,
    binding: &'static str,
    /// The policy decided "no cache" by SETTINGS (the privacy default, a workspace or key
    /// `off`), not because the caller said `bypass`: the response says nothing about it.
    quiet: bool,
    /// `false` = the workspace turned the semantic (embedding) tier off.
    semantic: bool,
    /// The namespace and epochs folded into both hashes (`None` = nothing applies, so the
    /// hashed bytes are what they were before OG-51).
    fold: Option<crate::cache_controls::Fold>,
}
impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            bypass: false,
            ttl_hours: None,
            binding: "",
            quiet: false,
            semantic: true,
            fold: None,
        }
    }
}
impl CachePolicy {
    pub fn suspend(mut self) -> Self {
        self.bypass = true;
        self
    }
    /// May the semantic (embedding) tier run for this request? `false` when the workspace
    /// switched it off.
    #[must_use]
    pub fn semantic_allowed(self) -> bool {
        self.semantic
    }
    pub fn key(self, mut key: RequestKey) -> RequestKey {
        key.bypass = self.bypass;
        key.ttl_hours = self.ttl_hours;
        // Different age policies cannot share either tier's compatibility key.
        if let Some(ttl) = self.ttl_hours {
            for digest in [&mut key.exact_hash, &mut key.params_hash] {
                let mut h = blake3::Hasher::new();
                hash_field(&mut h, digest.as_bytes());
                hash_field(&mut h, &ttl.to_le_bytes());
                *digest = h.finalize().to_hex().to_string();
            }
        }
        // OG-51: a namespace / an invalidation epoch moves BOTH hashes, exactly as the
        // canary namespace does, so the semantic tier's `(tenant, model, params_hash)`
        // prefilter separates namespaces with no schema change.
        if let Some(fold) = self.fold {
            for digest in [&mut key.exact_hash, &mut key.params_hash] {
                let mut h = blake3::Hasher::new();
                hash_field(&mut h, digest.as_bytes());
                hash_field(&mut h, &fold.digest);
                *digest = h.finalize().to_hex().to_string();
            }
        }
        key
    }
    pub fn response(self, mut response: axum::response::Response) -> axum::response::Response {
        use axum::http::HeaderValue;
        if self.bypass && !self.quiet {
            response
                .headers_mut()
                .insert("x-tracelane-cache", HeaderValue::from_static("bypass"));
        }
        if let Some(ttl) = self.ttl_hours {
            response
                .headers_mut()
                .entry("x-tracelane-cache")
                .or_insert(HeaderValue::from_static("miss"));
            response.headers_mut().insert(
                "x-tracelane-cache-ttl-hours",
                HeaderValue::from_str(&ttl.to_string()).expect("integer header"),
            );
            response.headers_mut().insert(
                "x-tracelane-cache-bound",
                HeaderValue::from_static(self.binding),
            );
        }
        // Only an 8-hex prefix of a hash — never the raw namespace, id or epoch.
        if let Some(fold) = self.fold {
            for (name, tag) in [
                ("x-tracelane-cache-namespace", fold.namespace_tag),
                ("x-tracelane-cache-epoch", fold.epoch_tag),
            ] {
                if let Some(tag) = tag
                    && let Ok(v) = HeaderValue::from_bytes(&tag)
                {
                    response.headers_mut().insert(name, v);
                }
            }
        }
        response
    }
}

/// A served hit, and everything the span needs to record it honestly.
#[derive(Debug, Clone)]
pub struct CacheHit {
    created_at_ms: i64,
    /// The stored provider response, verbatim.
    pub response_json: String,
    /// `exact` or `semantic` — a byte match and a 1.000 similarity are different
    /// facts and must not render identically.
    pub tier: &'static str,
    /// `None` for an exact hit. Present, 3 dp, for a semantic one.
    pub similarity: Option<f32>,
    /// The trace whose answer is being reused. The flight-recorder link.
    pub source_trace_id: Uuid,
    /// What the ORIGINAL call cost. This is what the hit SAVED; it is not
    /// charged again.
    pub cost_saved_usd: f64,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    /// Wall-clock the lookup itself took, so the span can carry the real added
    /// latency rather than an estimate.
    pub lookup_us: u64,
}

/// The row as stored. Field order mirrors
/// `infra/dev/clickhouse/migrations/17_semantic_cache.sql`.
#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
struct CacheRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    cache_id: ::uuid::Uuid,
    model: String,
    /// `FixedString(64)` in migration 17, NOT `String`. Declaring these as
    /// `String` makes clickhouse-rs emit a varint length prefix a FixedString
    /// never carries, which desynchronises the RowBinary block and fails the
    /// INSERT outright — the B-273/B-274 class, third and fourth instances.
    ///
    /// IT WAS INVISIBLE BECAUSE THE FAILURE IS SWALLOWED BY DESIGN: `store()`
    /// logs the error at DEBUG and folds it into a degradation counter, which is
    /// the correct fail-OPEN posture for a cache (`CLAUDE.md` §10) and is also
    /// why a total write failure produced no error anyone would see.
    params_hash: crate::prompt_router::FixedHex64,
    exact_hash: crate::prompt_router::FixedHex64,
    embedding: Vec<f32>,
    embedding_model: String,
    embedding_dims: u16,
    response_json: String,
    prompt_tokens: u32,
    completion_tokens: u32,
    cost_usd: f64,
    #[serde(with = "clickhouse::serde::uuid")]
    source_trace_id: ::uuid::Uuid,
    /// `DateTime64(3)` — MILLIS. See `clickhouse_query::datetime64_millis_now`,
    /// which exists because this exact mistake shipped twice on sibling tables.
    created_at: i64,
}

/// The canonical identity of a request, split so the two tiers can use different
/// parts of it.
#[derive(Debug, Clone)]
pub struct RequestKey {
    canary_namespace: String,
    bypass: bool,
    ttl_hours: Option<u32>,
    /// blake3 of params + normalised messages. The exact tier's key.
    pub exact_hash: String,
    /// sha256-shaped hex of the NON-message parameters. An exact match on this
    /// is required before any similarity comparison: two requests whose sampling
    /// parameters differ are not interchangeable however alike their text reads.
    pub params_hash: String,
    /// The normalised message text that gets embedded.
    pub embed_text: String,
    /// rev6 N3: the embedding models this REQUEST may send `embed_text` to. `None` =
    /// the configured list (no request context — tests and tooling); `Some(list)` =
    /// only these, in the configured order; `Some(empty)` = the semantic tier is OFF
    /// for this request (no embedding call on lookup or store). Set by the chat
    /// handler through [`RequestKey::restrict_semantic_tier`]: an R2-redacted request
    /// gets an empty list, and a model the workspace blocks, the key's policy denies,
    /// or (under ZDR-required) a non-ZDR provider would serve is left out.
    semantic_models: Option<Vec<String>>,
}

impl RequestKey {
    /// rev6 N3: restrict the semantic tier to `models` (empty = off). The exact tier is
    /// unaffected — it is a hash, it sends nothing anywhere.
    pub fn restrict_semantic_tier(&mut self, models: Vec<String>) {
        self.semantic_models = Some(models);
    }

    /// rev6 N3: the models the semantic tier may embed with, given the configured list.
    fn semantic_models<'a>(&'a self, configured: &'a [String]) -> &'a [String] {
        self.semantic_models.as_deref().unwrap_or(configured)
    }
}

/// Derive the cache identity of a request.
///
/// **Call this BEFORE guardrail redaction**, and the reason is not obvious:
/// `crates/policy/src/pii.rs` builds its placeholder as
/// `{REDACT_OPEN}{category}:{idx}}}` — category plus a running index, carrying no
/// secret and no tenant material. Two DIFFERENT secrets in the same position
/// therefore redact to a BYTE-IDENTICAL string, so hashing after redaction would
/// treat two genuinely different requests as the same one and serve the wrong
/// answer.
/// One length-prefixed field into the exact-key hasher (B-476): `u64 LE` byte
/// length, then the bytes. A field can therefore never masquerade as a delimiter.
fn hash_field(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

/// A digest of the conversation's TOOL HISTORY — every message's `tool_call_id`
/// and `tool_calls` (name + arguments), length-prefixed — or `None` when no
/// message carries either (B-476). Feeds `params_hash`, so the semantic tier's
/// compatibility filter never offers an entry from a conversation whose tool
/// history differs.
fn tool_history_digest(messages: &[tracelane_shared::model::Message]) -> Option<String> {
    let any = messages
        .iter()
        .any(|m| m.tool_call_id.is_some() || m.tool_calls.as_ref().is_some_and(|t| !t.is_empty()));
    if !any {
        return None;
    }
    let mut h = blake3::Hasher::new();
    for m in messages {
        h.update(b"\x01msg");
        hash_field(
            &mut h,
            m.tool_call_id.as_deref().unwrap_or_default().as_bytes(),
        );
        hash_field(
            &mut h,
            m.tool_calls
                .as_ref()
                .map(|tc| serde_json::to_string(tc).unwrap_or_default())
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    Some(h.finalize().to_hex().to_string())
}

#[must_use]
pub fn request_key(req: &ChatRequest) -> RequestKey {
    let mut params = blake3::Hasher::new();
    params.update(req.model.as_bytes());
    params.update(&req.max_tokens.unwrap_or(0).to_le_bytes());
    params.update(&req.temperature.unwrap_or(-1.0).to_le_bytes());
    // Tools participate in the PARAMS hash rather than the text hash: the same
    // question asked with and without a tool available is a different question.
    if let Some(tools) = &req.tools {
        params.update(&(tools.len() as u32).to_le_bytes());
        for t in tools {
            params.update(serde_json::to_string(t).unwrap_or_default().as_bytes());
        }
    }
    // B-355: same reasoning as `tools` above — the same question asked with
    // `tool_choice: "required"` and with `"none"` is a different question, and
    // sharing one cache entry between them would serve an answer that ignores
    // the caller's instruction. Absent → nothing hashed, so every existing key
    // is unchanged.
    if let Some(tc) = &req.tool_choice {
        params.update(serde_json::to_string(tc).unwrap_or_default().as_bytes());
    }
    // GWY-48: `top_p` and `seed` are sampling parameters in exactly the sense
    // `RequestKey::params_hash`'s own doc comment means — "two requests whose
    // sampling parameters differ are not interchangeable however alike their
    // text reads". Landing them on `ChatRequest` WITHOUT landing them here would
    // make two requests differing only in `top_p` collide on one cache entry and
    // serve the second caller the first caller's answer. That is B-355's defect
    // reintroduced under a new field name, which is why `model.rs` says so at
    // the field and why this is the same commit.
    //
    // OBS-53's `logprobs`/`top_logprobs` are hashed for a DIFFERENT reason, and
    // it is the stronger one: they change the SHAPE OF THE RESPONSE BODY. A
    // cached answer stored for a caller who did not ask for logprobs has no
    // `logprobs` object in it, so replaying it to a caller who did would silently
    // drop a field that caller's client is parsing. Not in the spec; found
    // building it.
    //
    // Each is length-tagged and only hashed when PRESENT, so every key written
    // before this change is byte-identical after it — the cache is not flushed by
    // a deploy. The tag is what keeps a `top_p` of 0.5 from colliding with a
    // `system` prompt that happens to carry the same four bytes; the pre-existing
    // fields have no tag and are left exactly as they are (changing them WOULD
    // flush the cache, for a weakness this feature does not introduce).
    if let Some(tp) = req.top_p {
        params.update(b"top_p=");
        params.update(&tp.to_le_bytes());
    }
    if let Some(seed) = req.seed {
        params.update(b"seed=");
        params.update(&seed.to_le_bytes());
    }
    if let Some(lp) = req.logprobs {
        params.update(b"logprobs=");
        params.update(&[u8::from(lp)]);
    }
    if let Some(tlp) = req.top_logprobs {
        params.update(b"top_logprobs=");
        params.update(&[tlp]);
    }
    // OG-03: every field that CHANGES THE ANSWER is part of the key, by the same rule as
    // `top_p` above — two requests differing only in `stop`, `response_format`,
    // `reasoning_effort`, the output cap named `max_completion_tokens`, a penalty, or an
    // unmodelled `extra` field are different questions, and a shared entry would serve the
    // second caller the first caller's answer (the B-355 class again, under new names).
    //
    // Each is tagged and only hashed when PRESENT, so every key written before this change is
    // byte-identical after it. `parallel_tool_calls` is hashed because it changes which tool
    // calls come back. DELIBERATELY NOT hashed: `user` and `service_tier` (an end-user label
    // and a latency tier — neither changes the answer, and hashing `user` would stop one
    // tenant's users from ever sharing an entry) and `n` (only 1 is ever served).
    if let Some(stop) = &req.stop {
        params.update(b"stop=");
        let seqs = stop.sequences();
        params.update(&(seqs.len() as u64).to_le_bytes());
        for s in seqs {
            hash_field(&mut params, s.as_bytes());
        }
    }
    if let Some(rf) = &req.response_format {
        params.update(b"response_format=");
        let mut canon = String::new();
        crate::request_support::canonical_json(rf, &mut canon);
        hash_field(&mut params, canon.as_bytes());
    }
    if let Some(re) = &req.reasoning_effort {
        params.update(b"reasoning_effort=");
        hash_field(&mut params, re.as_bytes());
    }
    if let Some(m) = req.max_completion_tokens {
        params.update(b"max_completion_tokens=");
        params.update(&m.to_le_bytes());
    }
    if let Some(p) = req.presence_penalty {
        params.update(b"presence_penalty=");
        params.update(&p.to_le_bytes());
    }
    if let Some(p) = req.frequency_penalty {
        params.update(b"frequency_penalty=");
        params.update(&p.to_le_bytes());
    }
    if let Some(p) = req.parallel_tool_calls {
        params.update(b"parallel_tool_calls=");
        params.update(&[u8::from(p)]);
    }
    if !req.extra.is_empty() {
        params.update(b"extra=");
        // Canonical sorted JSON: key order in the body must not change the key.
        let mut canon = String::new();
        crate::request_support::canonical_json(
            &serde_json::Value::Object(req.extra.clone()),
            &mut canon,
        );
        hash_field(&mut params, canon.as_bytes());
    }
    if let Some(sys) = &req.system {
        params.update(sys.as_bytes());
    }
    // B-476 (REV-4, 2026-09-21): the TOOL HISTORY — every message's `tool_calls`
    // (function names AND arguments) and `tool_call_id` — is part of the
    // compatibility hash. Two conversations with identical text but different
    // prior tool calls are different questions; until this they shared one
    // entry on both tiers, because `embed_text` carried role + content only.
    // Length-tagged and only hashed when any message carries tool state, so a
    // request with no tool history keeps the key shape it had (the semantic tier's
    // stored `params_hash` rows stay reachable for those).
    let tool_history = tool_history_digest(&req.messages);
    if let Some(d) = &tool_history {
        params.update(b"tool_history=");
        params.update(d.as_bytes());
    }
    let params_hash = params.finalize().to_hex().to_string();

    // The text the SEMANTIC tier embeds: readable, role-prefixed — an embedding
    // model wants prose, not framing bytes. It is NOT the exact key any more.
    let mut embed_text = String::new();
    for m in &req.messages {
        embed_text.push_str(&format!("{:?}:", m.role));
        match &m.content {
            MessageContent::Text(t) => embed_text.push_str(t),
            MessageContent::Parts(parts) => {
                embed_text.push_str(&serde_json::to_string(parts).unwrap_or_default());
            }
        }
        embed_text.push('\n');
    }

    // B-476: the EXACT key hashes an UNAMBIGUOUS serialization of every message —
    // each field length-prefixed (`u64 LE` + bytes) under a per-message record
    // marker — so no delimiter can be forged from inside a field. Until this the
    // exact key hashed `embed_text`, where a single user message reading
    // `"hello\nAssistant:world"` produced the same bytes as user `"hello"` followed
    // by assistant `"world"`, and `tool_calls` / `tool_call_id` were absent. Every
    // pre-B-476 exact key changes by construction — that IS the invalidation: an
    // entry stored under an ambiguous key could be served to the wrong request, so
    // none of them is trusted; the in-memory tier restarts empty on deploy anyway
    // and the ClickHouse rows keyed on old hashes expire by TTL.
    let mut exact = blake3::Hasher::new();
    exact.update(b"tracelane.semantic-cache.exact.v2\0");
    exact.update(params_hash.as_bytes());
    for m in &req.messages {
        exact.update(b"\x01msg");
        hash_field(&mut exact, format!("{:?}", m.role).as_bytes());
        match &m.content {
            MessageContent::Text(t) => {
                hash_field(&mut exact, b"text");
                hash_field(&mut exact, t.as_bytes());
            }
            MessageContent::Parts(parts) => {
                hash_field(&mut exact, b"parts");
                hash_field(
                    &mut exact,
                    serde_json::to_string(parts).unwrap_or_default().as_bytes(),
                );
            }
        }
        hash_field(
            &mut exact,
            m.tool_call_id.as_deref().unwrap_or_default().as_bytes(),
        );
        hash_field(
            &mut exact,
            m.tool_calls
                .as_ref()
                .map(|tc| serde_json::to_string(tc).unwrap_or_default())
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    let exact_hash = exact.finalize().to_hex().to_string();

    RequestKey {
        canary_namespace: String::new(),
        bypass: false,
        ttl_hours: None,
        exact_hash,
        params_hash,
        embed_text,
        semantic_models: None,
    }
}

/// The cache.
pub struct SemanticCache {
    prompt_router: Option<Arc<crate::prompt_router::PromptRouter>>,
    /// SRE #20: the entitlement cache, so cache reads run at the tenant's OWN cap tier.
    entitlements: Option<std::sync::Arc<crate::entitlement_cache::EntitlementCache>>,
    ch: ClickhouseClient,
    providers: Arc<ProviderRegistry>,
    cfg: SemanticCacheConfig,
    /// Exact tier. Bounded and TTL'd; lost on restart, deliberately — ClickHouse
    /// holds the durable copy and a restart simply re-warms this.
    exact: moka::future::Cache<(TenantId, String), Arc<CacheHit>>,
    /// NEGATIVE cache: tenants that have no embedding-capable credential.
    ///
    /// Not an optimisation — a correctness requirement for the hot path.
    /// `embed()` walks the preference list calling `resolve_provider_key`, and
    /// for a tenant holding no key for that provider the lookup can fall through
    /// to POSTGRES. Retrying that on every cache miss would put a per-request
    /// control-plane round trip on the hot path, which `CLAUDE.md` §2 forbids
    /// outright and which is the exact shape of B-256.
    ///
    /// And it is the MAJORITY case here, not an edge: of the credentials on
    /// prod, only mistral can embed — Anthropic has no embeddings API at all.
    ///
    /// Tenants known to hold NO embedding-capable credential, so the semantic
    /// tier can be skipped without re-walking the provider list into Postgres.
    ///
    /// **THE TTL MUST EXCEED THE GAP BETWEEN REQUESTS, and the first version of
    /// this cache got that exactly backwards.** It was 300s with an exemption
    /// comment claiming "a short TTL here is correct, not the B-256 class."
    /// That was wrong, and measurably so: prod traffic arrives every **423s at
    /// p50 / 565s at p90** (measured over 278 real requests), so a 300s entry
    /// had always expired by the time the next request looked for it. The
    /// negative cache never hit, every miss called `embed()`, and `embed()`
    /// walks the preference list into `resolve_provider_key`, which can reach
    /// **Postgres on the request path** — the thing `CLAUDE.md` §2 forbids and
    /// the precise shape of B-256.
    ///
    /// Measured cost of that mistake on the dominant prod model
    /// (`claude-haiku-4-5`, MISSES only so hits cannot flatter it):
    /// **p50 gateway overhead 1.78ms → 18.45ms, ~10×.**
    ///
    /// The trade the old comment worried about — a tenant that ADDS a key
    /// waiting for semantic hits — is real but tiny beside a Postgres round
    /// trip on every request, and it is bounded: an hour, once.
    no_embedder: moka::future::Cache<TenantId, ()>,
}

/// TTL for the `no_embedder` negative cache.
///
/// **A NAMED CONST SPECIFICALLY SO `check-hot-path-cache-ttl.py` CAN SEE IT.**
/// That guard matches `const <NAME>` declarations; this value used to be an
/// inline `Duration::from_secs(300)` inside a builder chain, so the guard could
/// not have read it even if the file had been listed — and it was not listed
/// either. It shipped at 300s against a measured 423s p50 request gap, never
/// hit once, and cost ~10x on hot-path overhead. 3600s clears the measured p90
/// gap (565s) with room.
const NO_EMBEDDER_TTL_SECS: u64 = 3600;

impl SemanticCache {
    /// SRE #20: the tenant's own ADR-031 tier (`clickhouse_query::tier_for_tenant`).
    async fn tier_for(&self, tenant: &TenantId) -> crate::clickhouse_query::PlanTier {
        crate::clickhouse_query::tier_for_tenant(self.entitlements.as_ref(), tenant).await
    }

    #[must_use]
    pub fn with_entitlements(
        mut self,
        entitlements: Option<std::sync::Arc<crate::entitlement_cache::EntitlementCache>>,
    ) -> Self {
        self.entitlements = entitlements;
        self
    }

    #[must_use]
    pub fn new(
        ch: ClickhouseClient,
        providers: Arc<ProviderRegistry>,
        cfg: SemanticCacheConfig,
    ) -> Self {
        let ttl = std::time::Duration::from_secs(u64::from(cfg.ttl_hours()) * 3600);
        Self {
            prompt_router: None,
            entitlements: None,
            ch,
            providers,
            cfg,
            // hot-path-cache-ttl: exempt -- the TTL here is the CACHE'S OWN
            // retention (operator-set, default 7 days), not an auth/entitlement
            // freshness window. The B-256 class is "a TTL shorter than the gap
            // between requests"; this one is deliberately far longer than any
            // traffic gap, which is the whole point of a cache.
            exact: moka::future::Cache::builder()
                .max_capacity(50_000)
                .time_to_live(ttl)
                .build(),
            // 3600s, NOT 300s. See the field's doc: prod's p50 request gap is
            // 423s, so the old 300s TTL guaranteed the entry was gone before the
            // next request could use it. A negative cache that never hits is not
            // a cache, it is a per-request Postgres call wearing one's coat.
            no_embedder: moka::future::Cache::builder()
                .max_capacity(10_000)
                .time_to_live(std::time::Duration::from_secs(NO_EMBEDDER_TTL_SECS))
                .build(),
        }
    }

    pub fn with_prompt_router(mut self, router: Arc<crate::prompt_router::PromptRouter>) -> Self {
        self.prompt_router = Some(router);
        self
    }
    pub fn bind_key(
        &self,
        tenant: &TenantId,
        mut key: RequestKey,
        route_namespace: Option<&str>,
    ) -> RequestKey {
        let context = self
            .prompt_router
            .as_ref()
            .map(|r| r.canary_cache_context(tenant))
            .unwrap_or_default();
        key.canary_namespace = context.namespace;
        key.bypass |= context.suspended;
        if !key.canary_namespace.is_empty() || route_namespace.is_some() {
            for hash in [&mut key.exact_hash, &mut key.params_hash] {
                let mut h = blake3::Hasher::new();
                hash_field(&mut h, hash.as_bytes());
                hash_field(&mut h, key.canary_namespace.as_bytes());
                if let Some(namespace) = route_namespace {
                    hash_field(&mut h, namespace.as_bytes());
                }
                *hash = h.finalize().to_hex().to_string();
            }
        }
        key
    }
    fn reusable(&self, tenant: &TenantId, key: &RequestKey) -> bool {
        let context = self
            .prompt_router
            .as_ref()
            .map(|r| r.canary_cache_context(tenant))
            .unwrap_or_default();
        !key.bypass && !context.suspended && key.canary_namespace == context.namespace
    }

    pub fn config(&self) -> &SemanticCacheConfig {
        &self.cfg
    }
}

impl SemanticCache {
    /// Look for a servable answer.
    ///
    /// **Returns `None` for every failure, never an error.** A cache is a
    /// fault-tolerance path, so it fails OPEN (`CLAUDE.md` §10): an unreachable
    /// embedder or a ClickHouse blip must degrade to a normal provider call, not
    /// turn a cacheable request into a 500. Every such degradation is counted
    /// through `degradation.rs` so a persistently broken embedder is a COUNTER
    /// rather than a log line per request (`.claude/rules/logging.md`).
    pub async fn lookup(
        &self,
        tenant_id: &TenantId,
        model: &str,
        key: &RequestKey,
    ) -> Option<CacheHit> {
        if !self.reusable(tenant_id, key) {
            return None;
        }
        let cutoff_ms = crate::clickhouse_query::datetime64_millis_now()
            - i64::from(
                key.ttl_hours
                    .unwrap_or(self.cfg.ttl_hours())
                    .min(crate::cache_controls::config().ttl_ceiling_hours),
            ) * 3_600_000;
        let started = Instant::now();

        // ── Tier 1: exact. No network, no embedding, no ClickHouse. ──────────
        if let Some(hit) = self
            .exact
            .get(&(tenant_id.clone(), key.exact_hash.clone()))
            .await
            && hit.created_at_ms >= cutoff_ms
            && self.reusable(tenant_id, key)
        {
            let mut h = (*hit).clone();
            h.lookup_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            return Some(h);
        }

        // ── Tier 2: semantic. Pays for an embedding. ─────────────────────────
        //
        // Skip entirely for a tenant already known to have no embedding-capable
        // credential — see `no_embedder`. Without this, every miss for an
        // Anthropic-only workspace re-walks the provider list and can reach
        // Postgres, on the hot path, forever.
        if self.no_embedder.get(tenant_id).await.is_some() {
            return None;
        }
        // rev6 N3: an R2-redacted request, or one whose policy admits no embedding model,
        // sends its text to NO embedding provider.
        if key.semantic_models(self.cfg.embedding_models()).is_empty() {
            return None;
        }
        let embedding = match self.embed(tenant_id, key).await {
            Ok(v) => v,
            Err(e) => {
                // B-347: no credential is configuration, not a degradation.
                if !embed_failure_is_configuration(&self.no_embedder, tenant_id).await {
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::SemanticCacheUnavailable,
                    );
                }
                tracing::debug!(error = %format!("{e:#}"), "semantic cache: embedding unavailable");
                return None;
            }
        };

        let threshold = self.cfg.default_threshold();
        // cosineDistance is 1 - similarity, so the threshold inverts.
        let max_distance = f64::from(1.0 - threshold);

        #[derive(Deserialize, clickhouse::Row)]
        struct Candidate {
            response_json: String,
            #[serde(with = "clickhouse::serde::uuid")]
            source_trace_id: ::uuid::Uuid,
            cost_usd: f64,
            prompt_tokens: u32,
            completion_tokens: u32,
            distance: f64,
        }

        // ADR-031 caps at the TIGHTEST tier: a cache lookup sits on the hot path
        // and must never out-consume the interactive queries of the same
        // workspace. The `LIMIT` is applied to the SCAN, so the cap is real.
        let sql = crate::clickhouse_query::TenantQuery::new(
            "SELECT response_json, source_trace_id, cost_usd, prompt_tokens, \
                    completion_tokens, toFloat64(cosineDistance(embedding, ?)) AS distance \
             FROM semantic_cache \
             WHERE tenant_id = ? AND model = ? AND params_hash = ? \
               AND embedding_dims = ? AND created_at >= fromUnixTimestamp64Milli(?) \
             ORDER BY created_at DESC \
             LIMIT ?",
            self.tier_for(tenant_id).await,
        )
        .sql_with_settings();

        let rows = self
            .ch
            .query(&sql)
            .bind(embedding.as_slice())
            .bind(tenant_id.to_string())
            .bind(model)
            .bind(key.params_hash.as_str())
            .bind(u16::try_from(embedding.len()).unwrap_or(u16::MAX))
            .bind(cutoff_ms)
            .bind(self.cfg.max_scan_entries())
            .fetch_all::<Candidate>()
            .await;

        let rows = match rows {
            Ok(r) => r,
            Err(e) => {
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::SemanticCacheUnavailable,
                );
                tracing::debug!(error = %format!("{e:#}"), "semantic cache: scan unavailable");
                return None;
            }
        };

        // The scan is ordered by RECENCY (that is what the LIMIT bounds); the
        // best MATCH is then chosen in Rust. Ordering by distance in SQL would
        // have to sort the whole partition before the limit could apply, which
        // is the opposite of a bounded scan.
        let best = rows
            .into_iter()
            .filter(|c| c.distance <= max_distance)
            .min_by(|a, b| a.distance.total_cmp(&b.distance))?;

        #[allow(clippy::cast_possible_truncation)]
        let similarity = (1.0 - best.distance) as f32;
        if !self.reusable(tenant_id, key) {
            return None;
        }
        Some(CacheHit {
            created_at_ms: cutoff_ms,
            response_json: best.response_json,
            tier: "semantic",
            similarity: Some(similarity),
            source_trace_id: best.source_trace_id,
            cost_saved_usd: best.cost_usd,
            prompt_tokens: best.prompt_tokens,
            completion_tokens: best.completion_tokens,
            lookup_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        })
    }

    /// Embed one string through the tenant's OWN provider credential.
    ///
    /// Tries `embedding_models` in order and takes the first the tenant can
    /// actually use. That ordering exists because of a hard prod fact: the six
    /// NATIVE adapters (Anthropic, Google, Vertex, Bedrock, Azure, Cohere) expose
    /// no OpenAI-shaped embeddings endpoint, and **Anthropic has no embeddings
    /// API at all** — so on prod today half the BYOK tenants can only embed via a
    /// second provider, and a single hardcoded model would exclude them silently.
    ///
    /// rev6 N3: only the models `key` admits ([`RequestKey::restrict_semantic_tier`]).
    async fn embed(&self, tenant_id: &TenantId, key: &RequestKey) -> Result<Vec<f32>> {
        let text = key.embed_text.as_str();
        let configured = self.cfg.embedding_models();
        let models = key.semantic_models(configured);
        // The negative cache records a TENANT fact ("holds no embedding credential"). A
        // request whose policy narrowed the list proves nothing about the models it
        // could not try, so only a walk over the whole configured list may record it.
        let full_walk = models.len() == configured.len();
        let mut last_err: Option<anyhow::Error> = None;
        for model in models {
            let Some(provider_id) = ProviderRegistry::provider_id_for_model(model) else {
                continue;
            };
            let Some(adapter) = self.providers.openai_compatible(provider_id) else {
                // A native adapter cannot serve this shape. Not an error — try
                // the next model in the preference list.
                continue;
            };
            let env_var = ProviderRegistry::env_var_for_provider_id(provider_id);
            let key =
                match crate::server::resolve_provider_key(tenant_id, provider_id, env_var).await {
                    crate::server::ProviderKey::Found(k) => k,
                    // No credential for THIS provider — try the next model.
                    crate::server::ProviderKey::KmsUnavailable => anyhow::bail!("kms_unavailable"),
                    crate::server::ProviderKey::KmsDenied => anyhow::bail!("kms_access_denied"),
                    crate::server::ProviderKey::NotConfigured
                    | crate::server::ProviderKey::Unusable
                    | crate::server::ProviderKey::LookupFailed => continue,
                };
            match adapter
                .embeddings(
                    &crate::providers::EmbeddingsRequest {
                        model: model.clone(),
                        input: serde_json::Value::String(text.to_owned()),
                        encoding_format: None,
                        dimensions: Some(self.cfg.embedding_dimensions()),
                        user: None,
                    },
                    key.expose_secret(),
                    tenant_id,
                )
                .await
            {
                Ok(resp) => {
                    if let Some(d) = resp.data.into_iter().next() {
                        return Ok(d.embedding);
                    }
                    last_err = Some(anyhow::anyhow!("{model}: empty embedding response"));
                }
                // B-454 (2026-09-19): the provider REJECTED the tenant's key (401/403).
                // That is the same fact as "no usable credential for this provider" —
                // a stable property of the tenant's configuration — so it is skipped
                // like a missing key, never remembered as a fault. Found on prod: one
                // tenant's stale Mistral key noted `SemanticCacheUnavailable` twice per
                // non-streaming request and re-tried the 401 on every one.
                Err(e) if credential_rejected(&e) => {
                    tracing::debug!(model = %model, "semantic cache: embedding credential rejected by the provider — treated as not configured");
                }
                Err(e) => last_err = Some(e),
            }
        }
        // NO CREDENTIAL AT ALL — absent, or rejected by its provider (B-454) — is
        // different from "the embedder errored", and only the first is worth
        // remembering. `last_err` is `None` exactly when every model was skipped for
        // lack of a usable key — a stable property of this tenant's configuration,
        // not a transient fault — so that is the case that populates the negative
        // cache. A provider OUTAGE must keep retrying, because it will come back.
        if last_err.is_none() && full_walk {
            self.no_embedder.insert(tenant_id.clone(), ()).await;
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!(
                "no configured embedding model is usable by this tenant — none of {:?} \
                 routes to a provider it holds an OpenAI-compatible key for",
                self.cfg.embedding_models()
            )
        }))
    }
}

/// B-347 (2026-09-05). `embed()` fails for two reasons that must NOT be counted the
/// B-454: is this embedding failure the provider refusing the tenant's credential?
/// Reuses [`crate::providers::ProviderHttpError::is_auth_rejection`] — the ONE
/// classifier that already knows 401, 403 AND Google's `400 API_KEY_INVALID` — so
/// the chat path and the cache agree on what "your key is dead" looks like. A
/// rejected key is the customer's configuration, exactly as "no key" is, and NOT a
/// cache fault; any other status (429, 5xx, a transport error) stays a fault that
/// keeps retrying.
pub(crate) fn credential_rejected(e: &anyhow::Error) -> bool {
    e.downcast_ref::<crate::providers::ProviderHttpError>()
        .is_some_and(crate::providers::ProviderHttpError::is_auth_rejection)
}

/// same way: a tenant with NO embedding-capable credential (a stable fact of its
/// configuration — prod is 94% Anthropic, which has no embeddings API) and an
/// embedder that actually ERRORED (a fault). `embed()` records the first in the
/// negative cache before returning, so "the tenant is in `no_embedder`" is exactly
/// "this was configuration". Counting configuration as `SemanticCacheUnavailable`
/// kept `degraded_open = 1` on prod for every container's whole life — one note at
/// the first miss after boot — and the watchdog signature carried `degraded=1`
/// from 2026-09-04 on, which is the shape that teaches a reader to ignore the
/// channel. Only a fault is a degradation.
pub(crate) async fn embed_failure_is_configuration(
    no_embedder: &moka::future::Cache<TenantId, ()>,
    tenant_id: &TenantId,
) -> bool {
    no_embedder.get(tenant_id).await.is_some()
}

/// B-359 (2026-09-07). Whether a buffered completion may enter the cache, by its
/// OpenAI-wire `finish_reason`.
///
/// Only `"stop"` qualifies. `"length"` is a truncated answer — an artefact of the
/// first caller's `max_tokens` that a later caller with a different limit would
/// receive as if complete. `"tool_calls"` is a side-effecting instruction whose
/// arguments were derived from the FIRST prompt's text: the semantic tier would
/// serve `get_weather(city="Paris")` to "weather in Berlin", which is similar
/// enough to hit. `"content_filter"` never reaches the store (the guardrail
/// branches return before it). Anything unrecognised is refused — fail-closed,
/// because a cache that guesses at an uninterpretable stop reason is worse than
/// a miss (§10: this is the correctness side of the cache, not its
/// fault-tolerance side).
#[must_use]
pub fn is_cacheable_finish_reason(finish_reason: &str) -> bool {
    finish_reason == "stop"
}

impl SemanticCache {
    /// Record an answer for reuse. Fire-and-forget: a store failure must never
    /// affect the response the customer already received.
    ///
    /// # What is deliberately NOT stored
    ///
    /// - **Streaming responses.** `provider_stream_to_sse` has no text
    ///   accumulator at all — each `GuardStep::Emit` is serialised and the
    ///   `String` dropped — so there is nothing to store without changing the
    ///   enforce-before-yield guard seam. Replaying a buffered body as SSE would
    ///   also fabricate timing the recorder never saw.
    /// - **Tool calls and truncated answers.** A `tool_calls` response is a
    ///   side-effecting instruction; serving a remembered one is a replay, not
    ///   a saving. A `length`-truncated answer is an artefact of the FIRST
    ///   caller's `max_tokens`, not an answer. Only `finish_reason == "stop"`
    ///   is stored — enforced by [`is_cacheable_finish_reason`] at the store
    ///   call site (B-359, 2026-09-07; until then this sentence was true only
    ///   because the reason was a hardcoded literal, see B-354).
    /// - **Over-size bodies**, so one pathological response cannot dominate the
    ///   scan every subsequent lookup pays for.
    #[allow(clippy::too_many_arguments)]
    pub async fn store(
        &self,
        tenant_id: &TenantId,
        model: &str,
        key: &RequestKey,
        response_json: &str,
        prompt_tokens: u32,
        completion_tokens: u32,
        cost_usd: f64,
        trace_id: Uuid,
    ) {
        const MAX_RESPONSE_BYTES: usize = 256 * 1024;
        if !self.reusable(tenant_id, key) || response_json.len() > MAX_RESPONSE_BYTES {
            return;
        }

        // WARM THE EXACT TIER FIRST, BEFORE ANY EMBEDDING.
        //
        // The order is the whole difference between this feature working for one
        // prod tenant and working for three. The exact tier needs NO embedding —
        // it is a hash of the request the caller already sent — so making it wait
        // behind `embed()` means a tenant with no embedding-capable credential
        // gets NOTHING, not even the free tier.
        //
        // That is the majority case here, not an edge: prod holds anthropic(3),
        // mistral(2) and vertex(1), and of those only mistral exposes an
        // OpenAI-shaped embeddings endpoint — Anthropic has no embeddings API at
        // all. Embedding first would have silently excluded every Anthropic-only
        // workspace from a cache that costs them nothing to use.
        let hit = CacheHit {
            created_at_ms: crate::clickhouse_query::datetime64_millis_now(),
            response_json: response_json.to_owned(),
            tier: "exact",
            similarity: None,
            source_trace_id: trace_id,
            cost_saved_usd: cost_usd,
            prompt_tokens,
            completion_tokens,
            lookup_us: 0,
        };
        self.exact
            .insert((tenant_id.clone(), key.exact_hash.clone()), Arc::new(hit))
            .await;

        // THE SAME `no_embedder` GUARD AS `lookup()`. It was missing here, and
        // that asymmetry is a bug on its own: `lookup()` skipped the embedding
        // for a credential-less tenant while `store()` attempted it on every
        // single miss, so the guard covered half the path it was written for.
        // `store()` is spawned rather than awaited, so this did not block the
        // response directly — but on a 4-vCPU box it is still a Postgres round
        // trip per miss competing with the request that spawned it.
        if self.no_embedder.get(tenant_id).await.is_some() {
            return;
        }
        // rev6 N3: the same per-request gate as `lookup()` — and no durable row either,
        // so an R2-redacted request's answer (which may carry the caller's re-inserted
        // originals) never reaches ClickHouse.
        if key.semantic_models(self.cfg.embedding_models()).is_empty() {
            return;
        }

        // The DURABLE half needs a vector, so it needs a credential. Failing here
        // costs the semantic tier and the cross-restart copy; the exact tier
        // above is already live either way.
        let embedding = match self.embed(tenant_id, key).await {
            Ok(v) => v,
            Err(_) => {
                // B-347: no credential is configuration, not a degradation.
                if !embed_failure_is_configuration(&self.no_embedder, tenant_id).await {
                    tracelane_shared::degradation::note(
                        tracelane_shared::degradation::Degradation::SemanticCacheUnavailable,
                    );
                }
                return;
            }
        };

        let row = CacheRow {
            tenant_id: tenant_id.to_string(),
            cache_id: Uuid::new_v4(),
            model: model.to_owned(),
            // UNREACHABLE BY CONSTRUCTION — both hashes are produced by
            // `RequestKey::derive` as 64-char hex (blake3's `to_hex`, and a
            // sha256-shaped digest). `None` would mean the deriver changed
            // length, and storing a padded or truncated key is worse than not
            // storing: it would never match on lookup while still occupying a
            // row. Skipping is the fail-OPEN direction a cache already takes.
            params_hash: match crate::prompt_router::FixedHex64::from_hex_str(&key.params_hash) {
                Some(h) => h,
                None => return,
            },
            exact_hash: match crate::prompt_router::FixedHex64::from_hex_str(&key.exact_hash) {
                Some(h) => h,
                None => return,
            },
            embedding_dims: u16::try_from(embedding.len()).unwrap_or(u16::MAX),
            embedding,
            embedding_model: self
                .cfg
                .embedding_models()
                .first()
                .cloned()
                .unwrap_or_default(),
            response_json: response_json.to_owned(),
            prompt_tokens,
            completion_tokens,
            cost_usd,
            source_trace_id: trace_id,
            created_at: crate::clickhouse_query::datetime64_millis_now(),
        };

        if let Err(e) = self.insert_row(&row).await {
            tracing::debug!(error = %format!("{e:#}"), "semantic cache: store failed");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::SemanticCacheUnavailable,
            );
        }
    }

    async fn insert_row(&self, row: &CacheRow) -> Result<()> {
        let mut insert = self
            .ch
            .insert("semantic_cache")
            .context("clickhouse semantic_cache insert init")?;
        insert
            .write(row)
            .await
            .context("clickhouse semantic_cache insert write")?;
        insert
            .end()
            .await
            .context("clickhouse semantic_cache insert end")
    }
}

// ── THE INSERT THAT COULD NEVER HAVE SUCCEEDED ───────────────────────────────
//
// Founder ruling R97's sweep, 2026-08-23. `CacheRow` declared `params_hash` and
// `exact_hash` as `String` against `FixedString(64)` columns, so
// `insert_row` desynchronised the RowBinary block on its first field and the
// INSERT could not complete — ever, for any input.
//
// WHY NOBODY SAW IT. `store()` swallows the error at `tracing::debug!` and folds
// it into a degradation counter. That is the CORRECT fail-open posture for a
// cache (`CLAUDE.md` §10 — a cache write failing must never fail a request), and
// it is also the reason a 100% write failure produced nothing anyone would read.
// `semantic_cache` has 0 rows on prod, and that has been attributed to prod being
// 94% Anthropic with no embeddings API. BOTH are true, and only the second was
// written down: the insert is ALSO structurally impossible.
//
// The exact tier is unaffected and its measured 186x stands — it hits an
// in-memory map (`store()`'s own comment says the exact tier needs no embedding),
// never this table.
#[cfg(test)]
mod clickhouse_roundtrip {
    use super::*;

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn a_cache_row_reaches_a_real_clickhouse() {
        let url = std::env::var("CLICKHOUSE_TEST_URL")
            .expect("CLICKHOUSE_TEST_URL not set — this test cannot run, which is not a pass");
        clickhouse::Client::default()
            .with_url(url.clone())
            .query("CREATE DATABASE IF NOT EXISTS tracelane")
            .execute()
            .await
            .expect("create database");
        let ch = clickhouse::Client::default()
            .with_url(url)
            .with_database("tracelane");
        let sql = include_str!("../../../infra/dev/clickhouse/migrations/17_semantic_cache.sql");
        for stmt in crate::clickhouse_query::split_migration_statements(sql) {
            ch.query(&stmt).execute().await.expect("migration 17 stmt");
        }

        let tenant = ::uuid::Uuid::new_v4().to_string();
        let row = CacheRow {
            tenant_id: tenant.clone(),
            cache_id: ::uuid::Uuid::new_v4(),
            model: "claude-haiku-4-5".into(),
            params_hash: crate::prompt_router::FixedHex64::from_hex_str(&"a".repeat(64)).unwrap(),
            exact_hash: crate::prompt_router::FixedHex64::from_hex_str(&"b".repeat(64)).unwrap(),
            embedding: vec![0.1, 0.2, 0.3],
            embedding_model: "text-embedding-3-small".into(),
            embedding_dims: 3,
            response_json: "{}".into(),
            prompt_tokens: 1,
            completion_tokens: 1,
            cost_usd: 0.0,
            source_trace_id: ::uuid::Uuid::new_v4(),
            created_at: crate::clickhouse_query::datetime64_millis_now(),
        };

        // THE ASSERTION IS THAT THE INSERT COMPLETES. With `String` hashes this
        // is where it failed, every time, for every input.
        let mut insert = ch.insert("semantic_cache").expect("insert init");
        insert
            .write(&row)
            .await
            .expect("semantic_cache write must not desynchronise the RowBinary stream");
        insert
            .end()
            .await
            .expect("semantic_cache insert must complete (B-274 class)");

        #[derive(serde::Deserialize, clickhouse::Row)]
        struct N {
            n: u64,
        }
        let n = ch
            .query("SELECT count() AS n FROM semantic_cache WHERE tenant_id = ?")
            .bind(&tenant)
            .fetch_one::<N>()
            .await
            .expect("count");
        assert_eq!(
            n.n, 1,
            "the row did not land — a swallowed insert error is still a lost row"
        );
    }
}

#[cfg(test)]
mod b454_tests {
    use super::credential_rejected;

    fn http(status: u16, reason: Option<&str>) -> anyhow::Error {
        crate::providers::ProviderHttpError {
            provider: "mistral",
            status,
            reason: reason.map(str::to_owned),
            message: None,
            retry_after: None,
        }
        .into()
    }

    /// B-454: a rejected credential is configuration (negative-cached, not counted);
    /// everything else stays a fault that retries. Both directions pinned.
    #[test]
    fn a_401_or_403_is_a_rejected_credential_and_nothing_else_is() {
        assert!(credential_rejected(&http(401, None)));
        assert!(credential_rejected(&http(403, None)));
        assert!(
            credential_rejected(&http(400, Some("API_KEY_INVALID"))),
            "Google's shape"
        );
        assert!(
            !credential_rejected(&http(400, None)),
            "a bare 400 is ambiguous — a fault"
        );
        assert!(!credential_rejected(&http(429, None)));
        assert!(!credential_rejected(&http(500, None)));
        assert!(!credential_rejected(&anyhow::anyhow!("connection reset")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-359. Only a complete text answer is remembered; a truncated one, a
    /// tool call, a filtered one and an unknown reason are all refused.
    #[test]
    fn only_a_stop_finish_reason_is_cacheable() {
        assert!(is_cacheable_finish_reason("stop"));
        for r in [
            "length",
            "tool_calls",
            "content_filter",
            "",
            "STOP",
            "unknown",
        ] {
            assert!(!is_cacheable_finish_reason(r), "`{r}` must not be cached");
        }
    }
    use tracelane_shared::{Message, Role};

    fn req(model: &str, text: &str, temp: Option<f32>) -> ChatRequest {
        ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: model.into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text(text.into()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            tool_choice: None,
            max_tokens: None,
            temperature: temp,
            stream: None,
            system: None,
            metadata: None,
            ..Default::default()
        }
    }

    /// **B-476 (REV-4) — the delimiter ambiguity.** One user message whose text is
    /// `"hello\nAssistant:world"` used to produce the same exact-key bytes as user
    /// `"hello"` followed by assistant `"world"`. Length-prefixed fields cannot be
    /// forged from inside a field.
    #[test]
    fn b476_a_message_containing_a_role_prefix_does_not_collide_with_two_messages() {
        let one = req("m", "hello\nAssistant:world", None);
        let mut two = req("m", "hello", None);
        two.messages.push(Message {
            role: Role::Assistant,
            content: MessageContent::Text("world".into()),
            tool_call_id: None,
            tool_calls: None,
        });
        // The embedded text is identical by construction (that IS the ambiguity)…
        assert_eq!(request_key(&one).embed_text, request_key(&two).embed_text);
        // …and the exact keys are not.
        assert_ne!(request_key(&one).exact_hash, request_key(&two).exact_hash);
    }

    /// **B-476 — tool history is identity.** Identical text with different prior
    /// tool-call ARGUMENTS (or ids) is a different conversation: different exact
    /// keys AND different compatibility (`params_hash`), so neither tier can serve
    /// one to the other. Requests with no tool history keep the params_hash they had.
    #[test]
    fn b476_tool_call_history_is_part_of_both_keys() {
        use tracelane_shared::model::ToolCall;
        let mk = |args: serde_json::Value, id: &str| {
            let mut r = req("m", "look it up", None);
            r.messages.push(Message {
                role: Role::Assistant,
                content: MessageContent::Text(String::new()),
                tool_call_id: None,
                tool_calls: Some(vec![ToolCall {
                    id: id.into(),
                    name: "search".into(),
                    input: args,
                }]),
            });
            r.messages.push(Message {
                role: Role::Tool,
                content: MessageContent::Text("result".into()),
                tool_call_id: Some(id.into()),
                tool_calls: None,
            });
            r
        };
        let a = request_key(&mk(serde_json::json!({"q": "cats"}), "c1"));
        let b = request_key(&mk(serde_json::json!({"q": "dogs"}), "c1"));
        assert_eq!(
            a.embed_text, b.embed_text,
            "the TEXT is identical — that is the finding"
        );
        assert_ne!(
            a.exact_hash, b.exact_hash,
            "different arguments ⇒ different exact key"
        );
        assert_ne!(
            a.params_hash, b.params_hash,
            "different arguments ⇒ not semantically compatible either"
        );
        let c = request_key(&mk(serde_json::json!({"q": "cats"}), "c2"));
        assert_ne!(
            a.exact_hash, c.exact_hash,
            "a different tool_call_id is a different history"
        );
        // No tool history: the compatibility hash is untouched by this change.
        let plain = request_key(&req("m", "look it up", None));
        let mut plain_h = blake3::Hasher::new();
        plain_h.update(b"m");
        plain_h.update(&0u32.to_le_bytes());
        plain_h.update(&(-1.0f32).to_le_bytes());
        assert_eq!(plain.params_hash, plain_h.finalize().to_hex().to_string());
    }

    /// **B-476 — the invalidation is by construction.** The exact key of a fixture
    /// request under the pre-B-476 scheme (params_hash + embed_text) is NOT the key
    /// the code computes now, so no entry written before this change can be served.
    #[test]
    fn b476_every_pre_change_exact_key_is_unreachable() {
        let r = req("m", "hello", None);
        let k = request_key(&r);
        let mut old = blake3::Hasher::new();
        old.update(k.params_hash.as_bytes());
        old.update(k.embed_text.as_bytes());
        assert_ne!(k.exact_hash, old.finalize().to_hex().to_string());
    }

    #[test]
    fn identical_requests_share_an_exact_hash() {
        let a = request_key(&req("m", "hello", None));
        let b = request_key(&req("m", "hello", None));
        assert_eq!(a.exact_hash, b.exact_hash);
        assert_eq!(a.params_hash, b.params_hash);
    }

    /// Different text ⇒ different exact hash, SAME params hash. The split is the
    /// whole design: params must match exactly, text is what similarity is for.
    #[test]
    fn different_text_keeps_the_params_hash_but_changes_the_exact_hash() {
        let a = request_key(&req("m", "hello", None));
        let b = request_key(&req("m", "goodbye", None));
        assert_ne!(a.exact_hash, b.exact_hash);
        assert_eq!(a.params_hash, b.params_hash);
    }

    /// SAMPLING PARAMETERS ARE NOT NEGOTIABLE. Identical text at a different
    /// temperature is a different question, and no similarity score may bridge
    /// it — which is why `params_hash` is an equality prefilter in SQL rather
    /// than another dimension of the distance.
    #[test]
    fn a_different_temperature_changes_the_params_hash() {
        let a = request_key(&req("m", "hello", Some(0.0)));
        let b = request_key(&req("m", "hello", Some(0.9)));
        assert_ne!(
            a.params_hash, b.params_hash,
            "temperature must partition the cache, not be smoothed over by similarity"
        );
    }

    /// **GWY-48 — THE CACHE-POISONING PROOF.** Two requests differing only in
    /// `top_p` must NOT share a cache entry. Without the `top_p` arm in
    /// `request_key` this test fails, and the failure mode in production is that
    /// the second caller is served the first caller's answer — the exact defect
    /// B-355 already fixed once for `tool_choice`.
    #[test]
    fn params_hash_changes_when_only_top_p_changes() {
        let mut a = req("m", "hello", Some(0.5));
        let mut b = req("m", "hello", Some(0.5));
        a.top_p = Some(0.1);
        b.top_p = Some(0.9);
        assert_ne!(
            request_key(&a).params_hash,
            request_key(&b).params_hash,
            "top_p must partition the cache"
        );
    }

    /// Same class: a `seed` is a request for a DIFFERENT sampling trajectory, so
    /// two seeds are two questions.
    #[test]
    fn params_hash_changes_when_only_seed_changes() {
        let mut a = req("m", "hello", None);
        let mut b = req("m", "hello", None);
        a.seed = Some(1);
        b.seed = Some(2);
        assert_ne!(request_key(&a).params_hash, request_key(&b).params_hash);
    }

    /// **OBS-53, and NOT in the spec — found while building.** `logprobs` changes
    /// the SHAPE OF THE RESPONSE BODY. A stored answer from a caller who did not
    /// ask for logprobs carries no `logprobs` object, so replaying it to a caller
    /// who did would silently drop a field that caller's client is parsing.
    #[test]
    fn params_hash_changes_when_only_logprobs_changes() {
        let mut a = req("m", "hello", None);
        let mut b = req("m", "hello", None);
        a.logprobs = Some(true);
        b.logprobs = Some(false);
        assert_ne!(request_key(&a).params_hash, request_key(&b).params_hash);

        let mut c = req("m", "hello", None);
        let mut d = req("m", "hello", None);
        c.logprobs = Some(true);
        c.top_logprobs = Some(3);
        d.logprobs = Some(true);
        d.top_logprobs = Some(5);
        assert_ne!(request_key(&c).params_hash, request_key(&d).params_hash);
    }

    /// **THE CACHE IS NOT FLUSHED BY THIS DEPLOY.** Each new field is hashed only
    /// when PRESENT, so a request that sends none of them produces the same
    /// `params_hash` it did before GWY-48 — which is why the four arms are
    /// `if let Some(..)` rather than `unwrap_or(default)` like `max_tokens`
    /// above. Pinned against a literal so a later "tidy-up" that makes them
    /// unconditional fails here rather than silently discarding every warm entry.
    #[test]
    fn a_request_sending_none_of_the_new_fields_keeps_its_pre_gwy48_params_hash() {
        let mut with_fields = req("m", "hello", Some(0.5));
        with_fields.top_p = None;
        with_fields.seed = None;
        with_fields.logprobs = None;
        with_fields.top_logprobs = None;
        assert_eq!(
            request_key(&req("m", "hello", Some(0.5))).params_hash,
            request_key(&with_fields).params_hash
        );
        // The literal: blake3 over model ‖ max_tokens(0) ‖ temperature(0.5), the
        // pre-GWY-48 input for this request. If this changes, existing cache
        // entries were orphaned.
        let mut h = blake3::Hasher::new();
        h.update(b"m");
        h.update(&0u32.to_le_bytes());
        h.update(&0.5f32.to_le_bytes());
        assert_eq!(
            request_key(&req("m", "hello", Some(0.5))).params_hash,
            h.finalize().to_hex().to_string(),
            "a warm cache entry written before GWY-48 must still be reachable"
        );
    }

    /// A different MODEL must never share a cache entry, even for byte-identical
    /// text — the answers are not interchangeable.
    #[test]
    fn a_different_model_changes_the_params_hash() {
        let a = request_key(&req("model-a", "hello", None));
        let b = request_key(&req("model-b", "hello", None));
        assert_ne!(a.params_hash, b.params_hash);
    }

    /// The embedded text carries the ROLE, so a user message and an assistant
    /// message with the same words are not the same input.
    #[test]
    fn embed_text_distinguishes_roles() {
        let mut r = req("m", "hello", None);
        let user_text = request_key(&r).embed_text;
        r.messages[0].role = Role::Assistant;
        assert_ne!(user_text, request_key(&r).embed_text);
    }

    /// B-347: a tenant remembered in the negative cache (no embedding-capable
    /// credential) is CONFIGURATION — the caller must not note a degradation;
    /// a tenant absent from it errored for real and must.
    #[tokio::test]
    async fn b347_no_credential_is_configuration_not_a_degradation() {
        let cache: moka::future::Cache<TenantId, ()> = moka::future::Cache::builder().build();
        let configured_out = TenantId::from_jwt_claim(
            uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("uuid"),
        );
        let faulted = TenantId::from_jwt_claim(
            uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("uuid"),
        );
        cache.insert(configured_out.clone(), ()).await;
        assert!(
            embed_failure_is_configuration(&cache, &configured_out).await,
            "a tenant in the negative cache failed for lack of a credential — no degradation"
        );
        assert!(
            !embed_failure_is_configuration(&cache, &faulted).await,
            "a tenant NOT in the negative cache errored for real — that IS a degradation"
        );
    }
}
#[cfg(all(test, debug_assertions))]
mod request_policy_tests {
    use super::*;
    use crate::cache_controls::CacheCaller;
    use crate::entitlement_cache::ResolvedEntitlements;

    /// A caller whose workspace records both prompt and response text — the privacy default
    /// lets the cache serve it (OG-51).
    fn captured() -> CacheCaller<'static> {
        CacheCaller {
            captured: true,
            ..CacheCaller::default()
        }
    }
    use crate::handler_harness::{LoopbackBypassGuard, registry_pointing_ollama_at};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    fn cache(url: String) -> SemanticCache {
        let cfg = crate::server::config::parse(
            "semantic_cache:\n  embedding_models: ollama/embed\n  ttl_hours: 168\n",
        )
        .unwrap();
        SemanticCache::new(
            crate::clickhouse_query::ch_client(url.clone()),
            Arc::new(registry_pointing_ollama_at(url)),
            cfg.semantic_cache().unwrap().clone(),
        )
    }
    #[tokio::test]
    async fn og37_kms_failure_stops_embedding_without_upstream_or_negative_configuration_cache() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock)
            .await;
        let cache = cache(mock.uri());
        let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
        for (failure, code) in [
            (crate::kms::KmsError::Unavailable, "kms_unavailable"),
            (crate::kms::KmsError::Denied, "kms_access_denied"),
        ] {
            let result = crate::kms::wire_tests::FAILURE
                .scope(failure, cache.embed(&tenant, &key()))
                .await;
            assert_eq!(result.unwrap_err().to_string(), code);
            assert!(!embed_failure_is_configuration(&cache.no_embedder, &tenant).await);
        }
        assert!(mock.received_requests().await.unwrap().is_empty());
    }
    fn key() -> RequestKey {
        request_key(&serde_json::from_value(serde_json::json!({"model":"ollama/llama3","messages":[{"role":"user","content":"test"}]})).unwrap())
    }
    #[tokio::test]
    async fn cache_control_refuses_invalid_and_unentitled_requests_on_all_three_routes() {
        use crate::handler_harness::{authed, body_json, test_state};
        use axum::{Json, extract::State};
        let state = test_state(ProviderRegistry::new().unwrap());
        for (value, status) in [
            ("ttl=0", axum::http::StatusCode::BAD_REQUEST),
            ("use", axum::http::StatusCode::FORBIDDEN),
        ] {
            let mut headers = authed();
            headers.insert("x-tracelane-cache", value.parse().unwrap());
            let chat = crate::server::chat_completions_handler(State(state.clone()),headers.clone(),Json(serde_json::json!({"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]}))).await;
            assert_eq!(chat.status(), status);
            assert!(
                body_json(chat).await["error"]["code"]
                    .as_str()
                    .unwrap()
                    .contains("cache_control")
            );
            let embeddings = crate::server::embeddings_handler(
                State(state.clone()),
                headers.clone(),
                Json(serde_json::json!({"model":"ollama/embed","input":"hi"})),
            )
            .await;
            assert_eq!(embeddings.status(), status);
            assert!(
                body_json(embeddings).await["error"]["code"]
                    .as_str()
                    .unwrap()
                    .contains("cache_control")
            );
            let messages = crate::anthropic_messages::messages_handler(State(state.clone()),headers,axum::body::Bytes::from_static(br#"{"model":"claude-test","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#)).await;
            assert_eq!(messages.status(), status);
            let body = body_json(messages).await;
            assert_eq!(body["type"], "error");
            assert!(
                body["error"]["code"]
                    .as_str()
                    .unwrap()
                    .contains("cache_control")
            );
        }
    }
    #[test]
    fn cache_header_validation_and_every_binding() {
        let cache = cache("http://127.0.0.1:1".into());
        let mut grant = ResolvedEntitlements::deny_all();
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(
            CacheControl::parse(&headers).unwrap(),
            CacheControl::Default
        );
        for raw in [
            "",
            "yes",
            "ttl=0",
            "ttl=-1",
            "ttl=+1",
            "ttl=1.5",
            "ttl=9999999999999",
            "use,bypass",
        ] {
            headers.insert("x-tracelane-cache", raw.parse().unwrap());
            assert!(CacheControl::parse(&headers).is_err(), "{raw}");
        }
        headers.insert("x-tracelane-cache", "use".parse().unwrap());
        headers.append("x-tracelane-cache", "bypass".parse().unwrap());
        assert!(CacheControl::parse(&headers).is_err());
        assert!(
            CacheControl::Bypass
                .resolve(None, None, false, &CacheCaller::default())
                .unwrap()
                .bypass
        );
        assert_eq!(
            CacheControl::Use
                .resolve(Some(&grant), Some(&cache), true, &CacheCaller::default())
                .unwrap_err()
                .code,
            "cache_control_not_entitled"
        );
        grant.f_cache_control = true;
        for (plan, requested, effective, binding) in [
            (24, 200, 24, "plan"),
            (720, 200, 168, "operator"),
            (168, 200, 168, "plan,operator"),
            (24, 1, 1, "requested"),
        ] {
            grant.cache_ttl_hours = plan;
            let policy = CacheControl::Ttl(requested)
                .resolve(Some(&grant), Some(&cache), true, &captured())
                .unwrap();
            assert_eq!(policy.ttl_hours, Some(effective));
            assert_eq!(policy.binding, binding);
            let response =
                policy.response(axum::response::Response::new(axum::body::Body::empty()));
            assert_eq!(
                response.headers()["x-tracelane-cache-ttl-hours"],
                effective.to_string()
            );
        }
        assert_eq!(
            CacheControl::Use
                .resolve(Some(&grant), Some(&cache), false, &CacheCaller::default())
                .unwrap_err()
                .code,
            "cache_control_unsupported_route"
        );
        assert_eq!(
            CacheControl::Use
                .resolve(Some(&grant), None, true, &CacheCaller::default())
                .unwrap_err()
                .code,
            "response_cache_disabled"
        );
    }
    /// OG-51 / spec §7 row 5: the effective TTL is the minimum of the request, the workspace,
    /// the plan, the operator and the table's ceiling, and `x-tracelane-cache-bound` names
    /// the winner. Table-driven over every candidate.
    #[test]
    fn og51_effective_ttl_is_the_minimum_and_names_what_bound_it() {
        let operator = |hours: u32| {
            let cfg = crate::server::config::parse(&format!(
                "semantic_cache:\n  embedding_models: ollama/embed\n  ttl_hours: {hours}\n"
            ))
            .unwrap();
            SemanticCache::new(
                crate::clickhouse_query::ch_client("http://127.0.0.1:1"),
                Arc::new(registry_pointing_ollama_at("http://127.0.0.1:1".into())),
                cfg.semantic_cache().unwrap().clone(),
            )
        };
        assert_eq!(crate::cache_controls::config().ttl_ceiling_hours, 168);
        // (requested, workspace, plan, operator) -> (effective, binding)
        for (requested, workspace, plan, op, want) in [
            (None, None, Some(24), 168, (24, "plan")),
            (None, Some(12), Some(24), 168, (12, "workspace")),
            (None, Some(24), Some(24), 168, (24, "workspace,plan")),
            (Some(2), Some(12), Some(24), 168, (2, "requested")),
            (Some(500), Some(12), Some(24), 168, (12, "workspace")),
            (None, None, Some(720), 720, (168, "ceiling")),
            (Some(500), None, Some(720), 720, (168, "ceiling")),
            (None, None, Some(168), 168, (168, "plan,operator")),
            (Some(168), None, Some(720), 720, (168, "requested")),
            (Some(100), None, Some(720), 168, (100, "requested")),
            (None, None, Some(720), 48, (48, "operator")),
            (None, Some(48), Some(720), 48, (48, "workspace,operator")),
        ] {
            let cache = operator(op);
            assert_eq!(
                effective_ttl(requested, workspace, plan, Some(&cache)),
                want,
                "requested={requested:?} workspace={workspace:?} plan={plan:?} operator={op}"
            );
        }
    }

    #[tokio::test]
    async fn og12_model_arms_use_cache_without_sharing_exact_or_semantic_namespace() {
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let cache = cache("http://127.0.0.1:1".into());
        cache.no_embedder.insert(tenant.clone(), ()).await;
        let request: ChatRequest = serde_json::from_value(serde_json::json!({"model":"ollama/llama3","messages":[{"role":"user","content":"identical request"}]})).unwrap();
        let a = cache.bind_key(&tenant, request_key(&request), Some("rule:arm-a"));
        let b = cache.bind_key(&tenant, request_key(&request), Some("rule:arm-b"));
        let ordinary = cache.bind_key(&tenant, request_key(&request), None);
        assert!(!a.bypass && !b.bypass);
        assert_ne!(a.exact_hash, b.exact_hash);
        assert_ne!(a.params_hash, b.params_hash);
        assert_ne!(a.params_hash, ordinary.params_hash);
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &a,
                "arm A",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert_eq!(
            cache
                .lookup(&tenant, "ollama/llama3", &a)
                .await
                .unwrap()
                .response_json,
            "arm A"
        );
        assert!(cache.lookup(&tenant, "ollama/llama3", &b).await.is_none());
        assert!(
            cache
                .lookup(&tenant, "ollama/llama3", &ordinary)
                .await
                .is_none()
        );
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &b,
                "arm B",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert_eq!(
            cache
                .lookup(&tenant, "ollama/llama3", &b)
                .await
                .unwrap()
                .response_json,
            "arm B"
        );
    }

    #[tokio::test]
    async fn canary_never_reuses_another_arm_or_lifecycle() {
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let (router, _, candidate) =
            crate::prompt_router::tests::canary_fixture(tenant.clone()).await;
        let cache = cache("http://127.0.0.1:1".into()).with_prompt_router(router.clone());
        cache.no_embedder.insert(tenant.clone(), ()).await;
        let request:ChatRequest=serde_json::from_value(serde_json::json!({"model":"ollama/llama3","messages":[{"role":"user","content":"same model input"}]})).unwrap();
        let before = cache.bind_key(&tenant, request_key(&request), None);
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &before,
                "arm A",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert_eq!(
            cache
                .lookup(&tenant, "ollama/llama3", &before)
                .await
                .unwrap()
                .response_json,
            "arm A"
        );
        router
            .configure_canary(&tenant, "proof", candidate, 50.0, "tester")
            .await
            .unwrap();
        let active = cache.bind_key(&tenant, request_key(&request), None);
        assert!(
            cache
                .lookup(&tenant, "ollama/llama3", &before)
                .await
                .is_none()
        );
        assert!(
            cache
                .lookup(&tenant, "ollama/llama3", &active)
                .await
                .is_none()
        );
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &active,
                "arm B",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert!(
            cache
                .exact
                .get(&(tenant.clone(), active.exact_hash.clone()))
                .await
                .is_none()
        );
        router
            .stop_canary(&tenant, "proof", "tester")
            .await
            .unwrap();
        let after = cache.bind_key(&tenant, request_key(&request), None);
        assert_ne!(after.params_hash, before.params_hash);
        assert_ne!(after.params_hash, active.params_hash);
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &before,
                "late arm A",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert!(
            cache
                .lookup(&tenant, "ollama/llama3", &before)
                .await
                .is_none()
        );
        assert!(
            cache
                .lookup(&tenant, "ollama/llama3", &after)
                .await
                .is_none()
        );
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &after,
                "current",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert_eq!(
            cache
                .lookup(&tenant, "ollama/llama3", &after)
                .await
                .unwrap()
                .response_json,
            "current"
        );
    }

    #[tokio::test]
    async fn cache_policy_age_and_bypass_store_are_enforced() {
        let cache = cache("http://127.0.0.1:1".into());
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        cache.no_embedder.insert(tenant.clone(), ()).await;
        let policy = CachePolicy {
            ttl_hours: Some(1),
            ..CachePolicy::default()
        };
        let k = policy.key(key());
        assert_ne!(k.params_hash, key().params_hash);
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &k,
                "cached",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert!(cache.lookup(&tenant, "ollama/llama3", &k).await.is_some());
        let mut expired = (*cache
            .exact
            .get(&(tenant.clone(), k.exact_hash.clone()))
            .await
            .unwrap())
        .clone();
        expired.created_at_ms -= 3_600_001;
        cache
            .exact
            .insert((tenant.clone(), k.exact_hash.clone()), Arc::new(expired))
            .await;
        assert!(cache.lookup(&tenant, "ollama/llama3", &k).await.is_none());
        let bypass = CacheControl::Bypass
            .resolve(None, None, true, &CacheCaller::default())
            .unwrap()
            .key(key());
        cache
            .store(
                &tenant,
                "ollama/llama3",
                &bypass,
                "must not store",
                1,
                1,
                0.0,
                Uuid::new_v4(),
            )
            .await;
        assert!(cache.exact.get(&(tenant, key().exact_hash)).await.is_none());
    }
    #[tokio::test]
    #[ignore = "local initialized ClickHouse only; no schema applied"]
    async fn cache_policy_real_clickhouse_age_and_tenant_proof() {
        let _guard = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/v1/embeddings")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"object":"list","data":[{"object":"embedding","index":0,"embedding":[1.0,0.0,0.0]}],"model":"ollama/embed","usage":{"prompt_tokens":1,"total_tokens":1}}))).mount(&server).await;
        let mut cache = cache(server.uri());
        cache.ch = crate::clickhouse_query::ch_client(
            std::env::var("CLICKHOUSE_TEST_URL").expect("local proof URL"),
        );
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let k = CachePolicy {
            ttl_hours: Some(1),
            ..CachePolicy::default()
        }
        .key(key());
        let row = |age_ms, response: &str| CacheRow {
            tenant_id: tenant.to_string(),
            cache_id: Uuid::new_v4(),
            model: "ollama/llama3".into(),
            params_hash: crate::prompt_router::FixedHex64::from_hex_str(&k.params_hash).unwrap(),
            exact_hash: crate::prompt_router::FixedHex64::from_hex_str(&k.exact_hash).unwrap(),
            embedding: vec![1.0, 0.0, 0.0],
            embedding_model: "ollama/embed".into(),
            embedding_dims: 3,
            response_json: response.into(),
            prompt_tokens: 1,
            completion_tokens: 1,
            cost_usd: 0.0,
            source_trace_id: Uuid::new_v4(),
            created_at: crate::clickhouse_query::datetime64_millis_now() - age_ms,
        };
        cache.insert_row(&row(7_200_000, "expired")).await.unwrap();
        assert!(
            cache.lookup(&tenant, "ollama/llama3", &k).await.is_none(),
            "semantic tier must exclude an expired row still present in ClickHouse"
        );
        cache.insert_row(&row(0, "fresh")).await.unwrap();
        let hit = cache.lookup(&tenant, "ollama/llama3", &k).await.unwrap();
        assert_eq!(hit.tier, "semantic");
        assert_eq!(hit.response_json, "fresh");
        assert!(
            cache
                .lookup(
                    &TenantId::from_jwt_claim(Uuid::new_v4()),
                    "ollama/llama3",
                    &k
                )
                .await
                .is_none()
        );
        let bypass = CacheControl::Bypass
            .resolve(None, None, true, &CacheCaller::default())
            .unwrap()
            .key(k);
        assert!(
            cache
                .lookup(&tenant, "ollama/llama3", &bypass)
                .await
                .is_none()
        );
    }

    /// OG-51 / spec §7 rows 2 and 3 on a REAL ClickHouse: the semantic tier's
    /// `(tenant, model, params_hash)` prefilter separates namespaces and epochs with no schema
    /// change, an invalidation hides the old row without deleting it, and no DELETE is issued.
    /// Run with `CLICKHOUSE_TEST_URL` pointing at a server with migration 17 applied.
    #[tokio::test]
    #[ignore = "local initialized ClickHouse only; migration 17 applied"]
    async fn og51_the_semantic_tier_separates_namespaces_and_epochs_on_real_clickhouse() {
        use crate::cache_controls::{Namespace, NamespaceValue};
        use crate::db::cache_settings::NamespaceBy;
        let _guard = LoopbackBypassGuard::new();
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/v1/embeddings")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"object":"list","data":[{"object":"embedding","index":0,"embedding":[1.0,0.0,0.0]}],"model":"ollama/embed","usage":{"prompt_tokens":1,"total_tokens":1}}))).mount(&server).await;
        let mut cache = cache(server.uri());
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("local proof URL");
        cache.ch = crate::clickhouse_query::ch_client(url);
        let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
        let policy = |ns: &str, epoch: i64| CachePolicy {
            fold: crate::cache_controls::fold(
                &NamespaceValue::Value(Namespace {
                    kind: NamespaceBy::Key,
                    value: ns.into(),
                }),
                None,
                &if epoch > 0 {
                    vec![("workspace".to_owned(), epoch)]
                } else {
                    Vec::new()
                },
            ),
            ..CachePolicy::default()
        };
        let (ka, kb) = (policy("key-a", 0).key(key()), policy("key-b", 0).key(key()));
        assert_ne!(
            ka.params_hash, kb.params_hash,
            "namespaces never share a prefilter key"
        );
        let row = CacheRow {
            tenant_id: tenant.to_string(),
            cache_id: Uuid::new_v4(),
            model: "ollama/llama3".into(),
            params_hash: crate::prompt_router::FixedHex64::from_hex_str(&ka.params_hash).unwrap(),
            exact_hash: crate::prompt_router::FixedHex64::from_hex_str(&ka.exact_hash).unwrap(),
            embedding: vec![1.0, 0.0, 0.0],
            embedding_model: "ollama/embed".into(),
            embedding_dims: 3,
            response_json: "key-a's answer".into(),
            prompt_tokens: 1,
            completion_tokens: 1,
            cost_usd: 0.0,
            source_trace_id: Uuid::new_v4(),
            created_at: crate::clickhouse_query::datetime64_millis_now(),
        };
        cache.insert_row(&row).await.unwrap();
        // The stored row is served to its own namespace on the SEMANTIC tier …
        let hit = cache.lookup(&tenant, "ollama/llama3", &ka).await.unwrap();
        assert_eq!(
            (hit.tier, hit.response_json.as_str()),
            ("semantic", "key-a's answer")
        );
        // … and to nobody else: another key, and the same key after an invalidation.
        assert!(cache.lookup(&tenant, "ollama/llama3", &kb).await.is_none());
        let bumped = policy("key-a", 1).key(key());
        assert!(
            cache
                .lookup(&tenant, "ollama/llama3", &bumped)
                .await
                .is_none()
        );
        // The row is still there: invalidation stops serving, it does not erase.
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct N {
            n: u64,
        }
        let n = cache
            .ch
            .query("SELECT count() AS n FROM semantic_cache WHERE tenant_id = ?")
            .bind(tenant.to_string())
            .fetch_one::<N>()
            .await
            .unwrap()
            .n;
        assert_eq!(n, 1);
    }
}

/// `OG-03` — every new answer-changing field is part of the cache identity.
#[cfg(test)]
mod og03_key_tests {
    use super::request_key;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, Stop};

    fn base() -> ChatRequest {
        ChatRequest {
            model: "gpt-4o".into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("hello".into()),
                tool_call_id: None,
                tool_calls: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn two_requests_differing_in_one_new_field_never_share_a_key() {
        let plain = request_key(&base());
        type Mutation = fn(&mut ChatRequest);
        let variants: Vec<(&str, Mutation)> = vec![
            ("stop", |r| r.stop = Some(Stop::One("END".into()))),
            ("stop (other)", |r| r.stop = Some(Stop::One("STOP".into()))),
            ("response_format", |r| {
                r.response_format = Some(serde_json::json!({"type": "json_object"}))
            }),
            ("reasoning_effort", |r| {
                r.reasoning_effort = Some("high".into())
            }),
            ("max_completion_tokens", |r| {
                r.max_completion_tokens = Some(5)
            }),
            ("presence_penalty", |r| r.presence_penalty = Some(0.5)),
            ("frequency_penalty", |r| r.frequency_penalty = Some(0.5)),
            ("parallel_tool_calls", |r| {
                r.parallel_tool_calls = Some(false)
            }),
            ("extra", |r| {
                r.extra
                    .insert("logit_bias".into(), serde_json::json!({"1": 2}));
            }),
        ];
        let mut seen = vec![plain.exact_hash.clone()];
        for (name, f) in variants {
            let mut r = base();
            f(&mut r);
            let k = request_key(&r);
            assert_ne!(
                k.exact_hash, plain.exact_hash,
                "{name}: exact key collides with the plain request"
            );
            assert_ne!(
                k.params_hash, plain.params_hash,
                "{name}: params hash collides"
            );
            assert!(
                !seen.contains(&k.exact_hash),
                "{name}: collides with another variant"
            );
            seen.push(k.exact_hash);
        }
    }

    #[test]
    fn extra_is_hashed_canonically_and_value_changes_move_the_key() {
        let mut a = base();
        a.extra
            .insert("a".into(), serde_json::json!({"x": 1, "y": 2}));
        a.extra.insert("b".into(), serde_json::json!(true));
        let mut b = base();
        b.extra.insert("b".into(), serde_json::json!(true));
        b.extra
            .insert("a".into(), serde_json::json!({"y": 2, "x": 1}));
        assert_eq!(request_key(&a).exact_hash, request_key(&b).exact_hash);
        b.extra
            .insert("a".into(), serde_json::json!({"y": 2, "x": 9}));
        assert_ne!(request_key(&a).exact_hash, request_key(&b).exact_hash);
    }

    /// `user` and `service_tier` do not change the answer, and `n` is always 1: none of them
    /// may fragment the cache. Existing keys (requests carrying none of the new fields) are
    /// untouched because every addition is tagged and hashed only when present.
    #[test]
    fn fields_that_do_not_change_the_answer_do_not_change_the_key() {
        let plain = request_key(&base());
        let mut r = base();
        r.user = Some("end-user-1".into());
        r.service_tier = Some("flex".into());
        r.n = Some(1);
        let k = request_key(&r);
        assert_eq!(k.exact_hash, plain.exact_hash);
        assert_eq!(k.params_hash, plain.params_hash);
    }
}
