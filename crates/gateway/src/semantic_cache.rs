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
use serde::{Deserialize, Serialize};
use tracelane_shared::{ChatRequest, MessageContent, TenantId};
use uuid::Uuid;

use crate::providers::ProviderRegistry;
use crate::server::config::SemanticCacheConfig;

/// A served hit, and everything the span needs to record it honestly.
#[derive(Debug, Clone)]
pub struct CacheHit {
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
    /// blake3 of params + normalised messages. The exact tier's key.
    pub exact_hash: String,
    /// sha256-shaped hex of the NON-message parameters. An exact match on this
    /// is required before any similarity comparison: two requests whose sampling
    /// parameters differ are not interchangeable however alike their text reads.
    pub params_hash: String,
    /// The normalised message text that gets embedded.
    pub embed_text: String,
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
    if let Some(sys) = &req.system {
        params.update(sys.as_bytes());
    }
    let params_hash = params.finalize().to_hex().to_string();

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

    let mut exact = blake3::Hasher::new();
    exact.update(params_hash.as_bytes());
    exact.update(embed_text.as_bytes());
    let exact_hash = exact.finalize().to_hex().to_string();

    RequestKey {
        exact_hash,
        params_hash,
        embed_text,
    }
}

/// The cache.
pub struct SemanticCache {
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
    #[must_use]
    pub fn new(
        ch: ClickhouseClient,
        providers: Arc<ProviderRegistry>,
        cfg: SemanticCacheConfig,
    ) -> Self {
        let ttl = std::time::Duration::from_secs(u64::from(cfg.ttl_hours()) * 3600);
        Self {
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

    #[must_use]
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
        let started = Instant::now();

        // ── Tier 1: exact. No network, no embedding, no ClickHouse. ──────────
        if let Some(hit) = self
            .exact
            .get(&(tenant_id.clone(), key.exact_hash.clone()))
            .await
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
        let embedding = match self.embed(tenant_id, &key.embed_text).await {
            Ok(v) => v,
            Err(e) => {
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::SemanticCacheUnavailable,
                );
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
                    completion_tokens, cosineDistance(embedding, ?) AS distance \
             FROM semantic_cache \
             WHERE tenant_id = ? AND model = ? AND params_hash = ? \
               AND embedding_dims = ? \
             ORDER BY created_at DESC \
             LIMIT ?",
            crate::clickhouse_query::PlanTier::Builder,
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
        Some(CacheHit {
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
    async fn embed(&self, tenant_id: &TenantId, text: &str) -> Result<Vec<f32>> {
        let mut last_err: Option<anyhow::Error> = None;
        for model in self.cfg.embedding_models() {
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
                    _ => continue,
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
                    &key,
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
                Err(e) => last_err = Some(e),
            }
        }
        // NO CREDENTIAL AT ALL is different from "the embedder errored", and only
        // the first is worth remembering. `last_err` is `None` exactly when every
        // model was skipped for lack of a usable key — a stable property of this
        // tenant's configuration, not a transient fault — so that is the case
        // that populates the negative cache. A provider OUTAGE must keep
        // retrying, because it will come back.
        if last_err.is_none() {
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
    /// - **Tool calls.** A `tool_calls` response is a side-effecting
    ///   instruction; serving a remembered one is a replay, not a saving. Only
    ///   `finish_reason == "stop"` is stored.
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
        if response_json.len() > MAX_RESPONSE_BYTES {
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

        // The DURABLE half needs a vector, so it needs a credential. Failing here
        // costs the semantic tier and the cross-restart copy; the exact tier
        // above is already live either way.
        let embedding = match self.embed(tenant_id, &key.embed_text).await {
            Ok(v) => v,
            Err(_) => {
                tracelane_shared::degradation::note(
                    tracelane_shared::degradation::Degradation::SemanticCacheUnavailable,
                );
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
mod tests {
    use super::*;
    use tracelane_shared::{Message, Role};

    fn req(model: &str, text: &str, temp: Option<f32>) -> ChatRequest {
        ChatRequest {
            model: model.into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text(text.into()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: None,
            temperature: temp,
            stream: None,
            system: None,
            metadata: None,
        }
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
}
