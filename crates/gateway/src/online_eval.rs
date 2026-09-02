//! Online evals — score a SAMPLE of live production traffic with the LLM judge
//! that Sprint 3 item 10 already shipped (`EVL-28`, item 11).
//!
//! ── WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT ───────────────────────────
//! It samples, it dispatches the existing judge, it records the score. It does
//! not build a judge — `Assertion::LlmJudge`, its rubrics, its two-stage
//! fail-closed validator and its BYOK dispatch all exist and are reused here.
//!
//! **AN ONLINE SCORE GATES NOTHING. Display and alert only.** It never reaches
//! `auto_rollback`, never flips a routing pointer, never blocks a request. That
//! is a PROPERTY of this module, stated here because it is an omission
//! everywhere else and an omission is not findable. ADR-037 is the rule
//! (subjective metrics are suggest-and-confirm, never auto) and the Intervention
//! Paradox is the evidence: a high-AUROC critic caused performance collapse when
//! it was allowed to intervene automatically. A sampled judge is a WEAKER signal
//! than that critic, and it is scoring live customer traffic. The only export
//! from this module is a row in `online_eval_scores`; nothing here returns a
//! value any control path consumes.
//!
//! ── THE HOT PATH ────────────────────────────────────────────────────────────
//! `admission()` is the only thing the chat handler calls, and it does NO I/O on
//! a cache hit — one cached entitlement read, one cached policy read, one hash.
//! Everything expensive happens in `spawn()`, after the response is complete and
//! the span is published, inside a `tokio::spawn` whose result nobody awaits.
//! A judge call cannot add latency to a customer request, cannot fail one, and
//! cannot hold the write path open.
//!
//! ── THE MONEY, AND THE THING MOST LIKELY TO BE "SIMPLIFIED" LATER ───────────
//! **TWO COUNTERS, ONE WALLET.** Judge spend is real money drawn from the
//! workspace's own budget, so it is recorded against `Subject::Workspace` — the
//! same counter `/v1/costs` and the workspace budget already read. The policy's
//! `judge_budget_usd_monthly` is a SUB-LIMIT checked **IN ADDITION**, never
//! instead.
//!
//! The tempting simplification is to keep only the sub-limit, on the reasoning
//! that judge spend is "eval money, not chat money". It is not: it is one
//! invoice. Dropping the workspace record would make judge spend invisible to
//! the workspace budget and to `/v1/costs` — a second wallet nobody reconciles,
//! which is exactly how a customer meets eval spend for the first time on a
//! bill. Both writes are required. If you are here to remove one, remove
//! neither.

use std::sync::{Arc, OnceLock};

use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
use uuid::Uuid;

use crate::providers::ProviderRegistry;

/// Policy cache TTL.
///
/// **`hot-path-cache-ttl` site.** 900s, well above the guard's 600s floor and
/// matching the entitlement cache. The B-256 class is the reason there is a
/// floor at all: a cache whose TTL is shorter than the gap between a sparse
/// tenant's requests is not a cache, it is a tax — three of four hot-path caches
/// had one, and it cost a 13x overhead regression.
///
/// This value is a NAMED CONST rather than an inline `Duration` on purpose. The
/// guard matches on the const name, and GWY-24's negative cache was invisible to
/// it precisely because the number lived inside a builder chain.
pub const POLICY_CACHE_TTL_SECS: u64 = 900;

/// Longest judge `reason` we store. A judge that will not be brief is not a
/// reason to grow a column without a bound.
const REASON_MAX_CHARS: usize = 2_000;

/// How much of the exchange the judge is shown. Bounded because this runs on
/// live traffic of unknown size and an unbounded prompt is an unbounded bill.
const JUDGE_INPUT_MAX_CHARS: usize = 8_000;

/// One workspace's online-eval configuration, as stored in
/// `online_eval_policies`.
#[derive(Debug, Clone)]
pub struct Policy {
    pub id: Uuid,
    pub enabled: bool,
    /// `builtin` | `prompt_version`.
    pub rubric_kind: String,
    pub rubric: String,
    pub judge_model: String,
    /// 0.0–0.10. The ceiling is a CHECK on the table, not a promise made here.
    pub sample_rate: f64,
    pub sample_salt: String,
    /// Required. There is no default anywhere in this system, by design.
    pub judge_budget_usd_monthly: f64,
}

type PolicyCache = moka::future::Cache<Uuid, Option<Arc<Policy>>>;

fn cache() -> &'static PolicyCache {
    static C: OnceLock<PolicyCache> = OnceLock::new();
    C.get_or_init(|| {
        moka::future::Cache::builder()
            .max_capacity(10_000)
            .time_to_live(std::time::Duration::from_secs(POLICY_CACHE_TTL_SECS))
            .build()
    })
}

/// Read one workspace's policy, through the cache.
///
/// **`None` covers three different facts and they are deliberately collapsed
/// here**: no policy row, a disabled policy, and no control plane at all. All
/// three mean the same thing to the caller — do not sample — and distinguishing
/// them at the call site would invite a branch that treats "cannot tell" as
/// "yes". Absent control plane resolving to OFF is `.claude/rules/tenancy.md`:
/// a no-cache path denies, it never grants. Here that is also the free
/// direction: no policy, no spend.
async fn policy_for(tenant_id: &TenantId) -> Option<Arc<Policy>> {
    let key = *tenant_id.as_uuid();
    if let Some(hit) = cache().get(&key).await {
        return hit;
    }
    let loaded = load_policy(key).await;
    cache().insert(key, loaded.clone()).await;
    loaded
}

async fn load_policy(tenant_uuid: Uuid) -> Option<Arc<Policy>> {
    let pool = crate::db::global_pool()?;
    let client = pool.get().await.ok()?;
    let row = client
        .query_opt(
            "SELECT id, enabled, rubric_kind, rubric, judge_model, sample_rate, \
                    sample_salt, judge_budget_usd_monthly \
               FROM online_eval_policies WHERE tenant_id = $1",
            &[&tenant_uuid],
        )
        .await
        .ok()??;
    Some(Arc::new(Policy {
        id: row.get(0),
        enabled: row.get(1),
        rubric_kind: row.get(2),
        rubric: row.get(3),
        judge_model: row.get(4),
        sample_rate: row.get(5),
        sample_salt: row.get(6),
        judge_budget_usd_monthly: row.get(7),
    }))
}

/// Drop this workspace's cached policy. Called by the write route so an edit is
/// visible immediately rather than after the TTL.
pub async fn invalidate(tenant_id: &TenantId) {
    cache().invalidate(tenant_id.as_uuid()).await;
}

/// Is this trace in the sample?
///
/// **DETERMINISTIC, NEVER RANDOM, and that is a product requirement rather than
/// an implementation taste.** A customer must be able to say WHICH traces were
/// scored and re-run exactly that set; a random draw makes "why was this one
/// scored" unanswerable and makes any re-run a different sample. `blake3` of
/// `salt || trace_id`, first 8 bytes as a big-endian u64, compared against
/// `rate * u64::MAX`.
///
/// The salt is per-policy so two workspaces sampling at the same rate do not
/// score correlated traces — without it, "1%" would mean the same 1% of trace
/// ids everywhere, which is a systematic bias, not a sample.
#[must_use]
pub fn should_sample(salt: &str, trace_id: Uuid, rate: f64) -> bool {
    // Guard both ends explicitly. `rate <= 0.0` is off; `>= 1.0` is everything.
    // Neither is reachable through the table (CHECK 0..=0.10) — this function is
    // pure and is unit-tested directly, so it defends its own contract.
    // NaN is spelled out rather than caught by a negated comparison. `!(rate >
    // 0.0)` was NaN-safe and unreadable; this is both. A NaN rate cannot reach
    // here through the table (the CHECK rejects it) — this function is pure and
    // defends its own contract.
    if rate.is_nan() || rate <= 0.0 {
        return false;
    }
    if rate >= 1.0 {
        return true;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(salt.as_bytes());
    hasher.update(trace_id.as_bytes());
    let digest = hasher.finalize();
    let bytes: [u8; 8] = digest.as_bytes()[..8].try_into().unwrap_or([0u8; 8]);
    let drawn = u64::from_be_bytes(bytes);
    // `rate * 2^64` as f64 then compare in u128 space: at 1% the threshold is
    // ~1.8e17, far inside f64's exact-integer range for this purpose, and the
    // u128 comparison avoids the f64->u64 saturating-cast edge at the top.
    let threshold = (rate * (u64::MAX as f64)) as u128;
    u128::from(drawn) < threshold
}

/// The ONLY thing the chat handler calls. No I/O on a cache hit.
///
/// Returns the policy iff this request should be scored: the workspace is
/// entitled, has an enabled policy, and this `trace_id` falls in the sample.
pub async fn admission(
    tenant_id: &TenantId,
    trace_id: Uuid,
    entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
) -> Option<Arc<Policy>> {
    // Entitlement first: it is the cheapest check and the one that must fail
    // closed. `None` (no control plane) is the unprivileged state — no feature.
    if !entitlements?.has(crate::entitlement_cache::FeatureKey::OnlineEvals) {
        return None;
    }
    let policy = policy_for(tenant_id).await?;
    if !policy.enabled {
        return None;
    }
    should_sample(&policy.sample_salt, trace_id, policy.sample_rate).then_some(policy)
}

/// Flatten a chat request body's user-visible text for the judge.
///
/// Best-effort and BOUNDED: this runs on the hot path, on live traffic of
/// unknown size. Only `messages[].content` is read — never tool payloads,
/// never metadata — because the judge grades the answer to a question, and
/// widening what it sees widens both the bill and the blast radius of a prompt
/// injection reaching the judge.
#[must_use]
pub fn flatten_request_text(body: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(msgs) = body.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            let Some(role) = m.get("role").and_then(|r| r.as_str()) else {
                continue;
            };
            // The SYSTEM prompt is deliberately excluded: it is the operator's
            // instruction, not the user's question, and it is frequently the
            // largest and most sensitive part of the body.
            if role == "system" {
                continue;
            }
            match m.get("content") {
                Some(serde_json::Value::String(t)) => {
                    out.push_str(role);
                    out.push_str(": ");
                    out.push_str(t);
                    out.push('\n');
                }
                Some(serde_json::Value::Array(parts)) => {
                    for part in parts {
                        if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                            out.push_str(role);
                            out.push_str(": ");
                            out.push_str(t);
                            out.push('\n');
                        }
                    }
                }
                _ => {}
            }
            if out.len() >= JUDGE_INPUT_MAX_CHARS {
                break;
            }
        }
    }
    truncate(&out, JUDGE_INPUT_MAX_CHARS / 2).to_string()
}

/// The admission decision, carried down the response path.
///
/// ONE `Option` parameter rather than four, because the two completion functions
/// already have very long signatures and a decision that arrives in pieces is a
/// decision that can arrive half-assembled. `Some` means "this request is in the
/// sample"; the completion site adds only the answer it alone has.
///
/// It also carries the STREAMING contract: `provider_stream_to_sse` accumulates
/// the response text **only when this is `Some`**. That is the entire reason the
/// sample decision is made at admission rather than at completion — accumulating
/// on 100% of streaming traffic to serve a 1% sample is a cost paid by every
/// request that will never be scored.
pub struct Pending {
    pub policy: Arc<Policy>,
    pub providers: Arc<ProviderRegistry>,
    pub clickhouse_url: Option<String>,
    /// The span bus. `None` on a deployment with capture disabled, in which case
    /// the judge still runs and still writes its score — it is only the COST
    /// span that is lost, and that is announced through the same
    /// `note_span_dropped_no_nats` counter every other publish site uses rather
    /// than being silently absorbed.
    pub nats: Option<Arc<async_nats::Client>>,
    /// The user's input, flattened to text at admission — the request body is
    /// gone by the time the judge runs.
    pub question: String,
}

impl Pending {
    #[must_use]
    pub fn into_job(
        self,
        tenant_id: TenantId,
        trace_id: Uuid,
        span_id: String,
        answer: String,
    ) -> JudgeJob {
        JudgeJob {
            policy: self.policy,
            tenant_id,
            trace_id,
            span_id,
            providers: self.providers,
            clickhouse_url: self.clickhouse_url,
            nats: self.nats,
            question: self.question,
            answer,
        }
    }
}

/// Everything the spawned judge needs, captured by value at the hook site.
///
/// Owned rather than borrowed because it crosses a `tokio::spawn` boundary and
/// must not keep the request alive.
pub struct JudgeJob {
    pub policy: Arc<Policy>,
    pub tenant_id: TenantId,
    pub trace_id: Uuid,
    pub span_id: String,
    pub providers: Arc<ProviderRegistry>,
    pub clickhouse_url: Option<String>,
    pub nats: Option<Arc<async_nats::Client>>,
    /// What the user asked, flattened to text.
    pub question: String,
    /// What the model answered.
    pub answer: String,
}

/// Fire and forget. Returns immediately; the caller never awaits the judge.
///
/// **This is the whole of the "never in the hot path" constraint in one line.**
/// The response has already been sent and the span already published by the time
/// this is called, so a slow judge, a provider outage or a ClickHouse blip is
/// invisible to the customer. Nothing here can return an error to the request.
pub fn spawn(job: JudgeJob) {
    tokio::spawn(async move {
        if let Err(e) = judge_one(&job).await {
            // A failed online eval is a DEGRADATION, not an incident: the
            // customer's request already succeeded. One counter, one rate-limited
            // WARN — never a line per occurrence (`.claude/rules/logging.md`).
            tracing::warn!(error = %format!("{e:#}"), "online eval judge failed");
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::OnlineEvalJudgeFailed,
            );
        }
    });
}

async fn judge_one(job: &JudgeJob) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    // Wall-clock start, kept alongside the `Instant`: the span needs a real
    // timestamp and `Instant` is monotonic-only.
    let started_at = chrono::Utc::now();

    // ── THE CAP, CHECKED BEFORE A CENT IS SPENT ─────────────────────────────
    //
    // TWO COUNTERS, ONE WALLET — see the module doc. The sub-limit below is
    // checked IN ADDITION to the workspace budget, never instead of it, and the
    // spend is recorded to BOTH after the call.
    let sub = crate::spend::Subject::OnlineEvalJudge(*job.tenant_id.as_uuid());
    let ym = crate::spend::year_month(chrono::Utc::now());
    if crate::spend::tracker().needs_seed(sub, ym) {
        // An in-memory counter alone is not a cap: a redeploy would forgive
        // every dollar accrued this month. Seeded from the durable ClickHouse
        // total, the same shape `seed_workspace` uses.
        let baseline = judge_spend_this_month(job).await;
        crate::spend::tracker().seed_if_needed(sub, ym, baseline);
    }
    if let crate::spend::BudgetDecision::Exceeded {
        budget_usd,
        spent_usd,
    } = crate::spend::tracker().check(sub, Some(job.policy.judge_budget_usd_monthly))
    {
        // Refused, recorded, and NOT retried. The customer's request was
        // unaffected; what stops is the scoring.
        tracelane_shared::degradation::note(
            tracelane_shared::degradation::Degradation::OnlineEvalBudgetExceeded,
        );
        write_score(job, ScoreRow::refused(job, budget_usd, spent_usd)).await?;
        return Ok(());
    }

    // ── THE JUDGE, REUSED — not reimplemented ───────────────────────────────
    let rubric_text = match job.policy.rubric_kind.as_str() {
        "builtin" => crate::prompt_eval::judge::built_in(&job.policy.rubric)
            .ok_or_else(|| anyhow::anyhow!("unknown built-in rubric {:?}", job.policy.rubric))?
            .to_string(),
        // A tenant rubric is a managed prompt version and is authorized the same
        // way the offline judge authorizes one. Resolved at policy-write time,
        // stored here as the version's own text id; a version that has since been
        // deleted is an error, not a silent fallback to a built-in.
        _ => anyhow::bail!(
            "rubric_kind {:?} is not resolvable from the online path yet",
            job.policy.rubric_kind
        ),
    };
    let system = format!(
        "{rubric_text}{}",
        crate::prompt_eval::judge::OUTPUT_CONTRACT
    );

    let mut prompt = String::with_capacity(512);
    prompt.push_str("<input>\n");
    prompt.push_str(truncate(&job.question, JUDGE_INPUT_MAX_CHARS / 2));
    prompt.push_str("\n</input>\n\n<output>\n");
    prompt.push_str(truncate(&job.answer, JUDGE_INPUT_MAX_CHARS / 2));
    prompt.push_str("\n</output>");

    let model = job.policy.judge_model.clone();
    let Some(provider_id) = ProviderRegistry::provider_id_for_model(&model) else {
        anyhow::bail!("unroutable judge model '{model}'");
    };
    let env_var = ProviderRegistry::env_var_for_provider_id(provider_id);
    // The tenant's OWN credential. A judge call appears in their traces and
    // costs us nothing, which is the whole reason it goes through our gateway
    // rather than a key of ours.
    let key = match crate::server::resolve_provider_key(&job.tenant_id, provider_id, env_var).await
    {
        crate::server::ProviderKey::Found(k) => k,
        crate::server::ProviderKey::NotConfigured => {
            anyhow::bail!("no provider key for '{provider_id}'")
        }
        crate::server::ProviderKey::Unusable => {
            anyhow::bail!("stored '{provider_id}' key could not be decrypted")
        }
    };

    let request = ChatRequest {
        model: model.clone(),
        messages: vec![Message {
            role: Role::User,
            content: MessageContent::Text(prompt),
            tool_calls: None,
            tool_call_id: None,
        }],
        tools: None,
        max_tokens: None,
        temperature: None,
        stream: Some(false),
        system: Some(system),
        metadata: None,
    };

    let mut stream =
        crate::server::dispatch_to_provider(&job.providers, request, &key, &model, &job.tenant_id)
            .await?;

    let mut text = String::new();
    // Upstream-reported cost, `Some` ONLY when the provider puts one on the
    // wire. Most do not — Anthropic, which is 94% of this deployment's traffic,
    // never does.
    let mut wire_cost_usd: Option<f64> = None;
    // TOKENS ARE CAPTURED, and they are the whole reason the cap works.
    //
    // This loop originally read `cost_usd` from `UsageUpdate` and nothing else.
    // Against a provider that does not price on the wire that yields
    // `cost_usd = None` for EVERY judge call, and `SpendTracker::record` treats
    // `None` as "no information" and adds nothing — correctly, since an unpriced
    // request must never be booked as free. The consequence is what matters:
    // both counters would stay at zero forever, the sub-limit could never be
    // reached, and every score row would carry a NULL `cost_usd` that the
    // re-seed SUM then ignores. **A cap that can never be reached is not a cap**,
    // and it would have looked exactly like a cap nobody had hit yet.
    let mut input_tokens = 0u32;
    let mut output_tokens = 0u32;
    use futures::StreamExt;
    while let Some(ev) = stream.next().await {
        match ev? {
            crate::providers::ProviderEvent::StreamChunk { delta } => text.push_str(&delta),
            crate::providers::ProviderEvent::UsageUpdate {
                input_tokens: i,
                output_tokens: o,
                cost_usd: c,
                ..
            } => {
                if i > 0 {
                    input_tokens = i;
                }
                if o > 0 {
                    output_tokens = o;
                }
                if c.is_some() {
                    wire_cost_usd = c;
                }
            }
            crate::providers::ProviderEvent::Done { response } => {
                if let Some(choice) = response.choices.first() {
                    if let MessageContent::Text(t) = &choice.message.content {
                        if !t.is_empty() {
                            text = t.clone();
                        }
                    }
                }
                if let Some(usage) = response.usage {
                    if usage.input_tokens > 0 {
                        input_tokens = usage.input_tokens;
                    }
                    if usage.output_tokens > 0 {
                        output_tokens = usage.output_tokens;
                    }
                }
            }
            _ => {}
        }
    }

    // The provider priced it, or our own catalog can. `None` STAYS `None` — an
    // unpriced model is UNKNOWN, never zero, and the ClickHouse column is
    // Nullable for exactly this reason. Same fallback and same order as
    // `prompt_eval::execute_case`, which is the offline half of this feature.
    let cost_usd = wire_cost_usd.or_else(|| {
        crate::pricing::cost_usd(
            &model,
            &tracelane_shared::Usage {
                input_tokens,
                output_tokens,
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
            },
        )
    });

    // ── RECORD THE SPEND TO BOTH COUNTERS ───────────────────────────────────
    //
    // Workspace FIRST, because that is the wallet and the one `/v1/costs` and the
    // workspace budget read. The sub-limit second. Removing either is the
    // simplification the module doc refuses.
    crate::spend::tracker().record(
        crate::spend::Subject::Workspace(*job.tenant_id.as_uuid()),
        cost_usd,
    );
    crate::spend::tracker().record(sub, cost_usd);

    // ── THE COST SPAN. `/v1/costs` READS SPANS, NOT THE TRACKER. ────────────
    //
    // The two counters above gate spending. They are in-memory and no read
    // surface consults them, so without this publish the judge's money would be
    // invisible on the one page a customer looks at to answer "what am I paying
    // for" — a second wallet nobody reconciles, which is the exact failure the
    // module doc refuses in the other direction. The sub-limit stops the spend;
    // this makes it VISIBLE. Both are required and neither substitutes.
    emit_judge_span(
        job,
        &model,
        started_at,
        input_tokens,
        output_tokens,
        cost_usd,
    );

    let latency_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);

    // Two-stage, fail-CLOSED: structure via the shared validator, then range at
    // this site. A non-conforming judge is `errored` with NO SCORE — never a
    // `failed`, never a 0.0 standing in for "we could not tell".
    let row = match crate::prompt_eval::judge::validate(&text) {
        Ok(v) => ScoreRow {
            status: "scored".into(),
            score: Some(v.score),
            verdict: v.verdict,
            reason: truncate(&v.reason, REASON_MAX_CHARS).to_string(),
            error: None,
            cost_usd,
            latency_ms,
        },
        Err(why) => ScoreRow {
            status: "errored".into(),
            score: None,
            verdict: String::new(),
            reason: String::new(),
            error: Some(why),
            cost_usd,
            latency_ms,
        },
    };
    write_score(job, row).await
}

/// Publish the judge call as a `gen_ai.chat` span so `/v1/costs` can price it.
///
/// ## The two attributes, and why BOTH
///
/// - **`tracelane_eval_role = "judge"`** is what `/v1/costs` splits
///   `judge_cost_usd` on (`trace_reads::JUDGE_SPAN_EXPR`). Without it the judge's
///   spend is reported as ordinary chat traffic.
/// - **`tracelane_eval_run_id`** is the eval-vs-production discriminator
///   (`EVAL_SPAN_EXPR`), and `trace_reads.rs:990` states the invariant this must
///   not break: *a judge call carries both, so `judge_cost_usd <= eval_cost_usd`
///   always.* Setting only the role would leave the judge counted in
///   `production_cost_usd = total - eval` — booking our own eval spend as the
///   customer's production traffic, on the surface built to separate them.
///
/// **It carries the POLICY id, and that is a deliberate reading of the field
/// rather than a convenient one.** The attribute's job at every consumer in this
/// tree is "this span is eval work, grouped by the thing that produced it" — it
/// is never joined against the `eval_runs` table (grepped: `/v1/costs` and the
/// scope filter test `!= ''`, nothing else). An online eval has no run and never
/// will: it is a continuous stream with no batch, no completion and no
/// denominator, which is migration 20's whole argument for a separate table. The
/// policy IS its grouping key, and `online_eval_scores.policy_id` already records
/// the same id, so the two surfaces agree.
///
/// ## Its own trace, like an eval case
///
/// A `Uuid::new_v4()` trace, not `job.trace_id`. Attaching it to the customer's
/// trace would put a span the customer did not make inside the tree they are
/// reading, and the trace-tree renderer would show a phantom second call. The
/// join back to the scored trace is `online_eval_scores`, which holds both ids.
///
/// Fire-and-forget, same posture as every other publish site: a capture failure
/// is COUNTED, never fatal. The score is already written; losing the cost span
/// is a capture problem, not an eval problem.
fn emit_judge_span(
    job: &JudgeJob,
    model: &str,
    started_at: chrono::DateTime<chrono::Utc>,
    input_tokens: u32,
    output_tokens: u32,
    cost_usd: Option<f64>,
) {
    let Some(ref nats) = job.nats else {
        crate::otlp_emit::note_span_dropped_no_nats();
        return;
    };
    let mut span = crate::server::build_gateway_span(
        &job.tenant_id,
        Uuid::new_v4(),
        model,
        None,
        None,
        None,
        started_at,
        input_tokens,
        output_tokens,
        None,
        crate::server::SpanUsageMeta {
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
            stream: false,
            // `None` here lets `build_gateway_span` fall back to the price
            // catalog, which is the same answer `cost_usd` above already
            // computed — passing our value keeps the span and the score row
            // reporting one number rather than two that could disagree.
            cost_usd,
        },
        None,
        None,
        None,
        None,
        None,
    );
    span.attributes.tracelane_eval_role = Some("judge".to_string());
    span.attributes.tracelane_eval_run_id = Some(job.policy.id.to_string());
    let nats = Arc::clone(nats);
    tokio::spawn(async move {
        if let Err(e) = crate::otlp_emit::publish_span(&nats, &span).await {
            crate::otlp_emit::note_span_publish_failed();
            tracing::warn!(error = %e, "online eval judge span NATS publish failed");
        }
    });
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

struct ScoreRow {
    status: String,
    score: Option<f64>,
    verdict: String,
    reason: String,
    error: Option<String>,
    cost_usd: Option<f64>,
    latency_ms: u32,
}

impl ScoreRow {
    fn refused(_job: &JudgeJob, budget_usd: f64, spent_usd: f64) -> Self {
        Self {
            status: "errored".into(),
            score: None,
            verdict: String::new(),
            reason: String::new(),
            // BOTH FIGURES AT THE SAME PRECISION, and it is not cosmetic.
            // This was `${budget_usd:.2}`, which renders a real cap of
            // $0.00006815 as **"$0.00"** — telling the customer their ceiling is
            // zero, which is precisely the "a cap of 0 is not a cap" confusion
            // `validate_policy` refuses at write time. Observed on prod
            // 2026-08-29 while proving the refusal: *"judge budget reached:
            // $0.0002 of $0.00 this month"*. A message that contradicts a rule
            // the same feature enforces is worse than no message.
            error: Some(format!(
                "judge budget reached: ${spent_usd:.6} of ${budget_usd:.6} this month"
            )),
            cost_usd: None,
            latency_ms: 0,
        }
    }
}

/// The durable monthly judge total, used to re-seed the sub-limit after a
/// restart. `SUM` over a Nullable column ignores NULLs, which is exactly right:
/// NULL is UNKNOWN, and an unknown cost must not be counted as zero.
async fn judge_spend_this_month(job: &JudgeJob) -> f64 {
    let Some(url) = job.clickhouse_url.clone() else {
        return 0.0;
    };
    // **`Option<f64>`, BECAUSE THE COLUMN IS NULLABLE — and that is the WHOLE
    // fix, deliberately not belt-and-braces.** `online_eval_scores.cost_usd` is
    // `Nullable(Float64)`, so `sum()` over it is `Nullable(Float64)` too. This
    // struct declared a bare `f64`; clickhouse-rs then failed to deserialize and
    // the `match` below fell to its `_ => 0.0` arm — **every time, for every
    // tenant, silently**.
    //
    // THE FIRST ATTEMPT AT THIS FIX ALSO WRAPPED THE SQL IN `ifNull(..., 0)`, on
    // the reasoning that two guards are safer than one. They are not: `ifNull`
    // makes the result NON-Nullable, so `Option<f64>` then went looking for a
    // null tag byte that was no longer on the wire — `InvalidTagEncoding(70)`,
    // a fresh defect in the same line. **RowBinary is positional and typed; the
    // Rust type must match the column EXACTLY, and a redundant guard changes the
    // type rather than reinforcing it.** The round trip below caught that within
    // one run, which is the second time in this file it has paid for itself.
    //
    // THE CONSEQUENCE IS THE ONE THE SEED EXISTS TO PREVENT, and this function's
    // own caller says so in writing: *"an in-memory counter alone is not a cap: a
    // redeploy would forgive every dollar accrued this month."* Seeded to zero on
    // every process start, that is exactly what happened. The sub-limit only ever
    // held within a single process lifetime.
    //
    // OBSERVED ON PROD, 2026-08-29, not inferred: with $0.0002856 of durable
    // judge spend and the cap set BELOW it at $0.0001428, a freshly deployed
    // gateway scored instead of refusing. The same test on the PREVIOUS process
    // refused correctly — because that process had accumulated the spend in
    // memory, which is precisely how a broken durable re-seed hides.
    //
    // WHY THE `spans` TWIN WORKS AND THIS DID NOT: `workspace_spend_baseline_from_clickhouse`
    // runs the identical shape against `spans.cost_usd`, which is **`Float64`,
    // NOT Nullable** — verified in `system.columns`. The shape was copied; the
    // column's nullability was not, and nothing about the copy could show that.
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct SumRow {
        usd: Option<f64>,
    }
    // ADR-031 CAPS, at the TIGHTEST tier, via `TenantQuery` — the guard
    // `no-raw-ch-query.sh` requires it and is right to: this is BACKGROUND work
    // on a fire-and-forget path, so it must not be able to out-consume the
    // interactive queries of the same workspace. The query is a single-row
    // aggregate already bounded by tenant and month, so the caps cost nothing
    // and remove the whole class rather than arguing about this one.
    let sql = crate::clickhouse_query::TenantQuery::new(
        "SELECT toFloat64(sum(cost_usd)) AS usd FROM online_eval_scores \
          WHERE tenant_id = ? AND toYYYYMM(scored_at) = toYYYYMM(now())",
        crate::clickhouse_query::PlanTier::Builder,
    )
    .sql_with_settings();
    match crate::clickhouse_query::ch_client(url)
        .query(&sql)
        .bind(job.tenant_id.to_string())
        .fetch_one::<SumRow>()
        .await
    {
        Ok(r) => r.usd.filter(|v| v.is_finite() && *v > 0.0).unwrap_or(0.0),
        // A READ FAILURE IS LOUD NOW. It resolves to 0.0 — the fail-open
        // direction, which is right for a fire-and-forget path that must never
        // block a customer's request — but it is no longer indistinguishable
        // from "this workspace has spent nothing". Seeding 0 when the real
        // total is unknown re-opens the cap for a whole month, so an operator
        // has to be able to see that it happened.
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant_id = %job.tenant_id,
                "online-eval judge spend re-seed FAILED — the monthly sub-limit is \
                 seeded to 0 for this process, so the cap is effectively open until \
                 the next successful read"
            );
            tracelane_shared::degradation::note(
                tracelane_shared::degradation::Degradation::OnlineEvalJudgeFailed,
            );
            0.0
        }
    }
}

#[derive(serde::Serialize, clickhouse::Row)]
struct ScoreInsert<'a> {
    tenant_id: &'a str,
    trace_id: &'a str,
    span_id: &'a str,
    /// **`UUID` in migration 20, and clickhouse-rs will NOT infer that.** Serde's
    /// default for `Uuid` is a 36-char hyphenated STRING, which RowBinary emits
    /// with a varint length prefix where the column expects 16 raw bytes. The
    /// block desynchronises at this field and every field after it is garbage,
    /// so the INSERT fails — for every input, always.
    ///
    /// This is the B-273/B-274 class, FIFTH instance, and it was found here
    /// before it ever ran: `semantic_cache::CacheRow` and
    /// `dataset_routes::DatasetWriteRow` both carry this attribute on their own
    /// UUID columns, and this row was written without it.
    ///
    /// IT WOULD HAVE BEEN INVISIBLE for the same reason B-274 was: `write_score`
    /// returns `Err`, `spawn` folds it into `Degradation::OnlineEvalJudgeFailed`
    /// and one rate-limited WARN — the correct posture for fire-and-forget work
    /// (§10), and precisely why a 100% write failure produces nothing anyone
    /// would read (`docs/reference/TRAPS.md` §46). Sampling would have looked
    /// like it was working and no score would ever have existed.
    #[serde(with = "clickhouse::serde::uuid")]
    policy_id: Uuid,
    rubric: &'a str,
    judge_model: &'a str,
    status: &'a str,
    score: Option<f64>,
    verdict: &'a str,
    reason: &'a str,
    error: Option<String>,
    cost_usd: Option<f64>,
    latency_ms: u32,
    scored_at: i64,
}

async fn write_score(job: &JudgeJob, row: ScoreRow) -> anyhow::Result<()> {
    let Some(url) = job.clickhouse_url.clone() else {
        anyhow::bail!("no ClickHouse url configured — online eval score dropped");
    };
    let tid = job.tenant_id.to_string();
    let trace = job.trace_id.to_string();
    let ch = crate::clickhouse_query::ch_client(url);
    let mut insert = ch.insert("online_eval_scores")?;
    insert
        .write(&ScoreInsert {
            tenant_id: &tid,
            trace_id: &trace,
            span_id: &job.span_id,
            policy_id: job.policy.id,
            rubric: &job.policy.rubric,
            judge_model: &job.policy.judge_model,
            status: &row.status,
            score: row.score,
            verdict: &row.verdict,
            reason: &row.reason,
            error: row.error,
            cost_usd: row.cost_usd,
            latency_ms: row.latency_ms,
            scored_at: crate::clickhouse_query::datetime64_millis_now(),
        })
        .await?;
    insert.end().await?;
    Ok(())
}

/// The REAL-ClickHouse round trip for the score row (R97).
///
/// **A mock stores a struct and hands it back; the BYTES ON THE WIRE are the
/// entire subject, and no mock inspects them.** This module exists because the
/// unit tests above cannot see a RowBinary desynchronisation, and this row
/// shipped with one: `policy_id: Uuid` without
/// `#[serde(with = "clickhouse::serde::uuid")]` writes a 36-char string where
/// the `UUID` column expects 16 raw bytes, and the INSERT fails for every input.
/// That is the B-273/B-274 class, and the failure is swallowed into a
/// degradation counter by design, so nothing downstream would have said so.
///
/// Run: `scripts/ci/run-clickhouse-integration.sh`
#[cfg(test)]
mod clickhouse_roundtrip {
    use super::*;

    #[tokio::test]
    #[ignore = "needs CLICKHOUSE_TEST_URL — run scripts/ci/run-clickhouse-integration.sh"]
    async fn a_score_row_reaches_a_real_clickhouse() {
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
        let sql = include_str!(
            "../../../infra/dev/clickhouse/migrations/20_evl28_online_eval_scores.sql"
        );
        for stmt in crate::clickhouse_query::split_migration_statements(sql) {
            ch.query(&stmt).execute().await.expect("migration 20 stmt");
        }

        let tenant = Uuid::new_v4().to_string();
        let trace = Uuid::new_v4().to_string();
        let policy_id = Uuid::new_v4();
        let mut insert = ch.insert("online_eval_scores").expect("insert init");
        insert
            .write(&ScoreInsert {
                tenant_id: &tenant,
                trace_id: &trace,
                span_id: "span-1",
                policy_id,
                rubric: "answers_the_question",
                judge_model: "claude-haiku-4-5-20251001",
                status: "scored",
                score: Some(0.87),
                verdict: "pass",
                reason: "it answers",
                error: None,
                cost_usd: Some(0.000_123),
                latency_ms: 412,
                scored_at: crate::clickhouse_query::datetime64_millis_now(),
            })
            .await
            .expect("score write must not desynchronise the RowBinary stream");
        insert
            .end()
            .await
            .expect("online_eval_scores insert must complete (B-274 class)");

        // READ IT BACK, and read the fields the surface actually renders. An
        // insert that "completed" while landing garbage in `policy_id` would
        // pass a count-only assertion — the desync is a shifted stream, not
        // always an error, and the count is the one column it cannot corrupt.
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct Back {
            #[serde(with = "clickhouse::serde::uuid")]
            policy_id: Uuid,
            status: String,
            score: Option<f64>,
            verdict: String,
            cost_usd: Option<f64>,
            latency_ms: u32,
        }
        let got = ch
            .query(
                "SELECT policy_id, status, score, verdict, cost_usd, latency_ms \
                   FROM online_eval_scores FINAL WHERE tenant_id = ?",
            )
            .bind(&tenant)
            .fetch_one::<Back>()
            .await
            .expect("the row did not land — a swallowed insert error is still a lost row");
        assert_eq!(got.policy_id, policy_id, "policy_id round-tripped wrong");
        assert_eq!(got.status, "scored");
        assert_eq!(got.score, Some(0.87));
        assert_eq!(got.verdict, "pass");
        assert_eq!(got.cost_usd, Some(0.000_123));
        assert_eq!(got.latency_ms, 412);

        // NULL IS UNKNOWN, NOT ZERO — the property migration 20 was written for,
        // asserted through the real column rather than trusted from the DDL.
        let etrace = Uuid::new_v4().to_string();
        let mut insert = ch.insert("online_eval_scores").expect("insert init");
        insert
            .write(&ScoreInsert {
                tenant_id: &tenant,
                trace_id: &etrace,
                span_id: "span-2",
                policy_id,
                rubric: "answers_the_question",
                judge_model: "claude-haiku-4-5-20251001",
                status: "errored",
                score: None,
                verdict: "",
                reason: "",
                error: Some("judge_schema_invalid".into()),
                cost_usd: None,
                latency_ms: 0,
                scored_at: crate::clickhouse_query::datetime64_millis_now(),
            })
            .await
            .expect("errored write");
        insert.end().await.expect("errored insert");

        #[derive(serde::Deserialize, clickhouse::Row)]
        struct Agg {
            scored: u64,
            errored: u64,
            mean: Option<f64>,
            total_cost: Option<f64>,
        }
        let agg = ch
            .query(
                "SELECT toUInt64(countIf(status='scored')) AS scored, \
                        toUInt64(countIf(status='errored')) AS errored, \
                        avgIf(score, score IS NOT NULL) AS mean, \
                        sum(cost_usd) AS total_cost \
                   FROM online_eval_scores FINAL WHERE tenant_id = ?",
            )
            .bind(&tenant)
            .fetch_one::<Agg>()
            .await
            .expect("summary aggregate — the exact shape /v1/online-evals/summary runs");
        assert_eq!((agg.scored, agg.errored), (1, 1));
        // The errored row contributes NOTHING to either aggregate. If a NULL
        // score were being read as 0.0 the mean would be 0.435, and the surface
        // would render a fabricated grade for a judge that never answered.
        assert_eq!(
            agg.mean,
            Some(0.87),
            "an errored row must not drag the mean"
        );
        assert_eq!(
            agg.total_cost,
            Some(0.000_123),
            "an unpriced row must not be summed as zero"
        );

        // ── THE MONTHLY RE-SEED, which is what makes the cap survive a redeploy.
        //
        // This is the EXACT query and the EXACT row shape `judge_spend_this_month`
        // uses, and it is here because the first version could not have worked:
        // `cost_usd` is `Nullable(Float64)`, so `sum()` over it is Nullable too,
        // and a bare `f64` field made every read fail into a silent `0.0`. The
        // sub-limit was then seeded to zero on every process start — a redeploy
        // forgiving every dollar accrued, which is the one thing the seed exists
        // to prevent.
        //
        // It is asserted through a REAL ClickHouse because that is the only place
        // the defect lives: the types are what disagree, and no mock has types.
        // It has now caught two defects on this one line — the original bare
        // `f64`, and the over-correction that added `ifNull(..., 0)` alongside
        // `Option<f64>` and produced `InvalidTagEncoding(70)` by making the
        // column non-Nullable under a type that still expected a null tag.
        #[derive(serde::Deserialize, clickhouse::Row)]
        struct SumRow {
            usd: Option<f64>,
        }
        let seed = ch
            .query(
                "SELECT toFloat64(sum(cost_usd)) AS usd \
                   FROM online_eval_scores \
                  WHERE tenant_id = ? AND toYYYYMM(scored_at) = toYYYYMM(now())",
            )
            .bind(&tenant)
            .fetch_one::<SumRow>()
            .await
            .expect("the monthly judge-spend re-seed must deserialize (Nullable(Float64))");
        assert_eq!(
            seed.usd,
            Some(0.000_123),
            "the re-seed must return the DURABLE total, not 0 — a 0 here is a cap \
             that a redeploy silently reopens for the rest of the month"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampling_is_deterministic_for_the_same_trace() {
        let t = Uuid::new_v4();
        let a = should_sample("salt-a", t, 0.5);
        for _ in 0..50 {
            assert_eq!(a, should_sample("salt-a", t, 0.5), "same inputs must agree");
        }
    }

    #[test]
    fn the_salt_decorrelates_two_workspaces() {
        // Two policies at the same rate must not score the same trace ids.
        // Not a claim about any single trace — a claim about the SET.
        let traces: Vec<Uuid> = (0..500).map(|_| Uuid::new_v4()).collect();
        let a: Vec<bool> = traces.iter().map(|t| should_sample("A", *t, 0.5)).collect();
        let b: Vec<bool> = traces.iter().map(|t| should_sample("B", *t, 0.5)).collect();
        let agree = a.iter().zip(&b).filter(|(x, y)| x == y).count();
        // Independent 50/50 draws agree ~50% of the time. Identical salts would
        // agree 100%. The band is wide because this asserts DECORRELATION, not a
        // distribution — a tight bound here would be a flaky test.
        assert!(
            (150..=350).contains(&agree),
            "salts did not decorrelate: {agree}/500 agreed"
        );
    }

    #[test]
    fn rate_zero_never_samples_and_rate_one_always_does() {
        for _ in 0..200 {
            let t = Uuid::new_v4();
            assert!(!should_sample("s", t, 0.0));
            assert!(should_sample("s", t, 1.0));
        }
    }

    #[test]
    fn one_percent_lands_near_one_percent() {
        // 20k traces at 1% — the observable that makes "configured vs achieved"
        // meaningful on the surface. A wide band, deliberately: this asserts the
        // hash is not degenerate, not that it is a perfect uniform.
        let hits = (0..20_000)
            .filter(|_| should_sample("salt", Uuid::new_v4(), 0.01))
            .count();
        assert!((100..=320).contains(&hits), "1% of 20000 drew {hits}");
    }
}
