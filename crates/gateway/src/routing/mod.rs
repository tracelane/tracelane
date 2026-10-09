//! `OG-11` — the workspace ROUTING DOCUMENT: virtual models (weighted / priority /
//! latency / cost), several keys per provider (key pools), and the plan a request is
//! dispatched by (`specs/OG-11-weighted-latency-cost-routing.md`). `OG-12` adds
//! conditional rules and canary splits and `OG-13` per-route timeouts and breaker
//! overrides to the SAME document.
//!
//! ## Where it runs
//!
//! - **Write**: `PUT /v1/routing` ([`routes`]) strict-parses the body ([`parse_for_write`],
//!   unknown fields refused) and validates every model, label and price ([`validate`]).
//! - **Read**: the entitlement refresh loads the stored JSON onto
//!   `ResolvedEntitlements::routing` ([`RoutingState::from_stored`]) — never per request.
//!   A stored document this gateway cannot parse is [`RoutingState::Invalid`] and every
//!   request on a wire that consults routing is refused `503 routing_invalid`
//!   (fail-CLOSED: an older gateway must never ignore a document a newer one wrote).
//! - **Admission** (inside `Step::Entitlements`, so before any charge or ledger row):
//!   [`plan`] turns the requested model into an ordered list of concrete candidates, and
//!   [`expand`] makes every control (OG-25 blocks, OG-20 key policy, OG-21 per-model
//!   limits) judge EVERY target — any denied target refuses the request.
//! - **Dispatch**: the handler walks the candidates, re-checking the breaker, kill switch,
//!   ZDR and key policy per hop, and walks each target's key pool ([`pool_labels`]).
//!
//! ## Tenant isolation
//!
//! The document is the tenant's own (`workspace_routing.tenant_id` = the validated
//! claim's tenant); a pool names LABELS of the tenant's own keys; key resolution is
//! `(tenant, provider, label)` end to end. Nothing here can select another tenant's key.

pub(crate) mod attempt;
pub(crate) mod conditions;
pub(crate) mod deadlines;
pub(crate) mod relay;
pub(crate) mod routes;
pub(crate) mod stats;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Reference-table limits (CLAUDE.md §23) ──────────────────────────────────

/// The `routing` block of `translation_policy.v1.json`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Limits {
    pub max_virtual_models: usize,
    pub max_targets_per_model: usize,
    pub max_pool_keys_per_provider: usize,
    pub max_attempts: usize,
    pub ewma_alpha: f64,
    pub min_samples: u32,
    pub explore_ratio: f64,
    pub stats_max_entries: usize,
    /// A latency-stats entry not observed for this long is evicted (MED round 2).
    pub stats_idle_evict_secs: u64,
    pub doc_max_bytes: usize,
}

fn parse_limits(raw: &str) -> Option<Limits> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let r = v.get("routing")?;
    let n = |k: &str| {
        r.get(k)
            .and_then(Value::as_u64)
            .filter(|n| *n >= 1)
            .and_then(|n| usize::try_from(n).ok())
    };
    let f = |k: &str| {
        r.get(k)
            .and_then(Value::as_f64)
            .filter(|x| *x > 0.0 && *x < 1.0)
    };
    Some(Limits {
        max_virtual_models: n("max_virtual_models")?,
        max_targets_per_model: n("max_targets_per_model")?,
        max_pool_keys_per_provider: n("max_pool_keys_per_provider")?,
        max_attempts: n("max_attempts")?,
        ewma_alpha: f("ewma_alpha")?,
        min_samples: u32::try_from(n("min_samples")?).ok()?,
        explore_ratio: f("explore_ratio")?,
        stats_max_entries: n("stats_max_entries")?,
        stats_idle_evict_secs: u64::try_from(n("stats_idle_evict_secs")?).ok()?,
        doc_max_bytes: n("doc_max_bytes")?,
    })
}

/// The routing limits, parsed once. A table that does not parse yields the SMALLEST
/// sane document (no virtual model, one attempt): routing writes then refuse almost
/// everything, which is the fail-CLOSED reading of a broken edit on a control surface.
/// A unit test makes that a red build, not a runtime surprise.
pub(crate) fn limits() -> &'static Limits {
    static L: OnceLock<Limits> = OnceLock::new();
    L.get_or_init(|| {
        parse_limits(include_str!("../../translation_policy.v1.json")).unwrap_or_else(|| {
            tracing::warn!(
                "translation_policy.v1.json routing block did not parse — routing documents are refused"
            );
            Limits {
                max_virtual_models: 0,
                max_targets_per_model: 0,
                max_pool_keys_per_provider: 0,
                max_attempts: 1,
                ewma_alpha: 0.5,
                min_samples: u32::MAX,
                explore_ratio: 0.5,
                stats_max_entries: 0,
                stats_idle_evict_secs: 1,
                doc_max_bytes: 0,
            }
        })
    })
}

// ── The document ────────────────────────────────────────────────────────────

/// How a virtual model (or a key pool) orders its targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Strategy {
    /// Declared order; the rest are fallbacks.
    #[default]
    Priority,
    /// One target drawn by weight, then the rest in declared order.
    Weighted,
    /// Lowest in-process EWMA time-to-first-byte; cold targets by priority.
    Latency,
    /// Lowest estimated `cost_usd` for the request's estimated tokens.
    Cost,
}

impl Strategy {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::Weighted => "weighted",
            Self::Latency => "latency",
            Self::Cost => "cost",
        }
    }
}

/// One concrete target of a virtual model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub model: String,
    /// `weighted` only; 1..=1000, absent = 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

/// A virtual model: a workspace-defined name that resolves to ordered concrete targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VirtualModel {
    #[serde(default)]
    pub strategy: Strategy,
    pub targets: Vec<Target>,
}

/// One key of a provider's pool — a LABEL of the tenant's own stored key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PoolKey {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

/// Several keys for one provider: a 401/403/429 on one moves to the next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyPool {
    pub provider: String,
    #[serde(default)]
    pub strategy: Strategy,
    pub keys: Vec<PoolKey>,
}

/// The whole routing document, strict-parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoutingDoc {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<conditions::Rule>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub virtual_models: BTreeMap<String, VirtualModel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_pools: Vec<KeyPool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeouts: Vec<deadlines::Rule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breaker: Option<deadlines::BreakerOverride>,
}

/// What the entitlement cache holds for one workspace.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum RoutingState {
    /// No document (no row, no control plane, bench).
    #[default]
    None,
    Valid(Arc<RoutingDoc>),
    /// A stored document this gateway cannot parse: routed requests are refused.
    Invalid,
}

impl RoutingState {
    /// The stored JSON → the hot-path state. Pure.
    #[must_use]
    pub(crate) fn from_stored(doc: Option<&Value>) -> Self {
        match doc {
            None => Self::None,
            Some(v) => match serde_json::from_value::<RoutingDoc>(v.clone()) {
                Ok(d)
                    if deadlines::validate(&d).is_err()
                        || conditions::validate(&d, true).is_err() =>
                {
                    Self::Invalid
                }
                Ok(d) if d == RoutingDoc::default() => Self::None,
                Ok(d) => Self::Valid(Arc::new(d)),
                Err(_) => Self::Invalid,
            },
        }
    }

    fn doc(&self) -> Option<&RoutingDoc> {
        match self {
            Self::Valid(d) => Some(d),
            _ => None,
        }
    }
}

// ── Write validation ─────────────────────────────────────────────────────────

/// One write refusal: `400 invalid_field` / `invalid_target`, naming the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldError {
    pub code: &'static str,
    pub field: String,
    pub message: String,
}

fn field(field: impl Into<String>, message: impl Into<String>) -> FieldError {
    FieldError {
        code: "invalid_field",
        field: field.into(),
        message: message.into(),
    }
}

fn target_err(field: impl Into<String>, message: impl Into<String>) -> FieldError {
    FieldError {
        code: "invalid_target",
        field: field.into(),
        message: message.into(),
    }
}

/// Strict-parse a write body's `doc`. An unknown field anywhere is a `400 invalid_field`
/// naming serde's own description — never silently dropped.
///
/// # Errors
/// The parse failure, as a field error on `doc`.
pub(crate) fn parse_for_write(raw: &Value) -> Result<RoutingDoc, FieldError> {
    if !raw.is_object() {
        return Err(field("doc", "the routing document must be a JSON object"));
    }
    let bytes = serde_json::to_vec(raw).map_or(usize::MAX, |b| b.len());
    if bytes > limits().doc_max_bytes {
        return Err(field(
            "doc",
            format!(
                "the routing document is {bytes} bytes; the most is {}",
                limits().doc_max_bytes
            ),
        ));
    }
    if let Some(rules) = raw.get("rules") {
        let rules = rules
            .as_array()
            .ok_or_else(|| conditions::invalid(0, "rules must be an array"))?;
        for (i, rule) in rules.iter().enumerate() {
            serde_json::from_value::<conditions::Rule>(rule.clone())
                .map_err(|e| conditions::invalid(i, e.to_string()))?;
        }
    }
    serde_json::from_value::<RoutingDoc>(raw.clone()).map_err(|e| field("doc", e.to_string()))
}

/// What a write is validated against — the tenant's own state, read by the route.
pub(crate) struct WriteContext<'a> {
    /// The workspace's GWY-27 aliases.
    pub aliases: &'a BTreeMap<String, String>,
    /// Every `(provider_id, label)` the tenant holds a key for.
    pub labels: &'a [(String, String)],
}

/// The provider a concrete model routes to (operator alias first, then the registry).
fn provider_of(model: &str) -> Option<&'static str> {
    crate::providers::ProviderRegistry::provider_id_for_model(model)
}

fn priced(model: &str) -> bool {
    matches!(
        crate::admission::token_pricing(model),
        crate::admission::Pricing::Priced
    )
}

/// An embedding model, by name — vector dimensions must not change mid-index, so a
/// virtual model over embedding models may have exactly one target.
fn is_embedding_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("embed")
}

fn weight_ok(w: Option<u32>) -> bool {
    w.is_none_or(|w| (1..=1000).contains(&w))
}

/// Every write refusal of `OG-11` §4, in document order.
///
/// # Errors
/// The first field that fails.
pub(crate) fn validate(doc: &RoutingDoc, ctx: &WriteContext<'_>) -> Result<(), FieldError> {
    deadlines::validate(doc)?;
    conditions::validate(doc, false)?;
    let l = limits();
    if doc.virtual_models.len() > l.max_virtual_models {
        return Err(field(
            "virtual_models",
            format!("at most {} virtual models", l.max_virtual_models),
        ));
    }
    for (name, vm) in &doc.virtual_models {
        let at = format!("virtual_models.{name}");
        if !crate::db::model_aliases::valid_alias(name) {
            return Err(field(
                &at,
                "a virtual model name must start with a letter or digit and use only letters, digits and . _ : / - (max 64)",
            ));
        }
        if provider_of(name).is_some() || crate::server::config::alias(name).is_some() {
            return Err(field(
                &at,
                format!(
                    "`{name}` is already a routable model name — a virtual model must not shadow one"
                ),
            ));
        }
        if ctx.aliases.contains_key(name) {
            return Err(field(
                &at,
                format!("`{name}` is one of your model aliases — pick another name"),
            ));
        }
        if vm.targets.is_empty() || vm.targets.len() > l.max_targets_per_model {
            return Err(field(
                format!("{at}.targets"),
                format!("1 to {} targets", l.max_targets_per_model),
            ));
        }
        let mut seen = BTreeSet::new();
        for (i, t) in vm.targets.iter().enumerate() {
            let tat = format!("{at}.targets[{i}]");
            if !seen.insert(t.model.as_str()) {
                return Err(target_err(&tat, format!("`{}` is listed twice", t.model)));
            }
            if doc.virtual_models.contains_key(&t.model) {
                return Err(target_err(
                    &tat,
                    "a target cannot be another virtual model (no nesting)",
                ));
            }
            if ctx.aliases.contains_key(&t.model) {
                return Err(target_err(
                    &tat,
                    format!(
                        "`{}` is one of your aliases — list the model it points at",
                        t.model
                    ),
                ));
            }
            if provider_of(&t.model).is_none() {
                return Err(target_err(
                    &tat,
                    format!("`{}` does not route to any provider", t.model),
                ));
            }
            if !weight_ok(t.weight) {
                return Err(field(format!("{tat}.weight"), "weight must be 1 to 1000"));
            }
            if vm.strategy == Strategy::Cost && !priced(&t.model) {
                return Err(target_err(
                    &tat,
                    format!(
                        "`{}` has no price, and the `cost` strategy orders targets by price",
                        t.model
                    ),
                ));
            }
        }
        if vm.targets.len() > 1 && vm.targets.iter().any(|t| is_embedding_model(&t.model)) {
            return Err(target_err(
                format!("{at}.targets"),
                "a virtual model over embedding models must have exactly one target — vector dimensions must not change mid-index",
            ));
        }
    }
    let mut providers = BTreeSet::new();
    for (i, pool) in doc.key_pools.iter().enumerate() {
        let at = format!("key_pools[{i}]");
        if !providers.insert(pool.provider.as_str()) {
            return Err(field(
                format!("{at}.provider"),
                format!("`{}` has two pools", pool.provider),
            ));
        }
        if !crate::byok_api::provider_keys_api::known_provider(&pool.provider) {
            return Err(field(
                format!("{at}.provider"),
                format!("`{}` is not a provider", pool.provider),
            ));
        }
        if !matches!(pool.strategy, Strategy::Priority | Strategy::Weighted) {
            return Err(field(
                format!("{at}.strategy"),
                "a key pool orders its keys by `priority` or `weighted` — one model, so latency and cost cannot tell keys apart",
            ));
        }
        if pool.keys.is_empty() || pool.keys.len() > l.max_pool_keys_per_provider {
            return Err(field(
                format!("{at}.keys"),
                format!("1 to {} keys", l.max_pool_keys_per_provider),
            ));
        }
        let mut labels = BTreeSet::new();
        for (j, k) in pool.keys.iter().enumerate() {
            let kat = format!("{at}.keys[{j}]");
            if !labels.insert(k.label.as_str()) {
                return Err(field(&kat, format!("`{}` is listed twice", k.label)));
            }
            if !ctx
                .labels
                .iter()
                .any(|(p, lab)| p == &pool.provider && lab == &k.label)
            {
                return Err(field(
                    &kat,
                    format!(
                        "no `{}` key labelled `{}` is stored — add it first (POST /v1/byok/provider-keys)",
                        pool.provider, k.label
                    ),
                ));
            }
            if !weight_ok(k.weight) {
                return Err(field(format!("{kat}.weight"), "weight must be 1 to 1000"));
            }
        }
    }
    Ok(())
}

/// Is `name` a virtual model of the stored document? (The alias writer refuses an alias
/// that would shadow one.)
#[must_use]
pub(crate) fn is_virtual(state: &RoutingState, name: &str) -> bool {
    state
        .doc()
        .is_some_and(|d| d.virtual_models.contains_key(name))
}

// ── Wire scopes (compile-enforced through `admission::Route::ROUTING`) ──────────

/// Which wire a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wire {
    Chat,
    Responses,
    Messages,
    Gemini,
    Embeddings,
    Media,
    Realtime,
    Files,
    Batches,
    Passthrough,
}

impl Wire {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
            Self::Messages => "messages",
            Self::Gemini => "gemini",
            Self::Embeddings => "embeddings",
            Self::Media => "media",
            Self::Realtime => "realtime",
            Self::Files => "files",
            Self::Batches => "batches",
            Self::Passthrough => "passthrough",
        }
    }
}

/// What a wire may do with a virtual model (`OG-11` §2, the wire table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VirtualSupport {
    /// Refused: `400 virtual_model_unroutable_on_wire`.
    No,
    /// Any provider (chat, responses).
    AnyProvider,
    /// Only targets of the wire's own provider (a native relay: messages, gemini).
    OwnProvider(&'static str),
    /// Exactly one concrete target (embeddings: dimensions must not change).
    SingleTarget,
}

/// Which keys a wire may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolSupport {
    /// `default` only — provider objects are account-scoped (files, batches, passthrough).
    DefaultOnly,
    /// The provider's pool.
    Pool,
    /// The pool, chosen once at session start (realtime).
    SessionStart,
}

/// One route's routing capabilities — a REQUIRED const of `admission::Route`, so a new
/// route cannot forget to declare them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoutingScope {
    pub wire: Wire,
    pub virtual_models: VirtualSupport,
    pub key_pool: PoolSupport,
    /// A 5xx / timeout moves to the next target.
    pub fallthrough: bool,
    /// Realtime has its own session bounds; every other wire enforces transport phases.
    pub timeouts: bool,
}

impl RoutingScope {
    /// Does this wire consult the routing document at all?
    #[must_use]
    pub(crate) const fn consults_routing(&self) -> bool {
        self.timeouts
            || !matches!(self.virtual_models, VirtualSupport::No)
            || !matches!(self.key_pool, PoolSupport::DefaultOnly)
    }
}

// ── The plan ─────────────────────────────────────────────────────────────────

/// One concrete dispatch candidate.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Candidate {
    pub model: String,
    pub provider_id: &'static str,
    /// Its index in the virtual model's declared target list.
    pub target_index: usize,
    /// `weight / Σ weights` of the surviving targets (`weighted`), for `simulate`.
    pub weight_pct: Option<f64>,
    /// The smoothed time-to-first-byte, when warm (`latency`), for `simulate`.
    pub ewma_ttfb_ms: Option<f64>,
}

/// A target dropped while planning, recorded on the attempt ledger as a skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanSkip {
    pub provider: String,
    pub model: String,
    pub reason: &'static str,
}

/// How a request will be dispatched.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RoutePlan {
    /// The model the caller sent.
    pub requested: String,
    pub virtual_model: Option<String>,
    pub strategy: Option<Strategy>,
    /// Dispatch order.
    pub candidates: Vec<Candidate>,
    pub skipped: Vec<PlanSkip>,
    /// Every name a control must judge — the candidates' models plus any target
    /// dropped while planning (a block on an unpriced target still refuses).
    pub policy_targets: Vec<String>,
    pub policy_aliases: Vec<String>,
    pub assignment: Option<conditions::Assignment>,
}

impl RoutePlan {
    pub(crate) fn dispatches(&self) -> bool {
        self.virtual_model.is_some() || self.assignment.is_some()
    }
    pub(crate) fn cache_namespace(&self) -> Option<&str> {
        self.assignment
            .as_ref()
            .and_then(|a| a.namespace.as_deref())
    }

    pub(crate) fn skipped_attempts(&self) -> Vec<tracelane_shared::DispatchAttempt> {
        self.skipped
            .iter()
            .map(|s| tracelane_shared::DispatchAttempt {
                key_label: None,
                attempt: 0,
                provider: s.provider.clone(),
                model: s.model.clone(),
                outcome: "skipped".to_owned(),
                status: None,
                reason: Some(s.reason.to_owned()),
                took_ms: 0,
            })
            .collect()
    }
}

/// Routed failures advance the pool or target exactly once per attempt. The
/// legacy same-key retry remains for requests that routing did not touch.
pub(crate) fn retry_policy(
    config: Option<&crate::server::config::FailoverConfig>,
    routed: bool,
) -> crate::providers::failover::RetryPolicy {
    let mut policy = crate::providers::failover::retry_policy(config);
    if routed {
        policy.retries = 0;
    }
    policy
}

/// Why a plan could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlanError {
    /// The stored document did not parse: `503 routing_invalid`.
    RoutingInvalid,
    IdentityRequired,
    /// A virtual model on a wire that cannot serve it: `400
    /// virtual_model_unroutable_on_wire`.
    UnroutableOnWire {
        model: String,
        why: &'static str,
    },
    /// Every target was dropped while planning (`cost` with no priced target left).
    NoCandidate {
        model: String,
    },
}

impl PlanError {
    /// The admission refusal for this error, rendered by the route on its own wire.
    #[must_use]
    pub(crate) fn into_refusal(self) -> crate::admission::Refusal {
        match self {
            Self::IdentityRequired => crate::admission::Refusal::Malformed(crate::admission::Malformed {
                code: "canary_identity_required", message: "this route requires a sticky identity".to_owned(), detail: None,
            }),
            Self::RoutingInvalid => crate::admission::Refusal::Control(
                crate::admission::ControlDenial {
                    status: 503,
                    code: "routing_invalid",
                    message: "this workspace's routing document could not be read by this gateway, so routed requests are refused — an owner can correct it with PUT /v1/routing".to_owned(),
                    detail: vec![],
                    retry_after_secs: None,
                },
            ),
            Self::UnroutableOnWire { model, why } => {
                crate::admission::Refusal::Malformed(crate::admission::Malformed {
                    code: "virtual_model_unroutable_on_wire",
                    message: format!(
                        "`{}` is a virtual model, and this endpoint cannot serve it: {why}",
                        model.chars().take(128).collect::<String>()
                    ),
                    detail: None,
                })
            }
            Self::NoCandidate { model } => {
                crate::admission::Refusal::Malformed(crate::admission::Malformed {
                    code: "no_routable_target",
                    message: format!(
                        "no target of the virtual model `{}` can be dispatched (none is priced for the `cost` strategy)",
                        model.chars().take(128).collect::<String>()
                    ),
                    detail: None,
                })
            }
        }
    }
}

/// The request facts the strategies order with: the cost strategy's token estimate and
/// the latency strategy's stats OWNER.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Estimate {
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// The tenant whose latency stats the latency strategy (and `simulate`) reads — M1
    /// (security review, 2026-10-05): never another tenant's. `None` = no stats (cold).
    pub owner: Option<uuid::Uuid>,
}

/// A source of randomness: the weighted draw and the latency strategy's exploration.
/// Injected so a test can fix the sequence (`OG-11` §7 proofs 1 and 7).
pub(crate) type Rng<'a> = &'a mut (dyn FnMut() -> u64 + Send);

/// Process RNG: a thread-local xorshift64* seeded once from the OS. Not a security
/// value — it only spreads traffic across targets the caller is allowed to reach.
pub(crate) fn thread_rng() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static S: Cell<u64> = Cell::new({
            use ring::rand::SecureRandom as _;
            let mut b = [0u8; 8];
            let _ = ring::rand::SystemRandom::new().fill(&mut b);
            u64::from_le_bytes(b) | 1
        });
    }
    S.with(|s| {
        let mut x = s.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    })
}

/// Order `targets` by `strategy`. Returns the dispatch order (indices into `targets`)
/// and, for `cost`, the indices dropped as unpriced.
fn order(
    strategy: Strategy,
    targets: &[Target],
    est: Estimate,
    rng: Rng<'_>,
) -> (Vec<usize>, Vec<usize>) {
    let all: Vec<usize> = (0..targets.len()).collect();
    match strategy {
        Strategy::Priority => (all, Vec::new()),
        Strategy::Weighted => {
            let weights: Vec<u64> = targets
                .iter()
                .map(|t| u64::from(t.weight.unwrap_or(1)))
                .collect();
            let total: u64 = weights.iter().sum();
            if total == 0 {
                return (all, Vec::new());
            }
            let r = rng() % total;
            let mut acc = 0;
            let mut pick = 0;
            for (i, w) in weights.iter().enumerate() {
                acc += w;
                if r < acc {
                    pick = i;
                    break;
                }
            }
            let mut out = vec![pick];
            out.extend(all.into_iter().filter(|i| *i != pick));
            (out, Vec::new())
        }
        Strategy::Latency => {
            let l = limits();
            let explore = (rng() % 10_000) < (l.explore_ratio * 10_000.0) as u64;
            let mut keyed: Vec<(bool, f64, usize)> = targets
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let warm = provider_of(&t.model)
                        .and_then(|p| stats::get(est.owner.as_ref(), p, &t.model))
                        .filter(|(_, n)| *n >= l.min_samples);
                    match warm {
                        Some((ms, _)) => (false, ms, i),
                        None => (true, 0.0, i),
                    }
                })
                .collect();
            keyed.sort_by(|a, b| {
                (a.0, a.1, a.2)
                    .partial_cmp(&(b.0, b.1, b.2))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let mut out: Vec<usize> = keyed.into_iter().map(|k| k.2).collect();
            if explore && out.len() > 1 {
                let pick = usize::try_from(rng() % out.len() as u64).unwrap_or(0);
                let chosen = out.remove(pick);
                out.insert(0, chosen);
            }
            (out, Vec::new())
        }
        Strategy::Cost => {
            let usage = tracelane_shared::Usage {
                input_tokens: u32::try_from(est.input_tokens).unwrap_or(u32::MAX),
                output_tokens: u32::try_from(est.output_tokens).unwrap_or(u32::MAX),
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
            };
            let mut priced_ix: Vec<(f64, usize)> = Vec::new();
            let mut dropped = Vec::new();
            for (i, t) in targets.iter().enumerate() {
                let alias = crate::server::config::alias(&t.model);
                match crate::pricing::cost_usd_for_routed_model(&t.model, alias, &usage) {
                    Some(c) => priced_ix.push((c, i)),
                    None => dropped.push(i),
                }
            }
            priced_ix.sort_by(|a, b| {
                (a.0, a.1)
                    .partial_cmp(&(b.0, b.1))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            (priced_ix.into_iter().map(|(_, i)| i).collect(), dropped)
        }
    }
}

/// Does planning `requested` need the request's token estimate (a `cost` virtual
/// model)? Lets admission skip computing it for everything else.
#[must_use]
pub(crate) fn needs_estimate(state: &RoutingState, requested: &str) -> bool {
    state.doc().is_some_and(|d| {
        d.virtual_models
            .values()
            .any(|v| v.strategy == Strategy::Cost)
            && (d.virtual_models.contains_key(requested) || !d.rules.is_empty())
    })
}

/// The plan for `requested` on `scope`'s wire, or `None` when routing does not apply
/// (no document, or the name is not one of its virtual models) — the request then
/// dispatches exactly as before OG-11.
///
/// # Errors
/// Fail-CLOSED: an unparseable stored document on a wire that consults routing; a
/// virtual model the wire cannot serve; a virtual model with no dispatchable target.
pub(crate) fn plan(
    scope: &RoutingScope,
    requested: &str,
    state: &RoutingState,
    est: Estimate,
    rng: Rng<'_>,
) -> Result<Option<RoutePlan>, PlanError> {
    let doc = match state {
        RoutingState::None => return Ok(None),
        RoutingState::Invalid => {
            return if scope.consults_routing() {
                Err(PlanError::RoutingInvalid)
            } else {
                Ok(None)
            };
        }
        RoutingState::Valid(d) => d,
    };
    let Some(vm) = doc.virtual_models.get(requested) else {
        return Ok(None);
    };
    let unroutable = |why| PlanError::UnroutableOnWire {
        model: requested.to_owned(),
        why,
    };
    match scope.virtual_models {
        VirtualSupport::No => {
            return Err(unroutable(
                "virtual models are served on chat, responses, messages, gemini and embeddings only",
            ));
        }
        VirtualSupport::SingleTarget if vm.targets.len() != 1 => {
            return Err(unroutable(
                "embeddings take a virtual model with exactly one target — vector dimensions must not change mid-index",
            ));
        }
        VirtualSupport::OwnProvider(p)
            if vm.targets.iter().any(|t| provider_of(&t.model) != Some(p)) =>
        {
            return Err(unroutable(
                "this endpoint relays one provider's own wire, and a target of this virtual model belongs to another provider — use POST /v1/chat/completions",
            ));
        }
        _ => {}
    }
    let (ordered, dropped) = order(vm.strategy, &vm.targets, est, rng);
    let mut skipped: Vec<PlanSkip> = Vec::new();
    for i in dropped {
        let t = &vm.targets[i];
        skipped.push(PlanSkip {
            provider: provider_of(&t.model).unwrap_or("unknown").to_owned(),
            model: t.model.clone(),
            reason: "unpriced",
        });
    }
    let total_weight: u64 = ordered
        .iter()
        .map(|i| u64::from(vm.targets[*i].weight.unwrap_or(1)))
        .sum();
    let mut candidates = Vec::with_capacity(ordered.len());
    for i in ordered {
        let t = &vm.targets[i];
        // A target that stopped routing since the write is skipped, never defaulted.
        let Some(provider_id) = provider_of(&t.model) else {
            skipped.push(PlanSkip {
                provider: "unknown".to_owned(),
                model: t.model.clone(),
                reason: "unroutable",
            });
            continue;
        };
        candidates.push(Candidate {
            model: t.model.clone(),
            provider_id,
            target_index: i,
            weight_pct: (vm.strategy == Strategy::Weighted && total_weight > 0)
                .then(|| f64::from(t.weight.unwrap_or(1)) * 100.0 / total_weight as f64),
            ewma_ttfb_ms: (vm.strategy == Strategy::Latency)
                .then(|| stats::get(est.owner.as_ref(), provider_id, &t.model))
                .flatten()
                .filter(|(_, n)| *n >= limits().min_samples)
                .map(|(ms, _)| ms),
        });
    }
    if candidates.is_empty() {
        return Err(PlanError::NoCandidate {
            model: requested.to_owned(),
        });
    }
    let policy_targets = vm.targets.iter().map(|t| t.model.clone()).collect();
    Ok(Some(RoutePlan {
        requested: requested.to_owned(),
        virtual_model: Some(requested.to_owned()),
        strategy: Some(vm.strategy),
        candidates,
        skipped,
        policy_targets,
        policy_aliases: vec![],
        assignment: None,
    }))
}

// ── Key pools ────────────────────────────────────────────────────────────────

/// The labels to try for `provider_id`, in order, and whether a pool chose them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PoolChoice {
    pub labels: Vec<String>,
    /// A pool is defined for this provider (the span then records `tracelane_key_label`).
    pub pooled: bool,
}

/// The key labels to try for `provider_id` on `scope`'s wire. No document, no pool for
/// the provider, or a `default`-only wire → `["default"]`, exactly as before OG-11.
#[must_use]
pub(crate) fn pool_labels(
    scope: &RoutingScope,
    state: &RoutingState,
    provider_id: &str,
    rng: Rng<'_>,
) -> PoolChoice {
    let default = || PoolChoice {
        labels: vec![crate::db::provider_keys::DEFAULT_LABEL.to_owned()],
        pooled: false,
    };
    if scope.key_pool == PoolSupport::DefaultOnly {
        return default();
    }
    let Some(pool) = state
        .doc()
        .and_then(|d| d.key_pools.iter().find(|p| p.provider == provider_id))
    else {
        return default();
    };
    let targets: Vec<Target> = pool
        .keys
        .iter()
        .map(|k| Target {
            model: k.label.clone(),
            weight: k.weight,
        })
        .collect();
    let (ordered, _) = order(pool.strategy, &targets, Estimate::default(), rng);
    PoolChoice {
        labels: ordered
            .into_iter()
            .map(|i| pool.keys[i].label.clone())
            .collect(),
        pooled: true,
    }
}

/// `OG-11`: the first usable key of `provider_id`'s pool for a wire that takes ONE key
/// per call (count_tokens, input_tokens, media, a realtime session): the first label
/// whose key resolves (non-empty unless the provider is keyless). `ProviderKey::Found`
/// or the pool's failure — the same answers a single `default` key gives.
pub(crate) async fn first_pool_key(
    scope: &RoutingScope,
    state: &RoutingState,
    tenant_id: &tracelane_shared::TenantId,
    provider_id: &str,
) -> (crate::server::ProviderKey, Option<String>) {
    use secrecy::ExposeSecret as _;
    let mut rng = thread_rng;
    let choice = pool_labels(scope, state, provider_id, &mut rng);
    let pooled = choice.pooled;
    let env = crate::providers::ProviderRegistry::env_var_for_provider_id(provider_id);
    let mut cursor = crate::server::KeyCursor::new(choice.labels);
    while let Some((label, k)) = cursor.next_key(tenant_id, provider_id, env).await {
        if !k.expose_secret().is_empty() || env.is_empty() {
            return (
                crate::server::ProviderKey::Found(k),
                pooled.then_some(label),
            );
        }
    }
    (cursor.into_failure(), None)
}

/// Is a dispatch error a KEY failure (the next pool key may succeed): 401, 403, 429?
#[must_use]
pub(crate) fn is_key_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<crate::providers::ProviderHttpError>()
        .is_some_and(|h| matches!(h.status, 401 | 403 | 429))
}

/// [`is_key_failure`] for a relay wire that sees the bare upstream status.
#[must_use]
pub(crate) fn is_key_failure_status(status: u16) -> bool {
    matches!(status, 401 | 403 | 429)
}

// ── Controls bind every target ───────────────────────────────────────────────

/// `OG-11` §2 "Controls bind every target": replace the request's model subject with
/// one subject per policy target of the plan, so a block, a key-policy deny or allow
/// rule and a per-model limit are judged on ALL of them (any denied target refuses).
/// Only the first carries the token facts, so a TPM reservation is not multiplied.
/// No plan → the request unchanged.
#[must_use]
pub(crate) fn expand(
    mut request: tracelane_shared::key_policy::PolicyRequest,
    plan: Option<&RoutePlan>,
) -> tracelane_shared::key_policy::PolicyRequest {
    use tracelane_shared::key_policy::{Fact, Subject};
    let Some(plan) = plan.filter(|p| !p.policy_targets.is_empty()) else {
        return request;
    };
    let Some(first) = request.subjects.first().cloned() else {
        return request;
    };
    if !matches!(first.model, Fact::Known(_)) {
        return request;
    }
    let mut subjects = Vec::with_capacity(plan.policy_targets.len());
    for (i, t) in plan.policy_targets.iter().enumerate() {
        let mut s = if i == 0 {
            first.clone()
        } else {
            Subject {
                input_tokens: Fact::NotApplicable,
                output_cap: Fact::NotApplicable,
                ..first.clone()
            }
        };
        s.model = Fact::Known(t.clone());
        s.workspace_alias = !plan.dispatches() && t == &plan.requested && first.workspace_alias;
        // The provider each TARGET routes to — never the wire's fixed provider.
        s.provider = None;
        subjects.push(s);
    }
    request.subjects.splice(0..1, subjects);
    request
}

/// `H2` for a routed request: every policy target must be priced for a budgeted caller
/// (the gateway cannot know in advance which target serves). The first unpriced one
/// refuses, named.
#[must_use]
pub(crate) fn pricing(
    plan: &RoutePlan,
    entitlements: Option<&crate::entitlement_cache::ResolvedEntitlements>,
) -> crate::admission::Pricing {
    for t in &plan.policy_targets {
        let pricing = if !plan.dispatches() && t == &plan.requested {
            crate::admission::token_pricing_after_workspace_alias(t, entitlements)
        } else {
            crate::admission::token_pricing(t)
        };
        if let p @ crate::admission::Pricing::Unpriced { .. } = pricing {
            return p;
        }
    }
    crate::admission::Pricing::Priced
}

#[cfg(test)]
mod tests {
    #[test]
    fn og13_timeout_document_accepts_all_four_phases() {
        let parsed = super::parse_for_write(&serde_json::json!({
            "timeouts": [{"match": {"provider": "openai", "model": "gpt-4*"},
                "headers_ms": 8000, "first_chunk_ms": 15000,
                "idle_ms": 20000, "total_ms": 120000}],
            "breaker": {"consecutive_failures": 3, "cooldown_secs": 20}
        }));
        assert!(
            parsed.is_ok(),
            "OG-13 timeout document must be accepted: {parsed:?}"
        );
    }

    use super::*;

    pub(crate) fn doc(v: Value) -> RoutingDoc {
        serde_json::from_value(v).expect("test doc parses")
    }

    fn chat_scope() -> RoutingScope {
        RoutingScope {
            wire: Wire::Chat,
            virtual_models: VirtualSupport::AnyProvider,
            key_pool: PoolSupport::Pool,
            fallthrough: true,
            timeouts: true,
        }
    }

    fn counter() -> impl FnMut() -> u64 {
        let mut n = 0u64;
        move || {
            let v = n;
            n += 1;
            v
        }
    }

    #[test]
    fn the_routing_block_of_the_reference_table_parses() {
        let l = parse_limits(include_str!("../../translation_policy.v1.json"))
            .expect("the routing block parses — a broken edit is a red build");
        assert_eq!(l.max_virtual_models, 64);
        assert_eq!(l.max_targets_per_model, 16);
        assert_eq!(l.max_pool_keys_per_provider, 8);
        assert_eq!(l.max_attempts, 3);
        assert_eq!(l.min_samples, 5);
        assert_eq!(l.doc_max_bytes, 65_536);
    }

    /// `OG-11` proof 1: weighted 7:3 over 2 000 requests with an injected RNG — exact
    /// counts at the expected ratio; the other target is always the fallback.
    #[test]
    fn og11_proof1_weighted_seven_to_three_exact_counts() {
        let state = RoutingState::Valid(Arc::new(doc(serde_json::json!({
            "virtual_models": {"fast": {"strategy": "weighted", "targets": [
                {"model": "gpt-4o-mini", "weight": 7}, {"model": "claude-haiku-4-5", "weight": 3}
            ]}}
        }))));
        let mut rng = counter();
        let (mut a, mut b) = (0, 0);
        for _ in 0..2_000 {
            let p = plan(&chat_scope(), "fast", &state, Estimate::default(), &mut rng)
                .expect("plans")
                .expect("routed");
            assert_eq!(p.candidates.len(), 2, "the other target is the fallback");
            match p.candidates[0].model.as_str() {
                "gpt-4o-mini" => a += 1,
                _ => b += 1,
            }
        }
        assert_eq!((a, b), (1_400, 600));
    }

    /// Priority keeps declared order; an unknown name and no document are untouched.
    #[test]
    fn og11_priority_order_and_unrouted_names_pass_through() {
        let state = RoutingState::Valid(Arc::new(doc(serde_json::json!({
            "virtual_models": {"safe": {"targets": [
                {"model": "claude-haiku-4-5"}, {"model": "gpt-4o-mini"}
            ]}}
        }))));
        let mut rng = counter();
        let p = plan(&chat_scope(), "safe", &state, Estimate::default(), &mut rng)
            .unwrap()
            .unwrap();
        assert_eq!(p.candidates[0].model, "claude-haiku-4-5");
        assert_eq!(p.candidates[0].provider_id, "anthropic");
        assert_eq!(p.policy_targets, vec!["claude-haiku-4-5", "gpt-4o-mini"]);
        assert!(
            plan(
                &chat_scope(),
                "gpt-4o",
                &state,
                Estimate::default(),
                &mut rng
            )
            .unwrap()
            .is_none()
        );
        assert!(
            plan(
                &chat_scope(),
                "safe",
                &RoutingState::None,
                Estimate::default(),
                &mut rng
            )
            .unwrap()
            .is_none()
        );
    }

    /// `OG-11` proof 4 (planning half): the wire table.
    #[test]
    fn og11_proof4_the_wire_table_refuses_what_a_wire_cannot_serve() {
        let state = RoutingState::Valid(Arc::new(doc(serde_json::json!({
            "virtual_models": {
                "mixed": {"targets": [{"model": "gpt-4o-mini"}, {"model": "claude-haiku-4-5"}]},
                "claudes": {"targets": [{"model": "claude-haiku-4-5"}, {"model": "claude-sonnet-4-5"}]},
                "vec": {"targets": [{"model": "text-embedding-3-small"}]}
            }
        }))));
        let mut rng = counter();
        let messages = RoutingScope {
            wire: Wire::Messages,
            virtual_models: VirtualSupport::OwnProvider("anthropic"),
            key_pool: PoolSupport::Pool,
            fallthrough: true,
            timeouts: true,
        };
        assert!(matches!(
            plan(&messages, "mixed", &state, Estimate::default(), &mut rng),
            Err(PlanError::UnroutableOnWire { .. })
        ));
        assert!(
            plan(&messages, "claudes", &state, Estimate::default(), &mut rng)
                .unwrap()
                .is_some()
        );
        let embeddings = RoutingScope {
            wire: Wire::Embeddings,
            virtual_models: VirtualSupport::SingleTarget,
            key_pool: PoolSupport::Pool,
            fallthrough: false,
            timeouts: true,
        };
        assert!(
            plan(&embeddings, "vec", &state, Estimate::default(), &mut rng)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            plan(&embeddings, "mixed", &state, Estimate::default(), &mut rng),
            Err(PlanError::UnroutableOnWire { .. })
        ));
        let media = RoutingScope {
            wire: Wire::Media,
            virtual_models: VirtualSupport::No,
            key_pool: PoolSupport::Pool,
            fallthrough: false,
            timeouts: true,
        };
        assert!(matches!(
            plan(&media, "claudes", &state, Estimate::default(), &mut rng),
            Err(PlanError::UnroutableOnWire { .. })
        ));
        let files = RoutingScope {
            wire: Wire::Files,
            virtual_models: VirtualSupport::No,
            key_pool: PoolSupport::DefaultOnly,
            fallthrough: false,
            timeouts: true,
        };
        assert_eq!(
            plan(
                &files,
                "x",
                &RoutingState::Invalid,
                Estimate::default(),
                &mut rng
            ),
            Err(PlanError::RoutingInvalid),
            "default-only keys still consult the document's timeout rules"
        );
        assert_eq!(
            plan(
                &chat_scope(),
                "x",
                &RoutingState::Invalid,
                Estimate::default(),
                &mut rng
            ),
            Err(PlanError::RoutingInvalid),
            "an unparseable document refuses routed wires (fail-CLOSED)"
        );
    }

    /// `OG-11` proof 6 (cost half): the cheaper target first.
    #[test]
    fn og11_proof6_cost_orders_by_estimated_price() {
        let state = RoutingState::Valid(Arc::new(doc(serde_json::json!({
            "virtual_models": {"cheap": {"strategy": "cost", "targets": [
                {"model": "gpt-4o"}, {"model": "gpt-4o-mini"}
            ]}}
        }))));
        let mut rng = counter();
        let p = plan(
            &chat_scope(),
            "cheap",
            &state,
            Estimate {
                input_tokens: 1_000,
                output_tokens: 500,
                owner: None,
            },
            &mut rng,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p.candidates[0].model, "gpt-4o-mini");
        assert_eq!(p.candidates[1].model, "gpt-4o");
    }

    /// Key pools: priority order, weighted draw, `default` when there is none, and a
    /// default-only wire never reads the pool.
    #[test]
    fn og11_pool_labels_follow_the_pool_and_default_otherwise() {
        let state = RoutingState::Valid(Arc::new(doc(serde_json::json!({
            "key_pools": [{"provider": "openai", "keys": [{"label": "team-a"}, {"label": "team-b"}]}]
        }))));
        let mut rng = counter();
        let c = pool_labels(&chat_scope(), &state, "openai", &mut rng);
        assert_eq!(c.labels, vec!["team-a", "team-b"]);
        assert!(c.pooled);
        let d = pool_labels(&chat_scope(), &state, "anthropic", &mut rng);
        assert_eq!(d.labels, vec!["default"]);
        assert!(!d.pooled);
        let files = RoutingScope {
            wire: Wire::Files,
            virtual_models: VirtualSupport::No,
            key_pool: PoolSupport::DefaultOnly,
            fallthrough: false,
            timeouts: true,
        };
        assert_eq!(
            pool_labels(&files, &state, "openai", &mut rng).labels,
            vec!["default"],
            "files/batches/passthrough ignore the pool (account-scoped objects)"
        );
    }

    /// `OG-11` §4: write refusals.
    #[test]
    fn og11_write_validation_refuses_each_bad_shape() {
        let aliases = BTreeMap::from([("fast-alias".to_owned(), "gpt-4o".to_owned())]);
        let labels = vec![
            ("openai".to_owned(), "default".to_owned()),
            ("openai".to_owned(), "team-b".to_owned()),
        ];
        let ctx = WriteContext {
            aliases: &aliases,
            labels: &labels,
        };
        let ok = doc(serde_json::json!({
            "virtual_models": {"fast": {"strategy": "weighted", "targets": [
                {"model": "gpt-4o-mini", "weight": 7}, {"model": "claude-haiku-4-5", "weight": 3}]}},
            "key_pools": [{"provider": "openai", "keys": [{"label": "default"}, {"label": "team-b"}]}]
        }));
        assert_eq!(validate(&ok, &ctx), Ok(()));
        let refused = |v: Value| validate(&doc(v), &ctx).expect_err("refused");
        assert_eq!(
            refused(serde_json::json!({"virtual_models": {"gpt-4o": {"targets": [{"model": "gpt-4o-mini"}]}}})).field,
            "virtual_models.gpt-4o",
            "a routable name"
        );
        assert_eq!(
            refused(serde_json::json!({"virtual_models": {"fast-alias": {"targets": [{"model": "gpt-4o-mini"}]}}})).field,
            "virtual_models.fast-alias",
            "an alias name"
        );
        assert_eq!(
            refused(serde_json::json!({"virtual_models": {"a": {"targets": [{"model": "b"}]}, "b": {"targets": [{"model": "gpt-4o"}]}}})).code,
            "invalid_target",
            "nesting"
        );
        assert_eq!(
            refused(serde_json::json!({"virtual_models": {"a": {"targets": [{"model": "no-such-model-xyz"}]}}})).code,
            "invalid_target",
            "unroutable"
        );
        assert_eq!(
            refused(
                serde_json::json!({"virtual_models": {"a": {"targets": [{"model": "fast-alias"}]}}})
            )
            .code,
            "invalid_target",
            "a target that is an alias"
        );
        assert_eq!(
            refused(serde_json::json!({"virtual_models": {"v": {"targets": [{"model": "text-embedding-3-small"}, {"model": "text-embedding-3-large"}]}}})).code,
            "invalid_target",
            "two embedding models"
        );
        assert_eq!(
            refused(serde_json::json!({"key_pools": [{"provider": "openai", "keys": [{"label": "nope"}]}]})).field,
            "key_pools[0].keys[0]",
            "an unknown label"
        );
        assert_eq!(
            refused(serde_json::json!({"virtual_models": {"a": {"strategy": "weighted", "targets": [{"model": "gpt-4o", "weight": 0}]}}})).field,
            "virtual_models.a.targets[0].weight"
        );
        assert!(
            parse_for_write(&serde_json::json!({"virtual_models": {}, "surprise": 1})).is_err(),
            "unknown fields are refused, never dropped"
        );
    }

    /// `OG-11` proof 5 (controls half): every target becomes a subject; only the first
    /// carries the token facts.
    #[test]
    fn og11_proof5_expand_puts_every_target_in_front_of_the_controls() {
        use tracelane_shared::key_policy::{Fact, PolicyRequest, Subject};
        let req = PolicyRequest {
            subjects: vec![Subject {
                line: None,
                model: Fact::Known("fast".into()),
                workspace_alias: true,
                provider: None,
                input_tokens: Fact::Known(100),
                output_cap: Fact::Known(Some(50)),
            }],
            body_bytes: Fact::Known(10),
        };
        let plan = RoutePlan {
            requested: "fast".into(),
            virtual_model: Some("fast".into()),
            strategy: Some(Strategy::Priority),
            candidates: vec![],
            skipped: vec![],
            policy_targets: vec!["gpt-4o-mini".into(), "claude-haiku-4-5".into()],
            policy_aliases: vec![],
            assignment: None,
        };
        let out = expand(req.clone(), Some(&plan));
        assert_eq!(out.subjects.len(), 2);
        assert_eq!(out.subjects[0].model, Fact::Known("gpt-4o-mini".into()));
        assert_eq!(out.subjects[0].input_tokens, Fact::Known(100));
        assert_eq!(
            out.subjects[1].model,
            Fact::Known("claude-haiku-4-5".into())
        );
        assert_eq!(out.subjects[1].input_tokens, Fact::NotApplicable);
        assert_eq!(expand(req.clone(), None), req);
    }

    #[test]
    fn the_stored_state_is_valid_invalid_or_none() {
        assert_eq!(RoutingState::from_stored(None), RoutingState::None);
        assert_eq!(
            RoutingState::from_stored(Some(&serde_json::json!({}))),
            RoutingState::None
        );
        assert_eq!(
            RoutingState::from_stored(Some(&serde_json::json!({"rules_from_the_future": []}))),
            RoutingState::Invalid,
            "a field this gateway does not know makes the document INVALID, never ignored"
        );
    }
}
