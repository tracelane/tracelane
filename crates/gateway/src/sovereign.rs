//! `GWY-80` — sovereign routing: a request that carries regulated data reaches only the
//! operator's own model endpoint (`specs/GWY-80-sovereign-routing.md`).
//!
//! ## The control, in one paragraph
//!
//! The operator names, in `tracelane.yaml`, which OpenAI-compatible providers are THEIR
//! endpoints (each re-pointed with its `<PROVIDER>_BASE_URL`), the model a regulated
//! request is moved to, and the data classes that count as regulated. Before the chat
//! handler picks a provider, the request is classified with the same detector rail R2
//! uses. A request carrying a configured class is CONFINED: it is moved to the sovereign
//! model (when it named another), the routing document, cross-provider failover, the
//! semantic cache tier and the online-eval judge are switched off for it, and every
//! dispatch it makes passes [`Egress::permits`] — the one check `dispatch_with_retry`
//! cannot be called without. A confined request whose sovereign target does not resolve
//! is refused; it is never sent to a frontier provider instead (§10 fail-CLOSED).
//!
//! ## What it confines, and what it does not
//!
//! It confines MODEL DISPATCHES: where the request is sent to be answered. Per-workspace
//! guardrail vendor hooks (Lakera, Azure, Bedrock, Model Armor, Presidio, TypeSafe) and MCP
//! servers need the control plane, which a `sovereign:` block refuses at boot, so they are
//! unavailable in this mode rather than a leak. The one off-model text egress that does not
//! need a control plane is the prompt-guard sidecar (`PROMPT_GUARD_URL`), which is sent recent
//! messages of every chat request before classification; boot refuses it unless it is a
//! loopback host. The classifier is a safety net for honest callers, not a defence against a
//! caller who deliberately disguises regulated data (`specs/GWY-80-sovereign-routing.md` §6).
//!
//! ## What is pure here
//!
//! Everything. [`classify`], [`decide`], [`Egress::permits`], [`wire_refused`] and
//! [`SovereignConfig::build`] / [`SovereignConfig::check_boot`] take their inputs as
//! arguments (the model resolver and the environment are injected), so every state is a
//! unit test and the invariant sweep at the bottom covers every combination.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::bail;
use serde_json::Value;

/// The data classes the detector can name — a CLOSED vocabulary, derived from
/// `tracelane_policy::pii` (its rule categories, folded by [`class_of`]). Listed in
/// severity order: the first one present is the request's recorded `data_class`.
/// A class with no detector (IBAN) is deliberately absent: accepting it would
/// let an operator configure a protection that can never fire.
pub(crate) const CLASSES: &[&str] = &[
    "secret",
    "credit_card",
    "ssn",
    "email",
    "phone",
    "ip_address",
];

/// Content the detector could not read: an oversized text payload, or binary media (an
/// image, a PDF, audio) the walker does not decode. It cannot be cleared, so a request carrying one is ALWAYS confined, whatever `classes:` says.
/// Not configurable, by design: a correctness parameter is not a user setting.
pub(crate) const UNSCANNABLE: &str = "unscannable";

/// What the span records for a request the block examined and found nothing in.
pub(crate) const NONE: &str = "none";

/// Severity order used to pick the ONE recorded class (unscannable sits after the three
/// classes whose disclosure is a breach on its own).
const SEVERITY: &[&str] = &[
    "secret",
    "credit_card",
    "ssn",
    UNSCANNABLE,
    "email",
    "phone",
    "ip_address",
];

/// The parsed, validated `sovereign:` block of `tracelane.yaml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovereignConfig {
    providers: Arc<BTreeSet<String>>,
    model: String,
    classes: BTreeSet<&'static str>,
}

impl SovereignConfig {
    /// Build from the raw block values.
    ///
    /// # Errors
    ///
    /// Fails CLOSED (the file then refuses to load and the gateway refuses to boot) on:
    /// an empty or duplicate provider; a provider that is not an OpenAI-compatible
    /// catalog row (the six native adapters reach their vendor's own host and cannot be
    /// re-pointed, so they can never be the operator's endpoint); an empty `model`; an
    /// unknown, duplicate or empty class.
    pub fn build(providers: &str, model: &str, classes: Option<&str>) -> anyhow::Result<Self> {
        let mut set = BTreeSet::new();
        for p in providers.split(',').map(str::trim) {
            if p.is_empty() {
                bail!("`sovereign.providers` has an empty entry");
            }
            if crate::providers::catalog::by_id(p).is_none() {
                bail!(
                    "`sovereign.providers`: `{p}` is not an OpenAI-compatible catalog provider \
                     — only a provider whose base URL can be re-pointed at your own endpoint \
                     can be sovereign"
                );
            }
            if !set.insert(p.to_owned()) {
                bail!("`sovereign.providers` lists `{p}` twice");
            }
        }
        let model = model.trim();
        if model.is_empty() {
            bail!("`sovereign.model` is empty");
        }
        let classes = match classes {
            // Omitted ⇒ every class: the most restrictive reading of an unstated policy.
            None => CLASSES.iter().copied().collect(),
            Some(raw) => {
                let mut out = BTreeSet::new();
                for c in raw.split(',').map(str::trim) {
                    let Some(known) = CLASSES.iter().copied().find(|k| *k == c) else {
                        bail!(
                            "`sovereign.classes`: `{c}` is not a class the detector can name \
                             (one of: {})",
                            CLASSES.join(", ")
                        );
                    };
                    if !out.insert(known) {
                        bail!("`sovereign.classes` lists `{c}` twice");
                    }
                }
                out
            }
        };
        Ok(Self {
            providers: Arc::new(set),
            model: model.to_owned(),
            classes,
        })
    }

    /// The boot-time half of the validation: the parts that depend on the installed
    /// model map and on the process environment, injected so the check is testable.
    ///
    /// # Errors
    ///
    /// Fails CLOSED (refuse to boot) when the sovereign `model` does not resolve, through
    /// the SAME canonical resolver the chat handler uses, to a sovereign provider; or when
    /// a sovereign provider's `<PROVIDER>_BASE_URL` is unset, blank or still the catalog
    /// default — a provider still pointed at its vendor's host is not the operator's own.
    pub fn check_boot(
        &self,
        resolve: impl Fn(&str) -> Option<&'static str>,
        env: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()> {
        // A single-tenant self-host control. With a control plane (hosted, multi-tenant) one
        // operator block would decide where EVERY tenant's regulated data goes. The signal
        // list is the self-host guard's own, and a variable that is SET counts even when
        // empty — the Postgres pool init treats it the same way (`server.rs`), so a block
        // can never boot where a pool would.
        for var in tracelane_shared::self_host::MULTI_TENANT_SIGNAL_ENVS {
            if env(var).is_some() {
                bail!(
                    "a `sovereign:` block is a single-tenant self-host control and cannot run \
                     with a control plane or hosted identity (`{var}` is set)"
                );
            }
        }
        // The prompt-guard sidecar is sent up to 8 recent messages of EVERY chat request
        // before classification, so it must be on this machine.
        if let Some(raw) = env("PROMPT_GUARD_URL").filter(|v| !v.trim().is_empty()) {
            let loopback = reqwest::Url::parse(raw.trim()).is_ok_and(|u| {
                u.host_str().is_some_and(|h| {
                    let h = h.trim_start_matches('[').trim_end_matches(']');
                    h.eq_ignore_ascii_case("localhost")
                        || h.parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                })
            });
            if !loopback {
                bail!(
                    "`PROMPT_GUARD_URL` must point at this machine (a loopback host) while a \
                     `sovereign:` block is on: the sidecar receives recent request text before \
                     classification"
                );
            }
        }
        match resolve(&self.model) {
            Some(p) if self.is_sovereign(p) => {}
            Some(p) => bail!(
                "`sovereign.model` `{}` resolves to `{p}`, which is not in `sovereign.providers`",
                self.model
            ),
            None => bail!(
                "`sovereign.model` `{}` does not resolve to any provider",
                self.model
            ),
        }
        for p in self.providers.iter() {
            let Some(def) = crate::providers::catalog::by_id(p) else {
                bail!("`sovereign.providers`: `{p}` is not a catalog provider");
            };
            match env(def.base_url_env) {
                Some(url) if !url.trim().is_empty() => {
                    let Ok(set) = reqwest::Url::parse(url.trim()) else {
                        bail!("`{}` is not a URL", def.base_url_env);
                    };
                    if same_endpoint(&set, def.base_url_default) {
                        bail!(
                            "sovereign provider `{p}` must be re-pointed at your own endpoint: \
                             `{}` is still the default `{}`",
                            def.base_url_env,
                            def.base_url_default
                        );
                    }
                }
                _ => bail!(
                    "sovereign provider `{p}` must be re-pointed at your own endpoint: set \
                     `{}` (it is unset or still the default `{}`)",
                    def.base_url_env,
                    def.base_url_default
                ),
            }
        }
        Ok(())
    }

    /// Is `provider_id` one of the operator's own endpoints?
    #[must_use]
    pub fn is_sovereign(&self, provider_id: &str) -> bool {
        self.providers.contains(provider_id)
    }

    /// The sovereign providers, for the startup log line.
    pub fn providers(&self) -> impl Iterator<Item = &str> {
        self.providers.iter().map(String::as_str)
    }

    /// The model a regulated request is moved to.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
}

/// Is `set` the same endpoint as the catalog default `default`? Host (lower-cased by the
/// parser) and effective port only: a different scheme or path on the default host is
/// still the default endpoint, not the operator's own.
fn same_endpoint(set: &reqwest::Url, default: &str) -> bool {
    let Ok(d) = reqwest::Url::parse(default) else {
        return false;
    };
    set.host_str() == d.host_str() && set.port_or_known_default() == d.port_or_known_default()
}

/// Fold a detector category into the closed class vocabulary.
fn class_of(category: &str) -> Option<&'static str> {
    if tracelane_policy::pii::is_secret_category(category) {
        return Some("secret");
    }
    match category {
        "credit_card" => Some("credit_card"),
        "ssn" => Some("ssn"),
        "email" => Some("email"),
        "phone" => Some("phone"),
        "ipv4" | "ipv6" => Some("ip_address"),
        _ => None,
    }
}

/// The classes found in one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Found(BTreeSet<&'static str>);

impl Found {
    #[cfg(test)]
    pub(crate) fn of(classes: &[&'static str]) -> Self {
        Self(classes.iter().copied().collect())
    }
}

/// Classify a request body: every text leaf the egress walker hands R2 (message text,
/// tool definitions and arguments, `response_format`, keys, decoded text media), run
/// through the R2 detector. Runs on the request BEFORE any guardrail rewrites it, and
/// independently of whether R2 is granted to the workspace or what mode it is in: a
/// restriction is never a paid grant (`.claude/rules/tenancy.md` forbids the opposite
/// direction only).
pub(crate) fn classify(body: &Value) -> Found {
    let mut found = BTreeSet::new();
    // Binary media (an image, a PDF, audio) is content the text detector cannot read: it may
    // carry a card number in pixels or speech. It is never Clear (fail-CLOSED).
    let mut binary = false;
    crate::guardrail::egress::egress_leaves_reporting(
        body,
        &mut |leaf, _| {
            match leaf {
                crate::guardrail::egress::Leaf::Text(t) => {
                    if tracelane_policy::pii::contains_redactable(t) {
                        for e in tracelane_policy::pii::redact_reversible(t).entries {
                            if let Some(c) = class_of(e.category) {
                                found.insert(c);
                            }
                        }
                    }
                }
                crate::guardrail::egress::Leaf::Unscannable => {
                    found.insert(UNSCANNABLE);
                }
            }
            false // never stop early: the recorded class is the most severe one present
        },
        &mut || binary = true,
    );
    if binary {
        found.insert(UNSCANNABLE);
    }
    Found(found)
}

/// Classify a typed request. A request that cannot be re-serialised cannot be cleared,
/// so it classifies as [`UNSCANNABLE`] (fail-CLOSED).
pub(crate) fn classify_request(request: &tracelane_shared::ChatRequest) -> Found {
    match serde_json::to_value(request) {
        Ok(v) => classify(&v),
        Err(_) => Found([UNSCANNABLE].into_iter().collect()),
    }
}

/// What the block decided for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// No `sovereign:` block: nothing changes and nothing is recorded.
    Off,
    /// The block is installed and the request carries no configured class.
    Clear,
    /// A configured class is present: only sovereign providers may serve it.
    Confine {
        class: &'static str,
        /// The model to dispatch: the caller's when it already resolves to a sovereign
        /// provider, otherwise the block's `model`.
        model: String,
        provider: &'static str,
        rerouted: bool,
    },
    /// A configured class is present and no sovereign target resolves. Refuse.
    Refuse { class: &'static str },
}

/// The decision. `resolve` is the canonical model→provider map
/// (`ProviderRegistry::provider_id_for_model` in production).
pub(crate) fn decide(
    cfg: Option<&SovereignConfig>,
    found: &Found,
    requested_model: &str,
    resolve: impl Fn(&str) -> Option<&'static str>,
) -> Decision {
    let Some(cfg) = cfg else {
        return Decision::Off;
    };
    let regulated = SEVERITY
        .iter()
        .copied()
        .find(|c| found.0.contains(c) && (*c == UNSCANNABLE || cfg.classes.contains(c)));
    let Some(class) = regulated else {
        return Decision::Clear;
    };
    if let Some(p) = resolve(requested_model).filter(|p| cfg.is_sovereign(p)) {
        return Decision::Confine {
            class,
            model: requested_model.to_owned(),
            provider: p,
            rerouted: false,
        };
    }
    match resolve(&cfg.model).filter(|p| cfg.is_sovereign(p)) {
        Some(p) => Decision::Confine {
            class,
            model: cfg.model.clone(),
            provider: p,
            rerouted: true,
        },
        None => Decision::Refuse { class },
    }
}

/// Where a request's dispatches may go. Passed to EVERY `dispatch_with_retry` call, so
/// a dispatch site added later cannot compile without saying which.
#[derive(Debug, Clone)]
pub(crate) enum Egress {
    /// Unconfined traffic: any provider the rest of the pipeline allows.
    Any,
    /// A confined request: only these providers.
    SovereignOnly(Arc<BTreeSet<String>>),
}

impl Egress {
    /// The egress a decision implies.
    pub(crate) fn for_decision(cfg: Option<&SovereignConfig>, d: &Decision) -> Self {
        match (cfg, d) {
            (Some(cfg), Decision::Confine { .. } | Decision::Refuse { .. }) => {
                Self::SovereignOnly(Arc::clone(&cfg.providers))
            }
            _ => Self::Any,
        }
    }

    /// The egress of a server-side dispatch whose text was never classified (a prompt-eval
    /// case or judge, the online-eval judge, the Responses translator). While a `sovereign:`
    /// block is installed it may go NOWHERE — those paths are refused rather than trusted;
    /// without one it is unchanged.
    pub(crate) fn unclassified(cfg: Option<&SovereignConfig>) -> Self {
        match cfg {
            Some(_) => Self::SovereignOnly(Arc::new(BTreeSet::new())),
            None => Self::Any,
        }
    }

    /// May a dispatch to `provider_id` (the canonical resolver's answer for the model
    /// being dispatched; `None` = unroutable) leave the gateway? A confined request:
    /// only to a sovereign provider, and never to an unresolved one.
    #[must_use]
    pub(crate) fn permits(&self, provider_id: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::SovereignOnly(set) => provider_id.is_some_and(|p| set.contains(p)),
        }
    }

    /// Is this request confined?
    #[must_use]
    pub(crate) fn confined(&self) -> bool {
        matches!(self, Self::SovereignOnly(_))
    }
}

/// What the span records (`tracelane_routing_*`). `None` on the span when the block is
/// not installed, so a deployment without it emits byte-identical spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Meta {
    pub data_class: &'static str,
    pub sovereign: bool,
    pub endpoint: Option<&'static str>,
    pub rerouted: bool,
}

impl Meta {
    pub(crate) fn of(d: &Decision) -> Option<Self> {
        match d {
            Decision::Off => None,
            Decision::Clear => Some(Self {
                data_class: NONE,
                sovereign: false,
                endpoint: None,
                rerouted: false,
            }),
            Decision::Confine {
                class,
                provider,
                rerouted,
                ..
            } => Some(Self {
                data_class: class,
                sovereign: true,
                endpoint: Some(provider),
                rerouted: *rerouted,
            }),
            Decision::Refuse { class } => Some(Self {
                data_class: class,
                sovereign: true,
                endpoint: None,
                rerouted: false,
            }),
        }
    }

    pub(crate) fn apply(&self, attrs: &mut tracelane_shared::span::SpanAttributes) {
        attrs.extra.insert(
            "tracelane_routing_data_class".to_owned(),
            serde_json::json!(self.data_class),
        );
        attrs.extra.insert(
            "tracelane_routing_sovereign".to_owned(),
            serde_json::json!(self.sovereign),
        );
        if let Some(e) = self.endpoint {
            attrs.extra.insert(
                "tracelane_routing_endpoint".to_owned(),
                serde_json::json!(e),
            );
        }
        if self.rerouted {
            attrs.extra.insert(
                "tracelane_routing_rerouted".to_owned(),
                serde_json::json!(true),
            );
        }
    }
}

/// The ONLY paths that pass the wire gate while a `sovereign:` block is installed:
/// the one confined model wire, plus routes that send no text to a model provider (liveness,
/// metrics, the API description, the caller's own identity, and trace ingest/read, which talk
/// to the gateway's own store). Everything else is refused (`403 sovereign_wire_unsupported`):
/// a deny-list fails open for every wire added later, an allow-list fails closed. A wire is
/// added HERE only after its text is classified by [`classify`] or it provably sends none.
const ALLOWED_EXACT: &[&str] = &[
    "/v1/chat/completions",
    "/health",
    "/metrics",
    "/v1/openapi.json",
    "/v1/auth/whoami",
    "/v1/traces",
    "/v1/traces/count",
    "/v1/traces/groups",
];

/// Is `path` refused by the gate? True for everything not in [`ALLOWED_EXACT`] (a single
/// trailing slash is ignored; the router would not match it anyway).
#[must_use]
pub(crate) fn wire_refused(path: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    !ALLOWED_EXACT.contains(&path)
}

/// Axum middleware: with a `sovereign:` block installed, refuse every model-egress
/// wire this slice does not classify. Without one: one comparison, then through. The block
/// is the layer's STATE (`AppState::sovereign`), so a test can drive the real gate with or
/// without one.
pub(crate) async fn wire_gate(
    axum::extract::State(block): axum::extract::State<Option<&'static SovereignConfig>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if block.is_some() && wire_refused(req.uri().path()) {
        return wire_refused_response();
    }
    next.run(req).await
}

/// Mount [`wire_gate`] on `app`. Called once in `server::run`, AFTER the last route merge: a
/// layer only wraps the routes merged before it, so a route merged later would bypass it
/// (`server.rs` `sovereign_wire_gate_follows_the_last_route_merge`).
pub(crate) fn with_wire_gate(
    app: axum::Router,
    block: Option<&'static SovereignConfig>,
) -> axum::Router {
    app.layer(axum::middleware::from_fn_with_state(block, wire_gate))
}

/// A dispatch refused HERE because the sovereign block does not permit it. A local decision
/// taken before any byte left: it says nothing about any provider's health, so the circuit
/// breaker is fed nothing for it (`dispatch::transport_outcome`).
#[derive(Debug)]
pub(crate) struct SovereignRefused(pub(crate) String);

impl std::fmt::Display for SovereignRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sovereign_egress_refused: {}", self.0)
    }
}
impl std::error::Error for SovereignRefused {}

/// The typed refusal for a wire the block does not cover.
pub(crate) fn wire_refused_response() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": {
                "code": "sovereign_wire_unsupported",
                "message": "This gateway confines regulated data to your own model endpoint, \
                            and only /v1/chat/completions is checked. Send model traffic \
                            through /v1/chat/completions.",
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
#[path = "sovereign_tests.rs"]
mod tests;
