//! `OG-20` — per-key (and per-project, `OG-23`) policy: the document, its parser, and the
//! pure evaluation the gateway runs at authentication and at admission.
//!
//! **Why it lives in `shared`.** The gateway's `db/` modules are also compiled into the
//! real-Postgres integration crate by `#[path]` and can only reach `tracelane_shared`; the
//! auth SELECT parses the stored document ONCE, into the cached auth entry, so the parser
//! must be reachable from `db/api_keys.rs`. Everything here is pure (no I/O, no clock).
//!
//! **The one authority for the vocabulary** (migration 0057's comment points here): the
//! database checks only that a stored policy is a JSON object.
//!
//! # Semantics (spec `specs/OG-20-per-key-policy.md` §2)
//!
//! * **Intersection, not override.** A key in a project carries up to two [`Layer`]s —
//!   the project's and its own — and EVERY layer must pass. A key can narrow its project;
//!   it can never widen it.
//! * **Fail-CLOSED on a document that does not parse** (unknown fields included: a rule
//!   this build does not understand cannot be enforced, so it is not ignored): the layer
//!   is [`LayerPolicy::Invalid`] and every request on the key is refused `policy_invalid`.
//! * **A rule a route cannot evaluate refuses** (`policy_unenforceable`) — a fact the
//!   route reports as [`Fact::Unknown`]. [`Fact::NotApplicable`] (embeddings have no
//!   output tokens) passes.
//! * **Absent policy = today's behaviour**: no `Governance` at all, or one with no layers.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Deserialize;
use serde_json::{Value, json};

/// The write-side bounds (the `key_policy` block of the gateway's reference table,
/// `crates/gateway/translation_policy.v1.json`). The READ side never applies them: a
/// stored document that was valid when written stays enforceable if a bound is lowered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteLimits {
    pub max_patterns: usize,
    pub max_pattern_chars: usize,
    pub max_cidrs: usize,
    pub max_required_keys: usize,
    /// `OG-21`: entries in `limits.per_model`.
    pub max_per_model_limits: usize,
    /// `OG-22`/`OG-24`: entries in each of a budget's `alert_at_percent` / `alert_at_usd`.
    pub max_alert_thresholds: usize,
}

/// Token caps are `1 ..= MAX_TOKEN_CAP` (a Postgres `int4`'s positive range: the cap is
/// compared with provider `max_tokens` fields, all 32-bit).
pub const MAX_TOKEN_CAP: u64 = i32::MAX as u64;
/// `max_body_bytes` is `1 ..= MAX_BODY_CAP` (1 TiB — larger than any route accepts).
pub const MAX_BODY_CAP: u64 = 1 << 40;
/// `OG-21`: an `rpm` is `1 ..= MAX_RPM`.
pub const MAX_RPM: u64 = 10_000_000;
/// `OG-21`: a `tpm` is `1 ..= MAX_TPM`.
pub const MAX_TPM: u64 = 10_000_000_000;
/// `OG-22`: a budget's `usd` is `> 0 ..= MAX_BUDGET_USD`.
pub const MAX_BUDGET_USD: f64 = 1_000_000_000.0;
/// `OG-24`: an `alert_at_percent` entry is `1 ..= MAX_ALERT_PERCENT`.
pub const MAX_ALERT_PERCENT: u32 = 1000;

/// One refused field of a policy document: the dotted path and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub field: String,
    pub message: String,
}

impl PolicyError {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

// ── The wire document ────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    #[serde(default)]
    models: Option<ListsDoc>,
    #[serde(default)]
    providers: Option<ListsDoc>,
    #[serde(default)]
    source_ips: Option<Vec<String>>,
    #[serde(default)]
    max_input_tokens: Option<u64>,
    #[serde(default)]
    max_output_tokens: Option<u64>,
    #[serde(default)]
    max_body_bytes: Option<u64>,
    #[serde(default)]
    required_tags: Option<Vec<String>>,
    #[serde(default)]
    required_metadata_keys: Option<Vec<String>>,
    #[serde(default)]
    limits: Option<LimitsDoc>,
    #[serde(default)]
    budget: Option<BudgetDoc>,
    #[serde(default)]
    end_user_budget: Option<BudgetDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RateDoc {
    #[serde(default)]
    rpm: Option<u64>,
    #[serde(default)]
    tpm: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRateDoc {
    model: String,
    #[serde(default)]
    rpm: Option<u64>,
    #[serde(default)]
    tpm: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsDoc {
    #[serde(default)]
    rpm: Option<u64>,
    #[serde(default)]
    tpm: Option<u64>,
    #[serde(default)]
    per_end_user: Option<RateDoc>,
    #[serde(default)]
    per_model: Option<Vec<ModelRateDoc>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetDoc {
    usd: f64,
    #[serde(default)]
    window: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    alert_at_percent: Option<Vec<u32>>,
    #[serde(default)]
    alert_at_usd: Option<Vec<f64>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListsDoc {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

/// An allow / deny pair. `allow` empty = no allow-list (everything not denied).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lists {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// One IPv4 or IPv6 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

/// A parsed, validated policy. Patterns and provider ids are stored lower-case (matching
/// is ASCII case-insensitive), lists de-duplicated in first-seen order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyPolicy {
    pub models: Option<Lists>,
    pub providers: Option<Lists>,
    pub source_ips: Vec<Cidr>,
    pub max_input_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub max_body_bytes: Option<u64>,
    pub required_tags: Vec<String>,
    pub required_metadata_keys: Vec<String>,
    /// `OG-21`: RPM / TPM limits this layer imposes.
    pub limits: Option<Limits>,
    /// `OG-22`: this layer's own USD budget.
    pub budget: Option<Budget>,
    /// `OG-22`: a USD budget per end user, inside this layer.
    pub end_user_budget: Option<Budget>,
}

// ── OG-21 limits / OG-22 budgets ─────────────────────────────────────────────

/// A per-minute rate: requests and / or tokens. At least one is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rate {
    pub rpm: Option<u64>,
    pub tpm: Option<u64>,
}

/// One `limits.per_model` entry: every model the `model` glob matches shares ONE bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRate {
    /// Lower-cased `OG-20` glob.
    pub model: String,
    pub rate: Rate,
}

/// `OG-21`: a layer's limits. Every applicable bucket must have room (AND).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Limits {
    /// The layer's own bucket(s): every request the layer governs.
    pub rate: Rate,
    /// One bucket per end user, inside the layer.
    pub per_end_user: Option<Rate>,
    /// One bucket per pattern, inside the layer.
    pub per_model: Vec<ModelRate>,
}

/// `OG-22`: the window a budget's spend is summed over (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetWindow {
    Daily,
    Weekly,
    Monthly,
    Rolling1h,
    Rolling24h,
    Rolling7d,
    Rolling30d,
}

impl BudgetWindow {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Rolling1h => "rolling_1h",
            Self::Rolling24h => "rolling_24h",
            Self::Rolling7d => "rolling_7d",
            Self::Rolling30d => "rolling_30d",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "daily" => Self::Daily,
            "weekly" => Self::Weekly,
            "monthly" => Self::Monthly,
            "rolling_1h" => Self::Rolling1h,
            "rolling_24h" => Self::Rolling24h,
            "rolling_7d" => Self::Rolling7d,
            "rolling_30d" => Self::Rolling30d,
            _ => return None,
        })
    }

    /// The window's length in hours when it is ROLLING; `None` for a calendar window.
    #[must_use]
    pub fn rolling_hours(self) -> Option<u32> {
        match self {
            Self::Rolling1h => Some(1),
            Self::Rolling24h => Some(24),
            Self::Rolling7d => Some(24 * 7),
            Self::Rolling30d => Some(24 * 30),
            Self::Daily | Self::Weekly | Self::Monthly => None,
        }
    }
}

/// `OG-22`: refuse at the ceiling (`hard`) or only alert (`soft`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetMode {
    Hard,
    Soft,
}

impl BudgetMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hard => "hard",
            Self::Soft => "soft",
        }
    }
}

/// `OG-22`: one USD budget. Money is integer micro-USD (`Eq`, and the unit the gateway's
/// spend tracker counts in).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub micro_usd: u64,
    pub window: BudgetWindow,
    pub mode: BudgetMode,
    /// `OG-24`: alert when spend reaches these percentages of `micro_usd`.
    pub alert_at_percent: Vec<u32>,
    /// `OG-24`: alert when spend reaches these absolute amounts.
    pub alert_at_micro_usd: Vec<u64>,
}

impl Budget {
    #[must_use]
    pub fn usd(&self) -> f64 {
        self.micro_usd as f64 / 1_000_000.0
    }

    /// Every threshold to alert at, in micro-USD, each with its label (`"80%"`,
    /// `"$250"`), ascending. A SOFT budget always alerts at 100 % (`OG-22`: soft = allow
    /// and alert).
    #[must_use]
    pub fn thresholds(&self) -> Vec<(u64, String)> {
        let mut out: Vec<(u64, String)> = Vec::new();
        let mut pcts = self.alert_at_percent.clone();
        if self.mode == BudgetMode::Soft && !pcts.contains(&100) {
            pcts.push(100);
        }
        for p in pcts {
            let at = (u128::from(self.micro_usd) * u128::from(p) / 100) as u64;
            out.push((at, format!("{p}%")));
        }
        for m in &self.alert_at_micro_usd {
            out.push((*m, format!("${}", fmt_usd(*m))));
        }
        out.sort_by_key(|(at, _)| *at);
        out.dedup_by(|a, b| a.1 == b.1);
        out
    }
}

/// `250`, `0.5`, `12.25` — the shortest exact rendering of a micro-USD amount.
fn fmt_usd(micro: u64) -> String {
    let whole = micro / 1_000_000;
    let frac = micro % 1_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        let f = format!("{frac:06}");
        format!("{whole}.{}", f.trim_end_matches('0'))
    }
}

fn usd_to_micro(field: &str, usd: f64) -> Result<u64, PolicyError> {
    if !(usd.is_finite() && usd > 0.0 && usd <= MAX_BUDGET_USD) {
        return Err(PolicyError::new(
            field,
            format!("must be greater than 0 and at most {MAX_BUDGET_USD}"),
        ));
    }
    let m = (usd * 1_000_000.0).round();
    if m < 1.0 {
        return Err(PolicyError::new(field, "must be at least 0.000001"));
    }
    Ok(m as u64)
}

// ── Glob + CIDR ──────────────────────────────────────────────────────────────

/// `*`-glob match, ASCII case-insensitive. `*` matches any run (including empty);
/// every other byte matches itself. Iterative, O(len(p) * len(t)) worst case.
/// rev5 `M3` — the names a model may carry ON THE PROVIDER'S WIRE once the gateway strips
/// its routing prefix: every tail after a `/` (`azure/gpt-4o` → `gpt-4o`;
/// `openrouter/openai/gpt-4o` → `openai/gpt-4o`, `gpt-4o`; `vertex/`, `bedrock/`, a catalog
/// `provider/` namespace), and every tail after a purely-alphabetic `vendor.` segment (a
/// Bedrock id: `us.anthropic.claude-…` → `anthropic.claude-…`, `claude-…`). A version dot
/// (`gpt-4.1`) is not a vendor separator — its head is not purely alphabetic.
///
/// A SUPERSET of what any adapter strips, on purpose: it is matched by DENY and BLOCK
/// lists, where matching more names is the fail-closed direction. It is never added to
/// what an ALLOW list matches — an allow of `gpt-4o` must not admit `evilhost/gpt-4o`.
#[must_use]
pub fn provider_facing_names(model: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = model;
    loop {
        let next = if let Some((_, tail)) = rest.split_once('/') {
            tail
        } else if let Some((head, tail)) = rest.split_once('.')
            && !head.is_empty()
            && head.bytes().all(|b| b.is_ascii_alphabetic())
        {
            tail
        } else {
            break;
        };
        if next.is_empty() {
            break;
        }
        out.push(next.to_owned());
        rest = next;
    }
    out
}

/// Does any of `patterns` DENY `model` — by the name it was given or any provider-facing
/// name ([`provider_facing_names`])?
#[must_use]
pub fn deny_matches(patterns: &[String], model: &str) -> bool {
    patterns.iter().any(|g| glob_match(g, model))
        || provider_facing_names(model)
            .iter()
            .any(|n| patterns.iter().any(|g| glob_match(g, n)))
}

#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    // The last `*` seen and the text position it is currently absorbing up to.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi].eq_ignore_ascii_case(&t[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            // Let the star absorb one more byte and retry the rest.
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|b| *b == b'*')
}

impl Cidr {
    /// `10.0.0.0/8`, `2001:db8::/32`, or a bare address (its /32 or /128). The network
    /// is masked, so `10.1.2.3/8` reads as `10.0.0.0/8`.
    ///
    /// # Errors
    /// Not an address, or a prefix length out of range for the family.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let shown: String = raw.chars().take(64).collect();
        let (addr, len) = match raw.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (raw, None),
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{shown}` is not an IP address or CIDR network"))?;
        if let IpAddr::V6(v6) = ip
            && v6.to_ipv4_mapped().is_some()
        {
            return Err(format!(
                "`{shown}` is an IPv4-mapped IPv6 address — write the IPv4 form"
            ));
        }
        let max: u8 = if ip.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(l) => l
                .parse::<u8>()
                .ok()
                .filter(|l| *l <= max)
                .ok_or_else(|| format!("`{shown}` has a prefix length outside 0..={max}"))?,
        };
        Ok(Self {
            net: mask(ip, len),
            len,
        })
    }

    /// Does `ip` fall inside this network? IPv4-mapped IPv6 is treated as IPv4.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_ipv4() == self.net.is_ipv4() && mask(ip, self.len) == self.net
    }
}

/// `ip` with every bit past `len` cleared.
fn mask(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let m = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.len)
    }
}

// ── Parse ────────────────────────────────────────────────────────────────────

impl KeyPolicy {
    /// Parse a stored or submitted document. `limits` is `Some` on the WRITE path
    /// (strict counts from the reference table) and `None` on the READ path.
    ///
    /// # Errors
    /// Not an object, an unknown field, a malformed entry, a value out of range, or a
    /// document that names no rule (`{}` never reads as "a policy").
    pub fn parse(v: &Value, limits: Option<&WriteLimits>) -> Result<Self, PolicyError> {
        if !v.is_object() {
            return Err(PolicyError::new(
                "policy",
                "the policy must be a JSON object (or null to clear it)",
            ));
        }
        let doc: Doc = serde_json::from_value(v.clone())
            .map_err(|e| PolicyError::new("policy", e.to_string()))?;
        let mut p = Self::default();
        if let Some(m) = doc.models {
            p.models = Some(lists("models", m, limits, model_pattern_ok)?);
        }
        if let Some(m) = doc.providers {
            p.providers = Some(lists("providers", m, limits, provider_id_ok)?);
        }
        if let Some(ips) = doc.source_ips {
            if ips.is_empty() {
                return Err(PolicyError::new(
                    "source_ips",
                    "must name at least one network — omit the field for no address rule",
                ));
            }
            if let Some(l) = limits
                && ips.len() > l.max_cidrs
            {
                return Err(PolicyError::new(
                    "source_ips",
                    format!("at most {} networks", l.max_cidrs),
                ));
            }
            for raw in &ips {
                let c = Cidr::parse(raw).map_err(|m| PolicyError::new("source_ips", m))?;
                if !p.source_ips.contains(&c) {
                    p.source_ips.push(c);
                }
            }
        }
        p.max_input_tokens = cap("max_input_tokens", doc.max_input_tokens, MAX_TOKEN_CAP)?;
        p.max_output_tokens = cap("max_output_tokens", doc.max_output_tokens, MAX_TOKEN_CAP)?;
        p.max_body_bytes = cap("max_body_bytes", doc.max_body_bytes, MAX_BODY_CAP)?;
        if let Some(tags) = doc.required_tags {
            p.required_tags = required("required_tags", tags, limits, |t| {
                !t.is_empty()
                    && t.len() <= 128
                    && !t.contains(',')
                    && !t.chars().any(char::is_control)
            })?;
        }
        if let Some(keys) = doc.required_metadata_keys {
            p.required_metadata_keys = required("required_metadata_keys", keys, limits, |k| {
                crate::labels::valid_key(k, 128)
            })?;
        }
        if let Some(l) = doc.limits {
            p.limits = Some(parse_limits(l, limits)?);
        }
        if let Some(b) = doc.budget {
            p.budget = Some(parse_budget("budget", b, limits, false)?);
        }
        if let Some(b) = doc.end_user_budget {
            p.end_user_budget = Some(parse_budget("end_user_budget", b, limits, true)?);
        }
        if !p.has_rules() {
            return Err(PolicyError::new(
                "policy",
                "the policy names no rule — send null to clear it",
            ));
        }
        Ok(p)
    }

    /// The canonical stored form: lower-cased, de-duplicated, empty parts omitted. What
    /// the write path stores, so "set it to what it already is" is a no-op.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = serde_json::Map::new();
        let lists_value = |l: &Lists| {
            let mut o = serde_json::Map::new();
            if !l.allow.is_empty() {
                o.insert("allow".into(), json!(l.allow));
            }
            if !l.deny.is_empty() {
                o.insert("deny".into(), json!(l.deny));
            }
            Value::Object(o)
        };
        if let Some(l) = &self.models {
            m.insert("models".into(), lists_value(l));
        }
        if let Some(l) = &self.providers {
            m.insert("providers".into(), lists_value(l));
        }
        if !self.source_ips.is_empty() {
            let ips: Vec<String> = self.source_ips.iter().map(ToString::to_string).collect();
            m.insert("source_ips".into(), json!(ips));
        }
        for (k, v) in [
            ("max_input_tokens", self.max_input_tokens),
            ("max_output_tokens", self.max_output_tokens),
            ("max_body_bytes", self.max_body_bytes),
        ] {
            if let Some(v) = v {
                m.insert(k.into(), json!(v));
            }
        }
        if !self.required_tags.is_empty() {
            m.insert("required_tags".into(), json!(self.required_tags));
        }
        if !self.required_metadata_keys.is_empty() {
            m.insert(
                "required_metadata_keys".into(),
                json!(self.required_metadata_keys),
            );
        }
        if let Some(l) = &self.limits {
            m.insert("limits".into(), limits_value(l));
        }
        if let Some(b) = &self.budget {
            m.insert("budget".into(), budget_value(b));
        }
        if let Some(b) = &self.end_user_budget {
            m.insert("end_user_budget".into(), budget_value(b));
        }
        Value::Object(m)
    }

    /// `OG-25`: what a WORKSPACE policy may carry — `limits`, `budget`, `end_user_budget`,
    /// and (rev5 `M6`) `models`, `providers` and `source_ips`, which then bind EVERY key in
    /// the workspace (including one minted after the policy was set: the layers intersect,
    /// so a key's own policy can only narrow the workspace's) and every session request.
    /// Token, body and label caps stay per project / key (they describe one integration's
    /// calls), and an emergency block is `/v1/controls/blocks`.
    ///
    /// # Errors
    /// The first field a workspace policy may not carry.
    pub fn workspace_only(&self) -> Result<(), PolicyError> {
        let first = [
            ("max_input_tokens", self.max_input_tokens.is_some()),
            ("max_output_tokens", self.max_output_tokens.is_some()),
            ("max_body_bytes", self.max_body_bytes.is_some()),
            ("required_tags", !self.required_tags.is_empty()),
            (
                "required_metadata_keys",
                !self.required_metadata_keys.is_empty(),
            ),
        ]
        .into_iter()
        .find(|(_, set)| *set);
        match first {
            None => Ok(()),
            Some((field, _)) => Err(PolicyError::new(
                field,
                "a workspace policy carries limits, budgets, models, providers and source_ips — \
                 set this rule on a project or key; an emergency block is PUT /v1/controls/blocks",
            )),
        }
    }

    /// May a request be dispatched to `model` on `provider` under THIS document's model and
    /// provider rules? Deny matches every provider-facing name too (rev5 `M3`); an allow
    /// list matches the dispatched name only (fail-closed).
    #[must_use]
    pub fn allows_dispatch(&self, model: &str, provider: &str) -> bool {
        let provider = provider.to_ascii_lowercase();
        self.models.as_ref().is_none_or(|r| {
            !deny_matches(&r.deny, model)
                && (r.allow.is_empty() || r.allow.iter().any(|g| glob_match(g, model)))
        }) && self.providers.as_ref().is_none_or(|r| {
            !r.deny.contains(&provider) && (r.allow.is_empty() || r.allow.contains(&provider))
        })
    }

    /// rev5 `M6`: this ONE document's model / provider / token rules against `request`, as
    /// `origin` (the workspace layer, which no key carries). Same rules, same codes as
    /// [`Governance::evaluate`].
    ///
    /// # Errors
    /// The first rule that fails — fail-CLOSED.
    pub fn check_request(
        &self,
        origin: Origin,
        request: &PolicyRequest,
        resolve: &dyn Fn(&str, bool) -> Resolved,
    ) -> Result<(), Denial> {
        for s in &request.subjects {
            let resolved = match &s.model {
                Fact::Known(m)
                    if self.models.is_some()
                        || (self.providers.is_some() && s.provider.is_none()) =>
                {
                    Some(resolve(m, s.workspace_alias))
                }
                _ => None,
            };
            check_subject(origin, self, s, resolved.as_ref())?;
        }
        Ok(())
    }

    /// rev5 `M6`: this document's `source_ips` against the request's source (`None` under a
    /// CIDR rule is DENIED), as `origin`.
    ///
    /// # Errors
    /// `policy_ip_denied`.
    pub fn check_source(&self, origin: Origin, ip: Option<IpAddr>) -> Result<(), Denial> {
        if self.source_ips.is_empty()
            || ip.is_some_and(|ip| self.source_ips.iter().any(|c| c.contains(ip)))
        {
            return Ok(());
        }
        Err(Denial::new(
            403,
            "policy_ip_denied",
            "source_ips",
            origin,
            None,
            format!(
                "{} does not allow requests from this network address",
                origin.phrase()
            ),
        ))
    }

    /// Does this policy carry any rule at all? (`parse` refuses one that does not.)
    #[must_use]
    pub fn has_rules(&self) -> bool {
        self.models.is_some()
            || self.providers.is_some()
            || !self.source_ips.is_empty()
            || self.max_input_tokens.is_some()
            || self.max_output_tokens.is_some()
            || self.max_body_bytes.is_some()
            || !self.required_tags.is_empty()
            || !self.required_metadata_keys.is_empty()
            || self.limits.is_some()
            || self.budget.is_some()
            || self.end_user_budget.is_some()
    }
}

fn rate_value(r: &Rate) -> serde_json::Map<String, Value> {
    let mut o = serde_json::Map::new();
    if let Some(n) = r.rpm {
        o.insert("rpm".into(), json!(n));
    }
    if let Some(n) = r.tpm {
        o.insert("tpm".into(), json!(n));
    }
    o
}

fn limits_value(l: &Limits) -> Value {
    let mut o = rate_value(&l.rate);
    if let Some(r) = &l.per_end_user {
        o.insert("per_end_user".into(), Value::Object(rate_value(r)));
    }
    if !l.per_model.is_empty() {
        let v: Vec<Value> = l
            .per_model
            .iter()
            .map(|m| {
                let mut e = rate_value(&m.rate);
                e.insert("model".into(), json!(m.model));
                Value::Object(e)
            })
            .collect();
        o.insert("per_model".into(), Value::Array(v));
    }
    Value::Object(o)
}

fn budget_value(b: &Budget) -> Value {
    let mut o = serde_json::Map::new();
    o.insert("usd".into(), json!(b.usd()));
    o.insert("window".into(), json!(b.window.as_str()));
    o.insert("mode".into(), json!(b.mode.as_str()));
    if !b.alert_at_percent.is_empty() {
        o.insert("alert_at_percent".into(), json!(b.alert_at_percent));
    }
    if !b.alert_at_micro_usd.is_empty() {
        let usd: Vec<f64> = b
            .alert_at_micro_usd
            .iter()
            .map(|m| *m as f64 / 1_000_000.0)
            .collect();
        o.insert("alert_at_usd".into(), json!(usd));
    }
    Value::Object(o)
}

fn rate(field: &str, rpm: Option<u64>, tpm: Option<u64>) -> Result<Rate, PolicyError> {
    if rpm.is_none() && tpm.is_none() {
        return Err(PolicyError::new(field, "must set `rpm`, `tpm` or both"));
    }
    let check = |name: &str, v: Option<u64>, max: u64| -> Result<Option<u64>, PolicyError> {
        match v {
            None => Ok(None),
            Some(n) if (1..=max).contains(&n) => Ok(Some(n)),
            Some(_) => Err(PolicyError::new(
                if field == "limits" {
                    format!("limits.{name}")
                } else {
                    field.to_owned()
                },
                format!("`{name}` must be between 1 and {max}"),
            )),
        }
    };
    Ok(Rate {
        rpm: check("rpm", rpm, MAX_RPM)?,
        tpm: check("tpm", tpm, MAX_TPM)?,
    })
}

fn parse_limits(doc: LimitsDoc, limits: Option<&WriteLimits>) -> Result<Limits, PolicyError> {
    let own = if doc.rpm.is_some() || doc.tpm.is_some() {
        rate("limits", doc.rpm, doc.tpm)?
    } else {
        Rate::default()
    };
    let per_end_user = doc
        .per_end_user
        .map(|r| rate("limits.per_end_user", r.rpm, r.tpm))
        .transpose()?;
    let mut per_model: Vec<ModelRate> = Vec::new();
    if let Some(entries) = doc.per_model {
        if entries.is_empty() {
            return Err(PolicyError::new(
                "limits.per_model",
                "must name at least one entry — omit the field for no per-model limit",
            ));
        }
        if let Some(l) = limits
            && entries.len() > l.max_per_model_limits
        {
            return Err(PolicyError::new(
                "limits.per_model",
                format!("at most {} entries", l.max_per_model_limits),
            ));
        }
        for e in entries {
            let model = e.model.trim().to_ascii_lowercase();
            let too_long = limits.is_some_and(|l| model.chars().count() > l.max_pattern_chars);
            if !model_pattern_ok(&model) || too_long {
                let shown: String = model.chars().take(64).collect();
                return Err(PolicyError::new(
                    "limits.per_model",
                    format!("`{shown}` is not a valid model pattern"),
                ));
            }
            let r = rate("limits.per_model", e.rpm, e.tpm)?;
            if per_model.iter().any(|m| m.model == model) {
                return Err(PolicyError::new(
                    "limits.per_model",
                    format!("`{model}` is listed twice"),
                ));
            }
            per_model.push(ModelRate { model, rate: r });
        }
    }
    let l = Limits {
        rate: own,
        per_end_user,
        per_model,
    };
    if l.rate == Rate::default() && l.per_end_user.is_none() && l.per_model.is_empty() {
        return Err(PolicyError::new(
            "limits",
            "names no limit — set rpm, tpm, per_end_user or per_model, or omit the field",
        ));
    }
    Ok(l)
}

fn parse_budget(
    field: &'static str,
    doc: BudgetDoc,
    limits: Option<&WriteLimits>,
    end_user: bool,
) -> Result<Budget, PolicyError> {
    let micro_usd = usd_to_micro(&format!("{field}.usd"), doc.usd)?;
    let window = match doc.window.as_deref() {
        None => BudgetWindow::Monthly,
        Some(w) => BudgetWindow::parse(w).ok_or_else(|| {
            PolicyError::new(
                format!("{field}.window"),
                "must be daily, weekly, monthly, rolling_1h, rolling_24h, rolling_7d or                  rolling_30d",
            )
        })?,
    };
    if end_user && window.rolling_hours().is_some() {
        return Err(PolicyError::new(
            format!("{field}.window"),
            "an end-user budget takes a calendar window: daily, weekly or monthly",
        ));
    }
    let mode = match doc.mode.as_deref() {
        None | Some("hard") => BudgetMode::Hard,
        Some("soft") => BudgetMode::Soft,
        Some(_) => {
            return Err(PolicyError::new(
                format!("{field}.mode"),
                "must be hard or soft",
            ));
        }
    };
    let max = limits.map(|l| l.max_alert_thresholds);
    let mut alert_at_percent = doc.alert_at_percent.unwrap_or_default();
    if max.is_some_and(|m| alert_at_percent.len() > m)
        || alert_at_percent
            .iter()
            .any(|p| !(1..=MAX_ALERT_PERCENT).contains(p))
    {
        return Err(PolicyError::new(
            format!("{field}.alert_at_percent"),
            format!(
                "each entry must be 1-{MAX_ALERT_PERCENT}{}",
                max.map_or(String::new(), |m| format!(", at most {m} entries"))
            ),
        ));
    }
    alert_at_percent.sort_unstable();
    alert_at_percent.dedup();
    let raw_usd = doc.alert_at_usd.unwrap_or_default();
    if max.is_some_and(|m| raw_usd.len() > m) {
        return Err(PolicyError::new(
            format!("{field}.alert_at_usd"),
            format!("at most {} entries", max.unwrap_or(0)),
        ));
    }
    let mut alert_at_micro_usd = raw_usd
        .into_iter()
        .map(|u| usd_to_micro(&format!("{field}.alert_at_usd"), u))
        .collect::<Result<Vec<u64>, _>>()?;
    alert_at_micro_usd.sort_unstable();
    alert_at_micro_usd.dedup();
    Ok(Budget {
        micro_usd,
        window,
        mode,
        alert_at_percent,
        alert_at_micro_usd,
    })
}

fn model_pattern_ok(p: &str) -> bool {
    !p.is_empty()
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@*-".contains(&b))
}

fn provider_id_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn lists(
    field: &'static str,
    doc: ListsDoc,
    limits: Option<&WriteLimits>,
    ok: fn(&str) -> bool,
) -> Result<Lists, PolicyError> {
    if doc.allow.is_empty() && doc.deny.is_empty() {
        return Err(PolicyError::new(
            field,
            "must name at least one entry in `allow` or `deny` — omit the field for no rule",
        ));
    }
    let one = |part: &str, raw: Vec<String>| -> Result<Vec<String>, PolicyError> {
        let path = format!("{field}.{part}");
        if let Some(l) = limits
            && raw.len() > l.max_patterns
        {
            return Err(PolicyError::new(
                path,
                format!("at most {} entries", l.max_patterns),
            ));
        }
        let mut out: Vec<String> = Vec::with_capacity(raw.len());
        for e in raw {
            let e = e.trim().to_ascii_lowercase();
            let too_long = limits.is_some_and(|l| e.chars().count() > l.max_pattern_chars);
            if !ok(&e) || too_long {
                let shown: String = e.chars().take(64).collect();
                return Err(PolicyError::new(
                    path,
                    format!(
                        "`{shown}` is not a valid entry (letters, digits, . _ - : / @ and `*` \
                         globs{})",
                        limits.map_or(String::new(), |l| format!(
                            ", at most {} characters",
                            l.max_pattern_chars
                        ))
                    ),
                ));
            }
            if !out.contains(&e) {
                out.push(e);
            }
        }
        Ok(out)
    };
    Ok(Lists {
        allow: one("allow", doc.allow)?,
        deny: one("deny", doc.deny)?,
    })
}

fn cap(field: &'static str, v: Option<u64>, max: u64) -> Result<Option<u64>, PolicyError> {
    match v {
        None => Ok(None),
        Some(n) if (1..=max).contains(&n) => Ok(Some(n)),
        Some(_) => Err(PolicyError::new(
            field,
            format!("must be between 1 and {max}"),
        )),
    }
}

fn required(
    field: &'static str,
    raw: Vec<String>,
    limits: Option<&WriteLimits>,
    ok: fn(&str) -> bool,
) -> Result<Vec<String>, PolicyError> {
    if raw.is_empty() {
        return Err(PolicyError::new(
            field,
            "must name at least one entry — omit the field for no rule",
        ));
    }
    if let Some(l) = limits
        && raw.len() > l.max_required_keys
    {
        return Err(PolicyError::new(
            field,
            format!("at most {} entries", l.max_required_keys),
        ));
    }
    let mut out: Vec<String> = Vec::with_capacity(raw.len());
    for e in raw {
        let e = e.trim().to_owned();
        if !ok(&e) {
            let shown: String = e.chars().take(64).collect();
            return Err(PolicyError::new(
                field,
                format!("`{shown}` is not a valid entry"),
            ));
        }
        if !out.contains(&e) {
            out.push(e);
        }
    }
    Ok(out)
}

// ── Governance: what a key carries ───────────────────────────────────────────

/// Which document a layer came from — named in every refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Project,
    Key,
    /// `OG-21`/`OG-22`/`OG-25`: the workspace's own layer (`workspace_controls.policy`):
    /// limits and budgets only.
    Workspace,
}

impl Origin {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Key => "key",
            Self::Workspace => "workspace",
        }
    }

    /// Whose policy, in a refusal message.
    #[must_use]
    pub fn phrase(self) -> String {
        match self {
            Self::Workspace => "this workspace's policy".to_owned(),
            o => format!("this API key's {} policy", o.as_str()),
        }
    }
}

/// A layer's policy, or the fact that it did not parse (fail-CLOSED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerPolicy {
    Valid(Box<KeyPolicy>),
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub origin: Origin,
    pub policy: LayerPolicy,
}

/// Everything `OG-20`/`OG-23` attach to an authenticated API key, resolved ONCE in the
/// auth SELECT and cached with the key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Governance {
    pub project_id: Option<uuid::Uuid>,
    pub environment: Option<String>,
    pub layers: Vec<Layer>,
    /// The stored documents, as stored (project first), for a fingerprint the gateway
    /// hashes (`OG-20` batch provenance). Empty when there are no layers.
    pub source: String,
}

impl Governance {
    /// Build from the auth row's columns. `None` when the key has no project, no
    /// environment and no policy anywhere — the zero-cost common case.
    #[must_use]
    pub fn from_columns(
        project_id: Option<uuid::Uuid>,
        environment: Option<String>,
        project_policy: Option<&Value>,
        key_policy: Option<&Value>,
    ) -> Option<Self> {
        let mut layers = Vec::new();
        let mut source = String::new();
        for (origin, doc) in [(Origin::Project, project_policy), (Origin::Key, key_policy)] {
            let Some(doc) = doc.filter(|d| !d.is_null()) else {
                continue;
            };
            let policy = match KeyPolicy::parse(doc, None) {
                Ok(p) => LayerPolicy::Valid(Box::new(p)),
                Err(_) => LayerPolicy::Invalid,
            };
            layers.push(Layer { origin, policy });
            source.push_str(origin.as_str());
            source.push('=');
            source.push_str(&doc.to_string());
            source.push('\n');
        }
        if project_id.is_none() && environment.is_none() && layers.is_empty() {
            return None;
        }
        Some(Self {
            project_id,
            environment,
            layers,
            source,
        })
    }

    /// Any layer at all (valid or not)?
    #[must_use]
    pub fn has_policy(&self) -> bool {
        !self.layers.is_empty()
    }

    /// Every layer that parsed, in order (project, then key). Admission reads the
    /// `OG-21` limits and `OG-22` budgets through this; an INVALID layer has already
    /// refused the request at `Step::Policy`.
    pub fn policies(&self) -> impl Iterator<Item = (Origin, &KeyPolicy)> {
        self.valid_layers()
    }

    fn valid_layers(&self) -> impl Iterator<Item = (Origin, &KeyPolicy)> {
        self.layers.iter().filter_map(|l| match &l.policy {
            LayerPolicy::Valid(p) => Some((l.origin, &**p)),
            LayerPolicy::Invalid => None,
        })
    }

    /// The authentication-time half: an unparseable layer, then every `source_ips`
    /// rule. `ip` is the request's source as B-594 derives it; `None` (no peer, no
    /// believable header) under a CIDR rule is DENIED.
    ///
    /// # Errors
    /// `policy_invalid` or `policy_ip_denied`.
    pub fn check_source(&self, ip: Option<IpAddr>) -> Result<(), Denial> {
        self.refuse_invalid()?;
        for (origin, p) in self.valid_layers() {
            if p.source_ips.is_empty() {
                continue;
            }
            if !ip.is_some_and(|ip| p.source_ips.iter().any(|c| c.contains(ip))) {
                return Err(Denial::new(
                    403,
                    "policy_ip_denied",
                    "source_ips",
                    origin,
                    None,
                    format!(
                        "this API key's {} policy does not allow requests from this network \
                         address",
                        origin.as_str()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Fail-CLOSED: any layer that did not parse refuses the request.
    fn refuse_invalid(&self) -> Result<(), Denial> {
        match self
            .layers
            .iter()
            .find(|l| matches!(l.policy, LayerPolicy::Invalid))
        {
            None => Ok(()),
            Some(l) => Err(Denial::new(
                403,
                "policy_invalid",
                "policy",
                l.origin,
                None,
                format!(
                    "this API key's {} policy could not be read, so every request on the key \
                     is refused — a workspace owner must correct or clear it",
                    l.origin.as_str()
                ),
            )),
        }
    }

    /// The admission-time half: every rule against what the route knows about the
    /// request. `resolve(model, workspace_alias)` names the model(s) and the provider
    /// the gateway will dispatch to; `labels` is called only when a layer requires tags
    /// or metadata keys.
    ///
    /// # Errors
    /// The FIRST rule that fails, in layer order (project, then key).
    pub fn evaluate(
        &self,
        request: &PolicyRequest,
        resolve: &dyn Fn(&str, bool) -> Resolved,
        labels: &dyn Fn() -> crate::labels::Labels,
    ) -> Result<(), Denial> {
        self.refuse_invalid()?;
        let mut seen_labels: Option<crate::labels::Labels> = None;
        // A subject's resolution does not depend on the layer; resolve each once.
        let mut resolved: Vec<Option<Resolved>> = vec![None; request.subjects.len()];
        for (origin, p) in self.valid_layers() {
            if let Some(limit) = p.max_body_bytes {
                match request.body_bytes {
                    Fact::Known(b) if b > limit => {
                        return Err(Denial::new(
                            413,
                            "policy_max_body_bytes",
                            "max_body_bytes",
                            origin,
                            None,
                            format!(
                                "this API key's {} policy caps a request body at {limit} bytes; \
                                 this one is {b}",
                                origin.as_str()
                            ),
                        )
                        .with("limit", json!(limit))
                        .with("bytes", json!(b)));
                    }
                    Fact::Known(_) | Fact::NotApplicable => {}
                    Fact::Unknown => return Err(unenforceable(origin, "max_body_bytes", None)),
                }
            }
            if !p.required_tags.is_empty() || !p.required_metadata_keys.is_empty() {
                let l = seen_labels.get_or_insert_with(labels);
                if let Some(t) = p.required_tags.iter().find(|t| !l.tags.contains(*t)) {
                    return Err(Denial::new(
                        403,
                        "policy_required_tag_missing",
                        "required_tags",
                        origin,
                        None,
                        format!(
                            "this API key's {} policy requires the tag `{t}` — send it in the \
                             `x-tracelane-tags` header",
                            origin.as_str()
                        ),
                    ));
                }
                if let Some(k) = p
                    .required_metadata_keys
                    .iter()
                    .find(|k| !l.metadata.contains_key(*k))
                {
                    return Err(Denial::new(
                        403,
                        "policy_required_metadata_missing",
                        "required_metadata_keys",
                        origin,
                        None,
                        format!(
                            "this API key's {} policy requires the metadata key `{k}` — send it \
                             in the `x-tracelane-metadata` header",
                            origin.as_str()
                        ),
                    ));
                }
            }
            for (i, s) in request.subjects.iter().enumerate() {
                if let Fact::Known(m) = &s.model
                    && resolved[i].is_none()
                    && (p.models.is_some() || (p.providers.is_some() && s.provider.is_none()))
                {
                    resolved[i] = Some(resolve(m, s.workspace_alias));
                }
                check_subject(origin, p, s, resolved[i].as_ref())?;
            }
        }
        Ok(())
    }

    /// May a request be MOVED to `model` on `provider` after admission (a ZDR re-route,
    /// a cross-provider failover)? Model and provider rules only; an invalid layer says
    /// no.
    #[must_use]
    pub fn allows_dispatch(&self, model: &str, provider: &str) -> bool {
        if self.refuse_invalid().is_err() {
            return false;
        }
        self.valid_layers()
            .all(|(_, p)| p.allows_dispatch(model, provider))
    }

    /// Does any layer require tags or metadata keys (so the caller must read labels)?
    #[must_use]
    pub fn needs_labels(&self) -> bool {
        self.valid_layers()
            .any(|(_, p)| !p.required_tags.is_empty() || !p.required_metadata_keys.is_empty())
    }
}

// ── What a route knows ───────────────────────────────────────────────────────

/// One fact a route reports about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact<T> {
    Known(T),
    /// The rule cannot apply (embeddings generate no output tokens).
    NotApplicable,
    /// The route cannot know (an opaque passthrough body) — a rule on it refuses.
    Unknown,
}

/// One model call inside a request: a single call for chat, one per line of a batch file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// 1-based batch-file line; `None` for an ordinary request.
    pub line: Option<usize>,
    /// The model as the CALLER sent it.
    pub model: Fact<String>,
    /// Does this route rewrite a WORKSPACE alias before dispatch (chat, embeddings)?
    pub workspace_alias: bool,
    /// The route's own fixed provider (passthrough path, realtime, media, files); `None`
    /// = the provider the dispatched model routes to.
    pub provider: Option<String>,
    /// Estimated input tokens.
    pub input_tokens: Fact<u64>,
    /// The caller's declared output cap; `Known(None)` = a generating call that
    /// declared none.
    pub output_cap: Fact<Option<u64>>,
}

impl Subject {
    /// A subject the route knows nothing about: every rule refuses on it.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            line: None,
            model: Fact::Unknown,
            workspace_alias: false,
            provider: None,
            input_tokens: Fact::Unknown,
            output_cap: Fact::Unknown,
        }
    }
}

/// What admission hands [`Governance::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub subjects: Vec<Subject>,
    pub body_bytes: Fact<u64>,
}

/// The gateway's answer for one model name: every name the request is known by on its
/// way to the wire, and the provider it routes to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolved {
    /// Every name a DENY is matched against: the caller's, the workspace alias target,
    /// the operator alias upstream.
    pub names: Vec<String>,
    /// The names an ALLOW may match: the dispatched model (after a workspace alias, the
    /// target — never the alias the caller typed).
    pub allow_names: Vec<String>,
    /// The provider the dispatched model routes to; `None` = unroutable.
    pub provider: Option<String>,
}

/// One refusal: what the wire renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// HTTP status: 403, or 413 for the body cap.
    pub status: u16,
    pub code: &'static str,
    /// The rule's document field (`models`, `source_ips`, …).
    pub rule: &'static str,
    pub origin: Origin,
    /// Batch-file line, when one is at fault.
    pub line: Option<usize>,
    pub message: String,
    /// `{limit, requested|estimated|bytes}` for the numeric caps.
    pub detail: BTreeMap<&'static str, Value>,
}

/// One subject against one layer's model, provider and token rules.
fn check_subject(
    origin: Origin,
    p: &KeyPolicy,
    s: &Subject,
    resolved: Option<&Resolved>,
) -> Result<(), Denial> {
    let at = |m: String| match s.line {
        Some(n) => format!("{m} (line {n} of the batch file)"),
        None => m,
    };
    if let Some(rules) = &p.models {
        match (&s.model, resolved) {
            (Fact::Known(m), Some(r)) => {
                let denied = r.names.iter().any(|n| deny_matches(&rules.deny, n));
                let allowed = rules.allow.is_empty()
                    || r.allow_names
                        .iter()
                        .any(|n| rules.allow.iter().any(|g| glob_match(g, n)));
                if denied || !allowed {
                    let shown: String = m.chars().take(128).collect();
                    return Err(Denial::new(
                        403,
                        "policy_model_denied",
                        "models",
                        origin,
                        s.line,
                        at(format!(
                            "this API key's {} policy does not allow the model `{shown}`",
                            origin.as_str()
                        )),
                    ));
                }
            }
            (Fact::NotApplicable, _) => {}
            _ => return Err(unenforceable(origin, "models", s.line)),
        }
    }
    if let Some(rules) = &p.providers {
        // `Known(Some(id))` routed, `Known(None)` unroutable.
        let provider: Fact<Option<String>> = match (&s.provider, resolved, &s.model) {
            (Some(fixed), _, _) => Fact::Known(Some(fixed.to_ascii_lowercase())),
            (None, Some(r), _) => Fact::Known(r.provider.as_ref().map(|p| p.to_ascii_lowercase())),
            (None, None, Fact::NotApplicable) => Fact::NotApplicable,
            (None, None, _) => Fact::Unknown,
        };
        match provider {
            Fact::Known(pid) => {
                let refused = match &pid {
                    Some(pid) => {
                        rules.deny.contains(pid)
                            || (!rules.allow.is_empty() && !rules.allow.contains(pid))
                    }
                    // Unroutable: no provider can be IN an allow-list.
                    None => !rules.allow.is_empty(),
                };
                if refused {
                    return Err(Denial::new(
                        403,
                        "policy_provider_denied",
                        "providers",
                        origin,
                        s.line,
                        at(format!(
                            "this API key's {} policy does not allow the provider `{}`",
                            origin.as_str(),
                            pid.as_deref().unwrap_or("(unroutable)")
                        )),
                    ));
                }
            }
            Fact::NotApplicable => {}
            Fact::Unknown => return Err(unenforceable(origin, "providers", s.line)),
        }
    }
    if let Some(limit) = p.max_input_tokens {
        match s.input_tokens {
            Fact::Known(n) if n > limit => {
                return Err(Denial::new(
                    403,
                    "policy_max_input_tokens",
                    "max_input_tokens",
                    origin,
                    s.line,
                    at(format!(
                        "this API key's {} policy caps input at {limit} tokens; this request is \
                         an estimated {n} (about 4 bytes per token)",
                        origin.as_str()
                    )),
                )
                .with("limit", json!(limit))
                .with("estimated", json!(n)));
            }
            Fact::Known(_) | Fact::NotApplicable => {}
            Fact::Unknown => return Err(unenforceable(origin, "max_input_tokens", s.line)),
        }
    }
    if let Some(limit) = p.max_output_tokens {
        match s.output_cap {
            Fact::Known(Some(n)) if n <= limit => {}
            Fact::Known(declared) => {
                let message = match declared {
                    Some(n) => format!(
                        "this API key's {} policy caps output at {limit} tokens; this request \
                         asks for {n}",
                        origin.as_str()
                    ),
                    None => format!(
                        "this API key's {} policy caps output at {limit} tokens, and this \
                         request declares no cap — set `max_tokens` (or the wire's equivalent) \
                         to at most {limit}",
                        origin.as_str()
                    ),
                };
                return Err(Denial::new(
                    403,
                    "policy_max_output_tokens",
                    "max_output_tokens",
                    origin,
                    s.line,
                    at(message),
                )
                .with("limit", json!(limit))
                .with("requested", json!(declared)));
            }
            Fact::NotApplicable => {}
            Fact::Unknown => return Err(unenforceable(origin, "max_output_tokens", s.line)),
        }
    }
    Ok(())
}

/// `policy_unenforceable`: the layer sets `rule`, which this route cannot evaluate.
#[must_use]
pub fn unenforceable(origin: Origin, rule: &'static str, line: Option<usize>) -> Denial {
    Denial::new(
        403,
        "policy_unenforceable",
        rule,
        origin,
        line,
        format!(
            "{} sets `{rule}`, which this endpoint cannot evaluate, so the request is refused",
            origin.phrase()
        ),
    )
}

impl Denial {
    #[must_use]
    pub fn new(
        status: u16,
        code: &'static str,
        rule: &'static str,
        origin: Origin,
        line: Option<usize>,
        message: String,
    ) -> Self {
        Self {
            status,
            code,
            rule,
            origin,
            line,
            message,
            detail: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with(mut self, k: &'static str, v: Value) -> Self {
        self.detail.insert(k, v);
        self
    }

    /// The JSON the OpenAI-shaped wire puts beside `error` / `message`.
    #[must_use]
    pub fn extra(&self) -> Value {
        let mut v = json!({ "rule": self.rule, "policy": self.origin.as_str() });
        if let Some(line) = self.line {
            v["line"] = json!(line);
        }
        for (k, val) in &self.detail {
            v[*k] = val.clone();
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> WriteLimits {
        WriteLimits {
            max_patterns: 4,
            max_pattern_chars: 32,
            max_cidrs: 3,
            max_required_keys: 2,
            max_per_model_limits: 2,
            max_alert_thresholds: 3,
        }
    }

    fn pol(v: Value) -> KeyPolicy {
        KeyPolicy::parse(&v, Some(&limits())).expect("valid policy")
    }

    fn gov_key(v: Value) -> Governance {
        Governance::from_columns(None, None, None, Some(&v)).expect("a governance")
    }

    /// The resolver a route with no aliases produces: the model is its own dispatch
    /// name; the provider is the prefix before `-` (`gpt-4o` → `gpt`) or `openai`.
    fn plain(model: &str, _ws: bool) -> Resolved {
        Resolved {
            names: vec![model.to_owned()],
            allow_names: vec![model.to_owned()],
            provider: Some(if model.starts_with("claude") {
                "anthropic".into()
            } else {
                "openai".into()
            }),
        }
    }

    fn no_labels() -> crate::labels::Labels {
        crate::labels::Labels::default()
    }

    fn chat(model: &str, out: Option<u64>, input: u64) -> PolicyRequest {
        PolicyRequest {
            subjects: vec![Subject {
                line: None,
                model: Fact::Known(model.into()),
                workspace_alias: true,
                provider: None,
                input_tokens: Fact::Known(input),
                output_cap: Fact::Known(out),
            }],
            body_bytes: Fact::Known(100),
        }
    }

    // ── glob ──

    #[test]
    fn glob_matches_star_runs_case_insensitively_and_nothing_else() {
        for (p, t) in [
            ("gpt-4o", "gpt-4o"),
            ("gpt-4o*", "gpt-4o-mini"),
            ("gpt-4o*", "gpt-4o"),
            ("*", ""),
            ("*-preview", "o3-preview"),
            ("claude-*-4*", "claude-sonnet-4-5"),
            ("GPT-4O", "gpt-4o"),
            ("a*b*c", "aXXbYYc"),
        ] {
            assert!(glob_match(p, t), "{p} should match {t}");
        }
        for (p, t) in [
            ("gpt-4o", "gpt-4o-mini"),
            ("gpt-4o", "xgpt-4o"),
            ("*-preview", "o3-preview-2"),
            ("a*b*c", "aXXbYY"),
            ("", "x"),
        ] {
            assert!(!glob_match(p, t), "{p} must NOT match {t}");
        }
    }

    // ── CIDR ──

    #[test]
    fn cidr_parses_v4_v6_and_bare_addresses_and_masks_the_network() {
        let c = Cidr::parse("10.1.2.3/8").unwrap();
        assert_eq!(c.to_string(), "10.0.0.0/8");
        assert!(c.contains("10.255.0.1".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        let one = Cidr::parse("203.0.113.7").unwrap();
        assert_eq!(one.to_string(), "203.0.113.7/32");
        assert!(one.contains("203.0.113.7".parse().unwrap()));
        assert!(!one.contains("203.0.113.8".parse().unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!v6.contains("2001:db9::5".parse().unwrap()));
        // A v4 rule never matches a v6 address and vice versa — except the v4-mapped
        // form, which IS the v4 address.
        assert!(!c.contains("::1".parse().unwrap()));
        assert!(c.contains("::ffff:10.0.0.9".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        let all = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        for bad in [
            "10.0.0.0/33",
            "2001:db8::/129",
            "nope",
            "10.0.0.0/",
            "/8",
            "10.0.0.0/x",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad} must be refused");
        }
    }

    // ── parse ──

    #[test]
    fn parse_normalises_and_round_trips_through_the_canonical_form() {
        let p = pol(json!({
            "models": { "allow": ["GPT-4o*", "gpt-4o*"], "deny": ["*-preview"] },
            "providers": { "allow": ["OpenAI"] },
            "source_ips": ["10.1.0.0/16"],
            "max_input_tokens": 8000,
            "max_output_tokens": 2000,
            "max_body_bytes": 1024,
            "required_tags": ["prod"],
            "required_metadata_keys": ["team"]
        }));
        let models = p.models.clone().unwrap();
        assert_eq!(
            models.allow,
            vec!["gpt-4o*"],
            "lower-cased and de-duplicated"
        );
        assert_eq!(p.providers.clone().unwrap().allow, vec!["openai"]);
        let canon = p.to_value();
        assert_eq!(KeyPolicy::parse(&canon, Some(&limits())).unwrap(), p);
        assert_eq!(canon["source_ips"], json!(["10.1.0.0/16"]));
        assert!(
            canon["providers"].get("deny").is_none(),
            "empty parts omitted"
        );
    }

    #[test]
    fn parse_refuses_every_malformed_document_naming_the_field() {
        for (doc, field) in [
            (json!([]), "policy"),
            (json!({}), "policy"),
            (json!({"modles": {"allow": ["x"]}}), "policy"),
            (json!({"models": {"allow": [], "deny": []}}), "models"),
            (json!({"models": {"allow": ["has space"]}}), "models.allow"),
            (
                json!({"models": {"allow": ["a", "b", "c", "d", "e"]}}),
                "models.allow",
            ),
            (json!({"models": {"deny": ["x".repeat(33)]}}), "models.deny"),
            (
                json!({"providers": {"allow": ["Open AI"]}}),
                "providers.allow",
            ),
            (json!({"source_ips": []}), "source_ips"),
            (json!({"source_ips": ["10.0.0.0/33"]}), "source_ips"),
            (
                json!({"source_ips": ["1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"]}),
                "source_ips",
            ),
            (json!({"max_input_tokens": 0}), "max_input_tokens"),
            (
                json!({"max_output_tokens": 2_147_483_648u64}),
                "max_output_tokens",
            ),
            (json!({"max_body_bytes": 0}), "max_body_bytes"),
            (json!({"max_output_tokens": -1}), "policy"),
            (json!({"required_tags": ["a,b"]}), "required_tags"),
            (json!({"required_tags": []}), "required_tags"),
            (
                json!({"required_metadata_keys": ["bad key"]}),
                "required_metadata_keys",
            ),
            (
                json!({"required_metadata_keys": ["a", "b", "c"]}),
                "required_metadata_keys",
            ),
        ] {
            let err = KeyPolicy::parse(&doc, Some(&limits()))
                .expect_err(&format!("{doc} must be refused"));
            assert_eq!(err.field, field, "{doc}: {err}");
        }
    }

    #[test]
    fn the_read_path_does_not_apply_the_write_bounds() {
        let many = json!({"models": {"allow": ["a", "b", "c", "d", "e"]}});
        assert!(KeyPolicy::parse(&many, Some(&limits())).is_err());
        assert!(KeyPolicy::parse(&many, None).is_ok());
    }

    // ── governance ──

    #[test]
    fn no_project_no_environment_no_policy_is_no_governance_at_all() {
        assert_eq!(Governance::from_columns(None, None, None, None), None);
        let g =
            Governance::from_columns(Some(uuid::Uuid::nil()), Some("staging".into()), None, None)
                .unwrap();
        assert!(!g.has_policy());
        assert_eq!(g.environment.as_deref(), Some("staging"));
        // No layer: every request passes exactly as before.
        assert!(g.check_source(None).is_ok());
        assert!(
            g.evaluate(&chat("anything", None, 1_000_000), &plain, &no_labels)
                .is_ok()
        );
    }

    #[test]
    fn an_unparseable_stored_policy_refuses_everything_fail_closed() {
        let g = gov_key(json!({"models": {"allow": ["gpt-4o"]}, "future_rule": true}));
        assert!(g.has_policy());
        let d = g
            .check_source(Some("10.0.0.1".parse().unwrap()))
            .unwrap_err();
        assert_eq!((d.status, d.code), (403, "policy_invalid"));
        let d = g
            .evaluate(&chat("gpt-4o", Some(10), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.code, "policy_invalid");
        assert!(!g.allows_dispatch("gpt-4o", "openai"));
        // A non-object is invalid too.
        let g = gov_key(json!("allow everything"));
        assert_eq!(g.check_source(None).unwrap_err().code, "policy_invalid");
    }

    #[test]
    fn source_ips_deny_outside_and_deny_an_unknown_source() {
        let g = gov_key(json!({"source_ips": ["10.0.0.0/8", "2001:db8::/32"]}));
        assert!(g.check_source(Some("10.9.9.9".parse().unwrap())).is_ok());
        assert!(g.check_source(Some("2001:db8::9".parse().unwrap())).is_ok());
        let d = g
            .check_source(Some("8.8.8.8".parse().unwrap()))
            .unwrap_err();
        assert_eq!(
            (d.status, d.code, d.rule),
            (403, "policy_ip_denied", "source_ips")
        );
        assert_eq!(g.check_source(None).unwrap_err().code, "policy_ip_denied");
        // No CIDR rule: no source needed.
        let g = gov_key(json!({"max_output_tokens": 5}));
        assert!(g.check_source(None).is_ok());
    }

    #[test]
    fn model_deny_wins_allow_must_match_and_an_alias_cannot_launder() {
        let g = gov_key(json!({"models": {"allow": ["gpt-4o*"], "deny": ["*-preview"]}}));
        assert!(
            g.evaluate(&chat("gpt-4o-mini", Some(1), 1), &plain, &no_labels)
                .is_ok()
        );
        let d = g
            .evaluate(&chat("gpt-4o-preview", Some(1), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!((d.code, d.rule), ("policy_model_denied", "models"));
        let d = g
            .evaluate(&chat("claude-sonnet-4", Some(1), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.code, "policy_model_denied");
        assert!(d.message.contains("claude-sonnet-4"), "{}", d.message);

        // `fast` is a workspace alias for a DENIED model: the deny matches the target.
        let deny = gov_key(json!({"models": {"deny": ["gpt-4o"]}}));
        let alias = |m: &str, ws: bool| -> Resolved {
            if ws && m == "fast" {
                Resolved {
                    names: vec!["fast".into(), "gpt-4o".into()],
                    allow_names: vec!["gpt-4o".into()],
                    provider: Some("openai".into()),
                }
            } else {
                plain(m, ws)
            }
        };
        assert_eq!(
            deny.evaluate(&chat("fast", Some(1), 1), &alias, &no_labels)
                .unwrap_err()
                .code,
            "policy_model_denied"
        );
        // And an allow-list naming the ALIAS does not admit the target behind it.
        let allow = gov_key(json!({"models": {"allow": ["fast"]}}));
        assert_eq!(
            allow
                .evaluate(&chat("fast", Some(1), 1), &alias, &no_labels)
                .unwrap_err()
                .code,
            "policy_model_denied"
        );
    }

    #[test]
    fn provider_rules_use_the_resolved_or_fixed_provider_and_refuse_unroutable() {
        let g = gov_key(json!({"providers": {"allow": ["openai"]}}));
        assert!(
            g.evaluate(&chat("gpt-4o", Some(1), 1), &plain, &no_labels)
                .is_ok()
        );
        let d = g
            .evaluate(&chat("claude-x", Some(1), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!((d.code, d.rule), ("policy_provider_denied", "providers"));
        let unroutable = |m: &str, _: bool| Resolved {
            names: vec![m.into()],
            allow_names: vec![m.into()],
            provider: None,
        };
        assert_eq!(
            g.evaluate(&chat("mystery", Some(1), 1), &unroutable, &no_labels)
                .unwrap_err()
                .code,
            "policy_provider_denied"
        );
        // A fixed provider (passthrough) is judged directly.
        let mut req = chat("x", Some(1), 1);
        req.subjects[0].model = Fact::Unknown;
        req.subjects[0].provider = Some("anthropic".into());
        req.subjects[0].input_tokens = Fact::Unknown;
        req.subjects[0].output_cap = Fact::Unknown;
        assert_eq!(
            g.evaluate(&req, &plain, &no_labels).unwrap_err().code,
            "policy_provider_denied"
        );
        let deny = gov_key(json!({"providers": {"deny": ["anthropic"]}}));
        assert!(!deny.allows_dispatch("claude-x", "anthropic"));
        assert!(deny.allows_dispatch("gpt-4o", "openai"));
    }

    #[test]
    fn token_caps_compare_the_estimate_and_the_declared_cap_and_refuse_an_undeclared_one() {
        let g = gov_key(json!({"max_input_tokens": 100, "max_output_tokens": 50}));
        assert!(
            g.evaluate(&chat("m", Some(50), 100), &plain, &no_labels)
                .is_ok()
        );
        let d = g
            .evaluate(&chat("m", Some(50), 101), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.code, "policy_max_input_tokens");
        assert_eq!(d.detail["limit"], json!(100));
        assert_eq!(d.detail["estimated"], json!(101));
        let d = g
            .evaluate(&chat("m", Some(51), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.code, "policy_max_output_tokens");
        assert_eq!(d.detail["requested"], json!(51));
        let d = g
            .evaluate(&chat("m", None, 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.code, "policy_max_output_tokens");
        assert_eq!(d.detail["requested"], Value::Null);
        // Embeddings: no output tokens to cap.
        let mut emb = chat("m", None, 1);
        emb.subjects[0].output_cap = Fact::NotApplicable;
        assert!(g.evaluate(&emb, &plain, &no_labels).is_ok());
    }

    #[test]
    fn a_rule_the_route_cannot_evaluate_refuses_as_unenforceable() {
        let mut opaque = PolicyRequest {
            subjects: vec![Subject {
                provider: Some("openai".into()),
                ..Subject::unknown()
            }],
            body_bytes: Fact::Unknown,
        };
        for (doc, rule) in [
            (json!({"models": {"allow": ["gpt-4o"]}}), "models"),
            (json!({"max_input_tokens": 5}), "max_input_tokens"),
            (json!({"max_output_tokens": 5}), "max_output_tokens"),
            (json!({"max_body_bytes": 5}), "max_body_bytes"),
        ] {
            let d = gov_key(doc)
                .evaluate(&opaque, &plain, &no_labels)
                .unwrap_err();
            assert_eq!((d.code, d.rule), ("policy_unenforceable", rule));
        }
        // A provider rule IS enforceable on it (the provider is the route's own).
        assert!(
            gov_key(json!({"providers": {"allow": ["openai"]}}))
                .evaluate(&opaque, &plain, &no_labels)
                .is_ok()
        );
        opaque.body_bytes = Fact::Known(10);
        let d = gov_key(json!({"max_body_bytes": 5}))
            .evaluate(&opaque, &plain, &no_labels)
            .unwrap_err();
        assert_eq!((d.status, d.code), (413, "policy_max_body_bytes"));
    }

    #[test]
    fn required_labels_must_be_present_in_what_is_recorded() {
        let g = gov_key(json!({"required_tags": ["prod"], "required_metadata_keys": ["team"]}));
        assert!(g.needs_labels());
        let d = g
            .evaluate(&chat("m", Some(1), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.code, "policy_required_tag_missing");
        let tagged = || crate::labels::Labels {
            tags: vec!["prod".into()],
            ..Default::default()
        };
        let d = g
            .evaluate(&chat("m", Some(1), 1), &plain, &tagged)
            .unwrap_err();
        assert_eq!(d.code, "policy_required_metadata_missing");
        let both = || crate::labels::Labels {
            tags: vec!["prod".into()],
            metadata: [("team".to_string(), "core".to_string())].into(),
            ..Default::default()
        };
        assert!(g.evaluate(&chat("m", Some(1), 1), &plain, &both).is_ok());
    }

    #[test]
    fn project_and_key_layers_intersect_and_the_refusal_names_the_layer() {
        let project = json!({"models": {"allow": ["gpt-4o*"]}});
        let key = json!({"models": {"deny": ["gpt-4o-mini"]}});
        let g = Governance::from_columns(Some(uuid::Uuid::nil()), None, Some(&project), Some(&key))
            .unwrap();
        assert_eq!(g.layers.len(), 2);
        assert!(
            g.evaluate(&chat("gpt-4o", Some(1), 1), &plain, &no_labels)
                .is_ok()
        );
        let d = g
            .evaluate(&chat("claude-x", Some(1), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.origin, Origin::Project);
        let d = g
            .evaluate(&chat("gpt-4o-mini", Some(1), 1), &plain, &no_labels)
            .unwrap_err();
        assert_eq!(d.origin, Origin::Key);
        // A key cannot WIDEN its project: allowing claude on the key changes nothing.
        let wide = json!({"models": {"allow": ["claude-*"]}});
        let g = Governance::from_columns(None, None, Some(&project), Some(&wide)).unwrap();
        assert!(
            g.evaluate(&chat("claude-x", Some(1), 1), &plain, &no_labels)
                .is_err()
        );
        assert!(!g.source.is_empty());
    }

    #[test]
    fn every_batch_line_is_judged_and_the_refusal_names_the_line() {
        let g = gov_key(json!({"models": {"deny": ["gpt-4o"]}}));
        let line = |n: usize, m: &str| Subject {
            line: Some(n),
            model: Fact::Known(m.into()),
            workspace_alias: false,
            provider: Some("openai".into()),
            input_tokens: Fact::Known(1),
            output_cap: Fact::Known(Some(1)),
        };
        let req = PolicyRequest {
            subjects: vec![line(1, "gpt-4o-mini"), line(3, "gpt-4o"), line(4, "gpt-4o")],
            body_bytes: Fact::Known(10),
        };
        let d = g.evaluate(&req, &plain, &no_labels).unwrap_err();
        assert_eq!((d.code, d.line), ("policy_model_denied", Some(3)));
        assert_eq!(d.extra()["line"], json!(3));
    }

    // ── OG-21 limits / OG-22 budgets ──

    #[test]
    fn og21_limits_parse_normalise_and_round_trip() {
        let p = pol(json!({
            "limits": {
                "rpm": 600, "tpm": 200000,
                "per_end_user": {"rpm": 20},
                "per_model": [{"model": "GPT-4o*", "tpm": 50000}]
            }
        }));
        let l = p.limits.clone().expect("limits");
        assert_eq!(
            l.rate,
            Rate {
                rpm: Some(600),
                tpm: Some(200_000)
            }
        );
        assert_eq!(
            l.per_end_user,
            Some(Rate {
                rpm: Some(20),
                tpm: None
            })
        );
        assert_eq!(l.per_model[0].model, "gpt-4o*");
        assert_eq!(
            l.per_model[0].rate,
            Rate {
                rpm: None,
                tpm: Some(50_000)
            }
        );
        assert!(p.has_rules(), "limits alone are a policy");
        let again = KeyPolicy::parse(&p.to_value(), Some(&limits())).expect("canonical parses");
        assert_eq!(again, p, "canonical form round-trips");
    }

    #[test]
    fn og21_limits_refuse_every_malformed_shape_naming_the_field() {
        for (doc, field) in [
            (json!({"limits": {}}), "limits"),
            (json!({"limits": {"rpm": 0}}), "limits.rpm"),
            (json!({"limits": {"tpm": MAX_TPM + 1}}), "limits.tpm"),
            (json!({"limits": {"rpm": MAX_RPM + 1}}), "limits.rpm"),
            (
                json!({"limits": {"per_end_user": {}}}),
                "limits.per_end_user",
            ),
            (
                json!({"limits": {"per_model": [{"model": "a b", "rpm": 1}]}}),
                "limits.per_model",
            ),
            (
                json!({"limits": {"per_model": [{"model": "a", "rpm": 1}, {"model": "b", "rpm": 1}, {"model": "c", "rpm": 1}]}}),
                "limits.per_model",
            ),
            (
                json!({"limits": {"per_model": [{"model": "a"}]}}),
                "limits.per_model",
            ),
            (json!({"limits": {"rpm": 1, "burst": 2}}), "policy"),
        ] {
            let e = KeyPolicy::parse(&doc, Some(&limits())).expect_err(&doc.to_string());
            assert_eq!(e.field, field, "{doc}");
        }
    }

    #[test]
    fn og22_budgets_parse_with_defaults_and_refuse_bad_values() {
        let p = pol(json!({
            "budget": {"usd": 500, "window": "rolling_7d", "mode": "soft",
                       "alert_at_percent": [80, 50], "alert_at_usd": [250.5]},
            "end_user_budget": {"usd": 5}
        }));
        let b = p.budget.clone().expect("budget");
        assert_eq!(b.micro_usd, 500_000_000);
        assert_eq!(b.window, BudgetWindow::Rolling7d);
        assert_eq!(b.mode, BudgetMode::Soft);
        assert_eq!(b.alert_at_percent, vec![50, 80], "sorted, de-duplicated");
        assert_eq!(b.alert_at_micro_usd, vec![250_500_000]);
        let eu = p.end_user_budget.clone().expect("end-user budget");
        assert_eq!(
            (eu.window, eu.mode),
            (BudgetWindow::Monthly, BudgetMode::Hard),
            "defaults"
        );
        assert_eq!(
            KeyPolicy::parse(&p.to_value(), Some(&limits())).expect("canonical"),
            p
        );
        // A soft budget alerts at 100 % even when the caller did not list it.
        let labels: Vec<String> = b.thresholds().into_iter().map(|(_, l)| l).collect();
        assert_eq!(labels, vec!["50%", "$250.5", "80%", "100%"]);
        for (doc, field) in [
            (json!({"budget": {"usd": 0}}), "budget.usd"),
            (json!({"budget": {"usd": -1}}), "budget.usd"),
            (json!({"budget": {"usd": 2e9}}), "budget.usd"),
            (
                json!({"budget": {"usd": 1, "window": "fortnightly"}}),
                "budget.window",
            ),
            (
                json!({"budget": {"usd": 1, "mode": "maybe"}}),
                "budget.mode",
            ),
            (
                json!({"budget": {"usd": 1, "alert_at_percent": [0]}}),
                "budget.alert_at_percent",
            ),
            (
                json!({"budget": {"usd": 1, "alert_at_percent": [1001]}}),
                "budget.alert_at_percent",
            ),
            (
                json!({"budget": {"usd": 1, "alert_at_percent": [1, 2, 3, 4]}}),
                "budget.alert_at_percent",
            ),
            (
                json!({"budget": {"usd": 1, "alert_at_usd": [0]}}),
                "budget.alert_at_usd",
            ),
            (
                json!({"end_user_budget": {"usd": 1, "window": "rolling_24h"}}),
                "end_user_budget.window",
            ),
        ] {
            let e = KeyPolicy::parse(&doc, Some(&limits())).expect_err(&doc.to_string());
            assert_eq!(e.field, field, "{doc}");
        }
    }

    #[test]
    fn og25_a_workspace_policy_carries_limits_budgets_and_rev5_m6_model_provider_ip_rules() {
        let ok =
            pol(json!({"limits": {"rpm": 5}, "budget": {"usd": 1}, "end_user_budget": {"usd": 1}}));
        assert!(ok.workspace_only().is_ok());
        // rev5 M6: the rules that must bind every key may live on the workspace.
        for doc in [
            json!({"models": {"deny": ["x"]}}),
            json!({"providers": {"allow": ["openai"]}}),
            json!({"source_ips": ["10.0.0.0/8"]}),
        ] {
            assert!(pol(doc.clone()).workspace_only().is_ok(), "{doc}");
        }
        for doc in [
            json!({"max_output_tokens": 5}),
            json!({"max_input_tokens": 5}),
            json!({"max_body_bytes": 5}),
            json!({"required_tags": ["prod"]}),
        ] {
            let e = pol(doc.clone())
                .workspace_only()
                .expect_err(&doc.to_string());
            assert!(e.message.contains("project or key"), "{doc}: {}", e.message);
        }
    }

    #[test]
    fn og21_governance_exposes_each_valid_layer_in_order() {
        let g = Governance::from_columns(
            Some(uuid::Uuid::nil()),
            None,
            Some(&json!({"limits": {"rpm": 10}})),
            Some(&json!({"limits": {"tpm": 99}})),
        )
        .expect("governance");
        let layers: Vec<(Origin, Option<Rate>)> = g
            .policies()
            .map(|(o, p)| (o, p.limits.as_ref().map(|l| l.rate)))
            .collect();
        assert_eq!(
            layers,
            vec![
                (
                    Origin::Project,
                    Some(Rate {
                        rpm: Some(10),
                        tpm: None
                    })
                ),
                (
                    Origin::Key,
                    Some(Rate {
                        rpm: None,
                        tpm: Some(99)
                    })
                ),
            ]
        );
        assert_eq!(Origin::Workspace.as_str(), "workspace");
    }
}
