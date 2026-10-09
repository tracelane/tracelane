//! Ordered request hints and deterministic model splits. Every possible outcome is
//! separately enumerated for admission; hints never grant permission to a target.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracelane_shared::key_policy::glob_match;

use super::{
    Candidate, Estimate, FieldError, PlanError, Rng, RoutePlan, RoutingDoc, RoutingScope,
    RoutingState,
};

#[derive(Deserialize, Serialize)]
pub(crate) struct Limits {
    pub max_rules: usize,
    pub max_arms: usize,
    pub max_match_value_bytes: usize,
    pub sticky_key_max_bytes: usize,
    pub match_header_denylist: Vec<String>,
}

pub(crate) fn limits() -> &'static Limits {
    static LIMITS: OnceLock<Limits> = OnceLock::new();
    LIMITS.get_or_init(|| {
        serde_json::from_str::<Value>(include_str!("../../translation_policy.v1.json"))
            .ok()
            .and_then(|v| serde_json::from_value::<Limits>(v["routing"].clone()).ok())
            .filter(|l| {
                l.max_rules > 0
                    && l.max_arms >= 2
                    && l.max_match_value_bytes > 0
                    && l.sticky_key_max_bytes > 0
                    && !l.match_header_denylist.is_empty()
            })
            .unwrap_or(Limits {
                max_rules: 0,
                max_arms: 0,
                max_match_value_bytes: 0,
                sticky_key_max_bytes: 0,
                match_header_denylist: vec![],
            })
    })
}

fn default_wires() -> Vec<String> {
    vec!["chat".into(), "responses".into()]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub id: String,
    #[serde(default = "default_wires")]
    pub wires: Vec<String>,
    #[serde(rename = "match")]
    pub predicate: Match,
    pub action: Action,
    /// Assigned by the server, preserved by rule id; request-supplied salts are ignored.
    #[serde(default)]
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Values {
    One(String),
    Many(Vec<String>),
}
impl Values {
    fn items(&self) -> &[String] {
        match self {
            Self::One(v) => std::slice::from_ref(v),
            Self::Many(v) => v,
        }
    }
    fn matches(&self, value: Option<&str>) -> bool {
        value.is_some_and(|v| self.items().iter().any(|s| s == v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, rename = "in", skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Metadata {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    #[serde(default, rename = "in", skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Match {
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Values>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<Values>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<Values>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_user_id: Option<Values>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Action {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split: Option<Split>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Split {
    pub sticky_by: Vec<String>,
    #[serde(default)]
    pub on_missing_identity: Missing,
    pub arms: Vec<Arm>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Missing {
    #[default]
    Stable,
    Random,
    Refuse,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Arm {
    pub name: String,
    pub route_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bp: Option<u32>,
}

pub(crate) fn invalid(index: usize, message: impl Into<String>) -> FieldError {
    FieldError {
        code: "invalid_rule",
        field: format!("rules[{index}]"),
        message: message.into(),
    }
}
fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= limits().max_match_value_bytes
}
fn header_ok(name: &str) -> bool {
    bounded(name)
        && axum::http::HeaderName::from_bytes(name.as_bytes()).is_ok()
        && !limits()
            .match_header_denylist
            .iter()
            .any(|s| s.eq_ignore_ascii_case(name))
}
fn predicate_ok(equals: Option<&str>, prefix: Option<&str>, values: Option<&[String]>) -> bool {
    usize::from(equals.is_some()) + usize::from(prefix.is_some()) + usize::from(values.is_some())
        == 1
        && equals.is_none_or(bounded)
        && prefix.is_none_or(bounded)
        && values.is_none_or(|v| {
            !v.is_empty() && v.len() <= limits().max_rules && v.iter().all(|s| bounded(s))
        })
}
fn targets(action: &Action) -> Vec<&str> {
    action
        .route_to
        .as_deref()
        .into_iter()
        .chain(
            action
                .split
                .iter()
                .flat_map(|s| s.arms.iter().map(|a| a.route_to.as_str())),
        )
        .collect()
}
fn concrete<'a>(doc: &'a RoutingDoc, target: &'a str) -> Vec<&'a str> {
    doc.virtual_models.get(target).map_or_else(
        || vec![target],
        |v| v.targets.iter().map(|t| t.model.as_str()).collect(),
    )
}

pub(crate) fn validate(doc: &RoutingDoc, stored: bool) -> Result<(), FieldError> {
    if doc.rules.len() > limits().max_rules {
        return Err(invalid(0, "too many routing rules"));
    }
    let mut ids = BTreeSet::new();
    for (i, r) in doc.rules.iter().enumerate() {
        let bad = |s| invalid(i, s);
        if !bounded(&r.id) || !ids.insert(&r.id) {
            return Err(bad("rule ids must be bounded, nonempty and unique"));
        }
        if r.wires.is_empty()
            || r.wires.len() > 4
            || r.wires
                .iter()
                .any(|s| !matches!(s.as_str(), "chat" | "responses" | "messages" | "gemini"))
        {
            return Err(bad("unsupported rule wire"));
        }
        let m = &r.predicate;
        if !bounded(&m.model) || m.tag.as_deref().is_some_and(|s| !bounded(s)) {
            return Err(bad("model and tag must be bounded and nonempty"));
        }
        for v in [&m.key_id, &m.project_id, &m.environment, &m.end_user_id]
            .into_iter()
            .flatten()
        {
            if v.items().is_empty()
                || v.items().len() > limits().max_rules
                || v.items().iter().any(|s| !bounded(s))
            {
                return Err(bad("match values must be bounded and nonempty"));
            }
        }
        for v in [&m.key_id, &m.project_id].into_iter().flatten() {
            if v.items().iter().any(|s| uuid::Uuid::parse_str(s).is_err()) {
                return Err(bad("key_id and project_id must be UUIDs"));
            }
        }
        if m.header.as_ref().is_some_and(|h| {
            !header_ok(&h.name)
                || !predicate_ok(
                    h.equals.as_deref(),
                    h.prefix.as_deref(),
                    h.values.as_deref(),
                )
        }) {
            return Err(bad("header is denied or its predicate is invalid"));
        }
        if m.metadata.as_ref().is_some_and(|m| {
            !bounded(&m.key) || !predicate_ok(m.equals.as_deref(), None, m.values.as_deref())
        }) {
            return Err(bad("metadata predicate is invalid"));
        }
        if r.action.route_to.is_some() == r.action.split.is_some() {
            return Err(bad("choose exactly one action: route_to or split"));
        }
        if let Some(s) = &r.action.split {
            if stored && !bounded(&r.salt) {
                return Err(bad("stored split has no valid server salt"));
            }
            if s.arms.len() < 2 || s.arms.len() > limits().max_arms {
                return Err(bad("split needs between two and max_arms arms"));
            }
            let mut names = BTreeSet::new();
            let mut sum = 0u32;
            for (n, a) in s.arms.iter().enumerate() {
                if !bounded(&a.name) || !names.insert(&a.name) {
                    return Err(bad("arm names must be bounded, nonempty and unique"));
                }
                if n == s.arms.len() - 1 {
                    if a.bp.is_some() {
                        return Err(bad("last arm must be the remainder, without bp"));
                    }
                } else {
                    let Some(bp) = a.bp.filter(|bp| *bp <= 10_000) else {
                        return Err(bad("non-final arms require bp between 0 and 10000"));
                    };
                    sum += bp;
                }
            }
            if sum > 10_000 {
                return Err(bad("arm basis points exceed 10000"));
            }
            if s.sticky_by.len() > limits().max_rules
                || s.sticky_by.iter().any(|v| match v.strip_prefix("header:") {
                    Some(h) => !header_ok(h),
                    None => !matches!(v.as_str(), "end_user" | "session" | "key"),
                })
            {
                return Err(bad("invalid or denied sticky source"));
            }
        }
        for target in targets(&r.action) {
            if !bounded(target) {
                return Err(bad("target must be bounded and nonempty"));
            }
            let models = concrete(doc, target);
            if models.is_empty() {
                return Err(bad("virtual target is empty"));
            }
            for model in models {
                let Some(provider) = super::provider_of(model) else {
                    return Err(bad("target is not routable"));
                };
                if (r.wires.iter().any(|w| w == "messages") && provider != "anthropic")
                    || (r.wires.iter().any(|w| w == "gemini") && provider != "google")
                {
                    return Err(bad("native wire target belongs to another provider"));
                }
            }
        }
    }
    Ok(())
}

/// Ignore caller salts, keeping the server's prior assignment for the same rule id.
pub(crate) fn assign_salts(doc: &mut RoutingDoc, previous: Option<&Value>) {
    for rule in &mut doc.rules {
        rule.salt = previous
            .and_then(|v| {
                v.get("rules")?
                    .as_array()?
                    .iter()
                    .find(|r| r.get("id").and_then(Value::as_str) == Some(&rule.id))?
                    .get("salt")?
                    .as_str()
            })
            .filter(|s| bounded(s))
            .map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned);
    }
}

/// Request-local only: intentionally neither Debug nor Serialize (contains identity).
#[derive(Default)]
pub(crate) struct Facts {
    pub headers: HeaderMap,
    pub metadata: BTreeMap<String, String>,
    pub tags: Vec<String>,
    pub key_id: Option<String>,
    pub project_id: Option<String>,
    pub environment: Option<String>,
    pub end_user: Option<String>,
    pub session: Option<String>,
    pub stream: bool,
    pub trace_id: String,
}
impl Facts {
    pub(crate) fn request(
        headers: &HeaderMap,
        labels: &crate::server::request_labels::BoundedLabels,
        identity: &crate::server::CallerIdentity,
        claims: &crate::auth::Claims,
        body: &Value,
        trace_id: uuid::Uuid,
    ) -> Self {
        Self {
            headers: headers.clone(),
            metadata: labels.0.metadata.clone(),
            tags: labels.0.tags.clone(),
            key_id: claims.api_key_id().map(|k| k.to_string()),
            project_id: identity.project_id.clone(),
            environment: identity
                .key_environment
                .clone()
                .or_else(|| labels.0.environment.clone()),
            end_user: identity.end_user_id.clone(),
            session: identity.conversation_id.clone(),
            stream: body.get("stream").and_then(Value::as_bool).unwrap_or(false),
            trace_id: trace_id.to_string(),
        }
    }
}
fn matches_value(
    value: Option<&str>,
    equals: Option<&str>,
    prefix: Option<&str>,
    values: Option<&[String]>,
) -> bool {
    value.is_some_and(|v| {
        equals == Some(v)
            || prefix.is_some_and(|p| v.starts_with(p))
            || values.is_some_and(|xs| xs.iter().any(|s| s == v))
    })
}
impl Match {
    fn matches(&self, model: &str, f: &Facts) -> bool {
        glob_match(&self.model, model)
            && self.header.as_ref().is_none_or(|h| {
                matches_value(
                    f.headers.get(&h.name).and_then(|v| v.to_str().ok()),
                    h.equals.as_deref(),
                    h.prefix.as_deref(),
                    h.values.as_deref(),
                )
            })
            && self.metadata.as_ref().is_none_or(|m| {
                matches_value(
                    f.metadata.get(&m.key).map(String::as_str),
                    m.equals.as_deref(),
                    None,
                    m.values.as_deref(),
                )
            })
            && self.tag.as_ref().is_none_or(|t| f.tags.contains(t))
            && self
                .key_id
                .as_ref()
                .is_none_or(|v| v.matches(f.key_id.as_deref()))
            && self
                .project_id
                .as_ref()
                .is_none_or(|v| v.matches(f.project_id.as_deref()))
            && self
                .environment
                .as_ref()
                .is_none_or(|v| v.matches(f.environment.as_deref()))
            && self
                .end_user_id
                .as_ref()
                .is_none_or(|v| v.matches(f.end_user.as_deref()))
            && self.stream.is_none_or(|v| v == f.stream)
    }
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Assignment {
    pub rule: String,
    pub arm: Option<String>,
    pub bucket: Option<u32>,
    pub sticky_source: Option<&'static str>,
    pub non_sticky: bool,
    pub arm_pct: Option<f64>,
    #[serde(skip)]
    pub namespace: Option<String>,
}
fn choose<'a>(rule: &'a Rule, f: &Facts) -> Result<(&'a str, Assignment), PlanError> {
    let mut assignment = Assignment {
        rule: rule.id.clone(),
        arm: None,
        bucket: None,
        sticky_source: None,
        non_sticky: false,
        arm_pct: None,
        namespace: None,
    };
    if let Some(target) = &rule.action.route_to {
        return Ok((target, assignment));
    }
    let split = rule
        .action
        .split
        .as_ref()
        .ok_or(PlanError::RoutingInvalid)?;
    let identity = split.sticky_by.iter().find_map(|s| {
        let (source, value) = match s.strip_prefix("header:") {
            Some(h) => ("header", f.headers.get(h).and_then(|v| v.to_str().ok())),
            None => match s.as_str() {
                "end_user" => ("end_user", f.end_user.as_deref()),
                "session" => ("session", f.session.as_deref()),
                "key" => ("key", f.key_id.as_deref()),
                _ => ("none", None),
            },
        };
        value
            .filter(|v| !v.is_empty() && v.len() <= limits().sticky_key_max_bytes)
            .map(|v| (source, v))
    });
    assignment.sticky_source = Some(identity.map_or("none", |(s, _)| s));
    assignment.non_sticky = identity.is_none();
    let value = match (identity, split.on_missing_identity) {
        (Some((_, value)), _) => Some(value),
        (None, Missing::Stable) => None,
        (None, Missing::Random) => Some(f.trace_id.as_str()),
        (None, Missing::Refuse) => return Err(PlanError::IdentityRequired),
    };
    assignment.bucket =
        value.map(|v| (crate::online_eval::sample_draw(&rule.salt, v.as_bytes()) % 10_000) as u32);
    let mut lower = 0;
    for arm in &split.arms {
        let bp = arm.bp.unwrap_or(10_000 - lower);
        if assignment.bucket.is_some_and(|b| b < lower + bp)
            || (assignment.bucket.is_none() && arm.bp.is_none())
        {
            assignment.arm = Some(arm.name.clone());
            assignment.arm_pct = Some(f64::from(bp) / 100.0);
            // Unambiguous namespace; no identity or raw sticky value is retained.
            assignment.namespace = serde_json::to_string(&(&rule.salt, &rule.id, &arm.name)).ok();
            return Ok((&arm.route_to, assignment));
        }
        lower += bp;
    }
    Err(PlanError::RoutingInvalid)
}

pub(crate) fn plan(
    scope: &RoutingScope,
    requested: &str,
    state: &RoutingState,
    est: Estimate,
    rng: Rng<'_>,
    facts: &Facts,
) -> Result<Option<RoutePlan>, PlanError> {
    let Some(doc) = state.doc() else {
        return super::plan(scope, requested, state, est, rng);
    };
    let rules: Vec<_> = doc
        .rules
        .iter()
        .filter(|r| {
            r.wires.iter().any(|w| w == scope.wire.as_str())
                && glob_match(&r.predicate.model, requested)
        })
        .collect();
    if rules.is_empty() {
        return super::plan(scope, requested, state, est, rng);
    }
    let selected = rules
        .iter()
        .find(|r| r.predicate.matches(requested, facts))
        .map(|r| choose(r, facts))
        .transpose()?;
    let target = selected.as_ref().map_or(requested, |(t, _)| *t);
    let mut plan = super::plan(scope, target, state, est, rng)?.unwrap_or_else(|| RoutePlan {
        requested: requested.to_owned(),
        virtual_model: None,
        strategy: None,
        candidates: super::provider_of(target)
            .map(|provider_id| Candidate {
                model: target.to_owned(),
                provider_id,
                target_index: 0,
                weight_pct: None,
                ewma_ttfb_ms: None,
            })
            .into_iter()
            .collect(),
        skipped: vec![],
        policy_targets: vec![target.to_owned()],
        policy_aliases: vec![],
        assignment: None,
    });
    plan.requested = requested.to_owned();
    plan.assignment = selected.map(|(_, a)| a);
    let mut all: BTreeSet<String> = plan.policy_targets.iter().cloned().collect();
    let mut aliases = BTreeSet::new();
    for r in rules {
        for target in targets(&r.action) {
            if doc.virtual_models.contains_key(target) {
                aliases.insert(target.to_owned());
            }
            all.extend(concrete(doc, target).into_iter().map(str::to_owned));
        }
    }
    plan.policy_aliases = aliases.into_iter().collect();
    // Keep the dispatched model first: its subject carries the token facts.
    for target in all {
        if !plan.policy_targets.contains(&target) {
            plan.policy_targets.push(target);
        }
    }
    if plan.dispatches() && plan.candidates.is_empty() {
        return Err(PlanError::RoutingInvalid);
    }
    Ok(Some(plan))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::Route as _;
    use serde_json::json;

    fn rule() -> Rule {
        serde_json::from_value(json!({"id":"split","salt":"og12-golden-salt","match":{"model":"gpt-*"},"action":{"split":{"sticky_by":["header:x-sticky","end_user","session","key"],"arms":[{"name":"canary","route_to":"gpt-4.1","bp":1000},{"name":"stable","route_to":"gpt-4o"}]}}})).unwrap()
    }
    fn document(r: Rule) -> RoutingDoc {
        RoutingDoc {
            rules: vec![r],
            ..Default::default()
        }
    }

    #[test]
    fn og12_match_matrix_ands_every_field_and_first_rule_wins() {
        let id = uuid::Uuid::new_v4().to_string();
        let m: Match = serde_json::from_value(json!({"model":"gpt-*","header":{"name":"X-Tier","prefix":"gold"},"metadata":{"key":"tier","in":["gold"]},"tag":"eval","key_id":[id],"project_id":id,"environment":"prod","end_user_id":["user"],"stream":true})).unwrap();
        let facts = || {
            let mut headers = HeaderMap::new();
            headers.insert("x-tier", "gold-team".parse().unwrap());
            Facts {
                headers,
                metadata: BTreeMap::from([("tier".into(), "gold".into())]),
                tags: vec!["eval".into()],
                key_id: Some(id.clone()),
                project_id: Some(id.clone()),
                environment: Some("prod".into()),
                end_user: Some("user".into()),
                stream: true,
                ..Default::default()
            }
        };
        assert!(m.matches("gpt-4o", &facts()));
        assert!(!m.matches("claude-haiku-4-5", &facts()));
        for n in 0..8 {
            let mut f = facts();
            match n {
                0 => {
                    f.headers.clear();
                }
                1 => f.metadata.clear(),
                2 => f.tags.clear(),
                3 => f.key_id = None,
                4 => f.project_id = None,
                5 => f.environment = None,
                6 => f.end_user = None,
                _ => f.stream = false,
            }
            assert!(!m.matches("gpt-4o", &f), "field {n}");
        }
        let mut first = rule();
        first.predicate = m;
        first.action = Action {
            route_to: Some("gpt-4.1".into()),
            split: None,
        };
        let mut second = first.clone();
        second.id = "second".into();
        second.action.route_to = Some("gpt-4o-mini".into());
        let state = RoutingState::Valid(std::sync::Arc::new(RoutingDoc {
            rules: vec![first, second],
            ..Default::default()
        }));
        let p = plan(
            &crate::admission::Chat::ROUTING,
            "gpt-4o",
            &state,
            Estimate::default(),
            &mut || 0,
            &facts(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(p.candidates[0].model, "gpt-4.1");
        assert_eq!(p.assignment.unwrap().rule, "split");
        assert!(p.policy_targets.contains(&"gpt-4o-mini".to_owned()));
    }

    #[test]
    fn og12_write_validation_rejects_credentials_bad_weights_and_cross_wire_targets() {
        assert_eq!(limits().max_rules, 64);
        for name in &limits().match_header_denylist {
            let mut r = rule();
            r.predicate.header = Some(Header {
                name: name.to_uppercase(),
                equals: Some("x".into()),
                prefix: None,
                values: None,
            });
            assert_eq!(
                validate(&document(r), false).unwrap_err().code,
                "invalid_rule"
            );
            let mut r = rule();
            r.action.split.as_mut().unwrap().sticky_by = vec![format!("header:{name}")];
            assert!(validate(&document(r), false).is_err());
        }
        for mode in 0..5 {
            let mut r = rule();
            match mode {
                0 => r.action.split.as_mut().unwrap().arms[0].bp = Some(10_001),
                1 => r.action.split.as_mut().unwrap().arms[1].bp = Some(1),
                2 => r.action.split.as_mut().unwrap().arms[0].bp = None,
                3 => r.wires = vec!["messages".into()],
                _ => r.wires = vec!["realtime".into()],
            }
            assert!(validate(&document(r), false).is_err(), "case {mode}");
        }
        let mut r = rule();
        r.action = Action {
            route_to: Some("claude-haiku-4-5".into()),
            split: None,
        };
        r.wires = vec!["messages".into()];
        assert!(validate(&document(r), false).is_ok());
        let bad = json!({"rules":[{"id":"x","match":{},"action":{"route_to":"gpt-4o"}}]});
        let err = super::super::parse_for_write(&bad).unwrap_err();
        assert_eq!(err.code, "invalid_rule");
        assert_eq!(err.field, "rules[0]");
        let mut d = document(rule());
        d.rules[0].salt.clear();
        assert!(matches!(
            RoutingState::from_stored(Some(&serde_json::to_value(d).unwrap())),
            RoutingState::Invalid
        ));
    }

    #[test]
    fn og12_sticky_golden_distribution_and_monotonic_ramp() {
        let r = rule();
        let mut f = Facts {
            end_user: Some("fixed-user".into()),
            ..Default::default()
        };
        let golden = choose(&r, &f).unwrap().1;
        for _ in 0..1000 {
            assert_eq!(choose(&r, &f).unwrap().1, golden);
        }
        let mut ramp = r.clone();
        ramp.action.split.as_mut().unwrap().arms[0].bp = Some(2500);
        let (mut small, mut large) = (0, 0);
        for i in 0..10_000 {
            f.end_user = Some(format!("user-{i}"));
            let a = choose(&r, &f).unwrap().1.arm.as_deref() == Some("canary");
            let b = choose(&ramp, &f).unwrap().1.arm.as_deref() == Some("canary");
            assert!(!a || b);
            small += usize::from(a);
            large += usize::from(b);
        }
        assert_eq!(golden.bucket, Some(1938));
        assert_eq!((small, large), (982, 2422));
    }

    #[test]
    fn og12_missing_identity_modes_caps_and_source_priority() {
        let mut r = rule();
        let mut f = Facts::default();
        let a = choose(&r, &f).unwrap().1;
        assert_eq!(a.arm.as_deref(), Some("stable"));
        assert!(a.non_sticky);
        assert_eq!(a.bucket, None);
        r.action.split.as_mut().unwrap().on_missing_identity = Missing::Refuse;
        assert_eq!(choose(&r, &f).unwrap_err(), PlanError::IdentityRequired);
        r.action.split.as_mut().unwrap().on_missing_identity = Missing::Random;
        let mut buckets = BTreeSet::new();
        for _ in 0..30 {
            f.trace_id = uuid::Uuid::new_v4().to_string();
            buckets.insert(choose(&r, &f).unwrap().1.bucket);
        }
        assert!(buckets.len() > 1);
        f.end_user = Some("end".into());
        f.session = Some("session".into());
        f.key_id = Some("key".into());
        f.headers.insert(
            "x-sticky",
            "a".repeat(limits().sticky_key_max_bytes + 1)
                .parse()
                .unwrap(),
        );
        assert_eq!(choose(&r, &f).unwrap().1.sticky_source, Some("end_user"));
        f.headers.insert("x-sticky", "present".parse().unwrap());
        let a = choose(&r, &f).unwrap().1;
        assert_eq!(a.sticky_source, Some("header"));
        assert!(!serde_json::to_string(&a).unwrap().contains("present"));
        f.headers.clear();
        f.end_user = None;
        assert_eq!(choose(&r, &f).unwrap().1.sticky_source, Some("session"));
        f.session = None;
        assert_eq!(choose(&r, &f).unwrap().1.sticky_source, Some("key"));
    }

    #[test]
    fn og12_salts_are_server_owned_stable_and_rule_specific() {
        let mut d = document(rule());
        let old = d.rules[0].salt.clone();
        assign_salts(&mut d, None);
        assert_ne!(d.rules[0].salt, old);
        let stored = serde_json::to_value(&d).unwrap();
        let salt = d.rules[0].salt.clone();
        d.rules[0].salt = "attacker".into();
        let mut second = d.rules[0].clone();
        second.id = "different".into();
        d.rules.push(second);
        assign_salts(&mut d, Some(&stored));
        assert_eq!(d.rules[0].salt, salt);
        assert_ne!(d.rules[1].salt, salt);
    }

    #[test]
    fn og12_unmatched_hint_preserves_workspace_alias_pricing_and_subject() {
        let mut r = rule();
        r.predicate.model = "workspace-alias".into();
        r.predicate.stream = Some(true);
        let state = RoutingState::Valid(std::sync::Arc::new(document(r)));
        let p = plan(
            &crate::admission::Chat::ROUTING,
            "workspace-alias",
            &state,
            Estimate::default(),
            &mut || 0,
            &Facts::default(),
        )
        .unwrap()
        .unwrap();
        assert!(!p.dispatches());
        let ent = crate::entitlement_cache::ResolvedEntitlements {
            model_aliases: std::sync::Arc::new(BTreeMap::from([(
                "workspace-alias".into(),
                "gpt-4o".into(),
            )])),
            ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
        };
        assert_eq!(
            super::super::pricing(&p, Some(&ent)),
            crate::admission::Pricing::Priced
        );
        let request = tracelane_shared::key_policy::PolicyRequest {
            subjects: vec![tracelane_shared::key_policy::Subject {
                line: None,
                model: tracelane_shared::key_policy::Fact::Known("workspace-alias".into()),
                workspace_alias: true,
                provider: None,
                input_tokens: tracelane_shared::key_policy::Fact::NotApplicable,
                output_cap: tracelane_shared::key_policy::Fact::NotApplicable,
            }],
            body_bytes: tracelane_shared::key_policy::Fact::NotApplicable,
        };
        assert!(super::super::expand(request, Some(&p)).subjects[0].workspace_alias);
    }

    #[test]
    fn og12_wire_filter_no_match_and_simulate_share_the_decision() {
        let mut r = rule();
        r.wires = vec!["chat".into()];
        let state = RoutingState::Valid(std::sync::Arc::new(document(r.clone())));
        assert!(
            plan(
                &crate::anthropic_messages::Messages::ROUTING,
                "claude-haiku-4-5",
                &state,
                Estimate::default(),
                &mut || 0,
                &Facts::default()
            )
            .unwrap()
            .is_none()
        );
        let f = Facts {
            end_user: Some("fixed-user".into()),
            ..Default::default()
        };
        let p = plan(
            &crate::admission::Chat::ROUTING,
            "gpt-4o",
            &state,
            Estimate::default(),
            &mut || 0,
            &f,
        )
        .unwrap()
        .unwrap();
        let sim = crate::routing::routes::plan_json(
            "gpt-4o",
            &crate::admission::Chat::ROUTING,
            Some(&p),
            &[],
        );
        assert_eq!(
            sim["assignment"],
            serde_json::to_value(choose(&r, &f).unwrap().1).unwrap()
        );
        r.predicate.stream = Some(true);
        let state = RoutingState::Valid(std::sync::Arc::new(document(r)));
        let p = plan(
            &crate::admission::Chat::ROUTING,
            "gpt-4o",
            &state,
            Estimate::default(),
            &mut || 0,
            &f,
        )
        .unwrap()
        .unwrap();
        assert!(!p.dispatches());
        assert_eq!(p.candidates[0].model, "gpt-4o");
        assert!(p.policy_targets.contains(&"gpt-4.1".into()));
    }
}
