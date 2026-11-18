//! Scoped, cached rail policy. Entitlement remains the outer ceiling.
use super::outcome::{Outcome, RailOutcome};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Redact,
    Block,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub thresholds: BTreeMap<String, f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pii: Option<super::pii_policy::PiiPolicy>,
    /// `R7_topic_competitor` only: the workspace's own term lists (GWY-60).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<Terms>,
    /// `terms` compiled once by [`Policy::parse`], so every clone of this policy (a
    /// stream's per-delta snapshot included) reuses one matcher.
    #[serde(skip)]
    pub compiled_terms: Option<std::sync::Arc<super::rails::r7_topic_competitor::R7Config>>,
}

/// A workspace's R7 lists. Bounded by `plans.v3.json` `policy.guardrail_terms`; a list
/// over the bound, a blank term, or a control character invalidates the whole document.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    #[serde(default)]
    pub denied_topics: Vec<String>,
    #[serde(default)]
    pub competitors: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct TermLimits {
    pub list_count: usize,
    pub term_bytes: usize,
    pub min_matches_examined: usize,
    pub matches_per_byte: usize,
}
/// `None` when the reference table is unreadable: then no `terms` validate (fail-CLOSED on
/// what a policy may carry; the rail itself is unaffected).
pub fn term_limits() -> Option<&'static TermLimits> {
    static LIMITS: std::sync::OnceLock<Option<TermLimits>> = std::sync::OnceLock::new();
    LIMITS
        .get_or_init(|| {
            let seed: serde_json::Value =
                serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
            serde_json::from_value(seed["policy"]["guardrail_terms"].clone()).ok()
        })
        .as_ref()
}

impl Terms {
    fn valid(&self) -> bool {
        let Some(limits) = term_limits() else {
            return false;
        };
        let ok = |list: &[String]| {
            list.len() <= limits.list_count
                && list.iter().all(|t| {
                    // At least one letter or digit: a punctuation-only term carries no
                    // boundary rule and overlaps everywhere (security review H1).
                    t.chars().any(char::is_alphanumeric)
                        && t.len() <= limits.term_bytes
                        && !t.chars().any(|c| c.is_control() && !c.is_whitespace())
                })
        };
        ok(&self.denied_topics) && ok(&self.competitors)
    }
}
fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(skip)]
    pub hooks: Vec<super::hooks::Hook>,
    #[serde(skip)]
    pub unavailable: bool,
    /// A stored scope layer did not validate and was SKIPPED (M3): that scope uses what
    /// is above it. Part of the policy fingerprint, so a batch frozen under the full
    /// policy is not silently run under the degraded one.
    #[serde(skip)]
    pub degraded: bool,
    pub rails: BTreeMap<String, Rule>,
}

pub const RAILS: &[&str] = &[
    "R1_cost",
    "R2_secrets_pii",
    "R3_schema",
    "R3_pinning",
    "R4_trifecta",
    "R5_format",
    "R6_sysprompt_leak",
    "R7_topic_competitor",
    "R8_injection",
];

impl Policy {
    /// Fail-closed fallback: an invalid document contributes no override.
    pub fn parse(value: &serde_json::Value) -> Option<Self> {
        let mut policy: Self = serde_json::from_value(value.clone()).ok()?;
        for (name, rule) in &policy.rails {
            if rule
                .pii
                .as_ref()
                .is_some_and(|p| name != "R2_secrets_pii" || !p.valid())
                || rule
                    .terms
                    .as_ref()
                    .is_some_and(|t| name != "R7_topic_competitor" || !t.valid())
                || !RAILS.contains(&name.as_str())
                || (rule.mode == Mode::Redact
                    && !matches!(name.as_str(), "R2_secrets_pii" | "R6_sysprompt_leak"))
            {
                return None;
            }
            for (key, value) in &rule.thresholds {
                if !value.is_finite() {
                    return None;
                }
                let valid = match (name.as_str(), key.as_str()) {
                    ("R8_injection", "score") => (0.0..=1.0).contains(value),
                    ("R6_sysprompt_leak", "min_tokens") => {
                        *value >= 1.0
                            && *value <= super::rails::r6_sysprompt_leak::MIN_LEAK_TOKENS as f64
                            && value.fract() == 0.0
                    }
                    (
                        "R1_cost",
                        "max_input_tokens"
                        | "max_output_tokens"
                        | "max_steps_per_run"
                        | "max_identical_tool_calls"
                        | "max_subagent_depth",
                    ) => *value >= 1.0 && *value <= f64::from(u32::MAX) && value.fract() == 0.0,
                    _ => false,
                };
                if !valid {
                    return None;
                }
            }
        }
        for rule in policy.rails.values_mut() {
            if let Some(pii) = rule.pii.as_mut()
                && !pii.compile()
            {
                return None;
            }
            rule.compiled_terms = rule
                .terms
                .as_ref()
                .map(super::rails::r7_topic_competitor::tenant_config);
        }
        Some(policy)
    }

    pub fn apply(&self, name: &str, mut outcome: RailOutcome) -> RailOutcome {
        let Some(rule) = self.rails.get(name) else {
            return outcome;
        };
        if name == "R2_secrets_pii" && rule.pii.is_some() {
            return outcome;
        }
        // Inability to scan is not a detection: observe never clears it.
        if matches!(
            outcome.reason_code,
            Some("UNSCANNABLE_MEDIA" | "BUDGET_STATE_UNKNOWN" | "DETECTOR_ERROR" | "RAIL_TIMEOUT")
        ) {
            return outcome;
        }
        if matches!(
            outcome.outcome,
            Outcome::Block | Outcome::Redact | Outcome::Warn
        ) {
            if let (Some(score), Some(threshold)) = (outcome.score, rule.thresholds.get("score")) {
                outcome.threshold = Some(*threshold);
                if score < *threshold {
                    outcome.outcome = Outcome::Allow;
                    return outcome;
                }
            }
            outcome.outcome = match rule.mode {
                Mode::Observe => Outcome::Warn,
                Mode::Redact => Outcome::Redact,
                Mode::Block => Outcome::Block,
            };
        }
        outcome
    }

    pub fn has_controls(&self) -> bool {
        self.unavailable || !self.hooks.is_empty() || !self.rails.is_empty()
    }
    pub fn has_hooks(&self) -> bool {
        self.unavailable || !self.hooks.is_empty()
    }

    pub fn pii(&self) -> Option<&super::pii_policy::PiiPolicy> {
        self.rails.get("R2_secrets_pii")?.pii.as_ref()
    }
    pub fn enforces(&self, name: &str) -> bool {
        self.rails.get(name).is_some_and(|r| {
            r.enabled
                && r.pii
                    .as_ref()
                    .map_or(r.mode != Mode::Observe, |p| p.enforces())
        })
    }
    pub fn enabled(&self, name: &str) -> bool {
        self.rails.get(name).is_none_or(|rule| rule.enabled)
    }

    pub fn threshold(&self, name: &str, key: &str) -> Option<f64> {
        self.rails.get(name)?.thresholds.get(key).copied()
    }
}

/// One tenant's control-plane snapshot. Never shared across tenant cache keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policies {
    pub hooks: Vec<super::hooks::Hook>,
    pub workspace: Option<serde_json::Value>,
    pub revision: String,
    pub keys: BTreeMap<uuid::Uuid, serde_json::Value>,
    pub projects: BTreeMap<uuid::Uuid, serde_json::Value>,
    pub key_projects: BTreeMap<uuid::Uuid, uuid::Uuid>,
}
impl Policies {
    pub fn effective(&self, key: Option<&str>, project: Option<uuid::Uuid>) -> Policy {
        let key = key.and_then(|k| uuid::Uuid::parse_str(k).ok());
        let mut out = Policy::default();
        for layer in [
            self.workspace.as_ref(),
            project.and_then(|p| self.projects.get(&p)),
            key.and_then(|k| self.keys.get(&k)),
        ]
        .into_iter()
        .flatten()
        {
            match Policy::parse(layer) {
                Some(policy) => {
                    for (name, mut rule) in policy.rails {
                        // B-638: a scoped rule that is silent about `terms` keeps the lists
                        // of the rule it replaces; an explicit `terms` (even empty) replaces.
                        if rule.terms.is_none()
                            && let Some(prev) = out.rails.get(&name)
                        {
                            rule.terms.clone_from(&prev.terms);
                            rule.compiled_terms.clone_from(&prev.compiled_terms);
                        }
                        out.rails.insert(name, rule);
                    }
                }
                // M3 (security review, 2026-10-05): an invalid layer is skipped — never
                // `out = Policy::default()`, which threw away a stricter workspace (or
                // project) layer above it. OG-30: "a malformed stored document at any
                // selected scope discards THAT scope's overrides".
                None => out.degraded = true,
            }
        }
        out.hooks = self.hooks.clone();
        out
    }
}

pub(crate) fn fingerprint(policy: &Policy, gate: &super::rail::RailGate, revision: &str) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(format!("{gate:?}:{revision}:").as_bytes());
    if policy.degraded {
        hash.update(b"degraded:");
    }
    // Only validated, finite values enter Policy; serialization cannot fail.
    hash.update(&serde_json::to_vec(policy).unwrap_or_default());
    hash.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn terms_doc(rail: &str, terms: serde_json::Value) -> serde_json::Value {
        json!({"rails":{rail:{"terms":terms}}})
    }
    #[test]
    fn gwy60_terms_validate_on_r7() {
        let p = Policy::parse(&terms_doc(
            "R7_topic_competitor",
            json!({"denied_topics":["merger plans"],"competitors":["Initech"]}),
        ))
        .expect("valid");
        let t = p.rails["R7_topic_competitor"].terms.as_ref().unwrap();
        assert_eq!(t.competitors, vec!["Initech".to_string()]);
    }
    #[test]
    fn gwy60_terms_need_a_letter_or_digit() {
        for bad in [".", "...", "++", "—"] {
            assert!(
                Policy::parse(&terms_doc(
                    "R7_topic_competitor",
                    json!({"denied_topics":[bad]})
                ))
                .is_none(),
                "{bad:?} must be refused"
            );
        }
        assert!(
            Policy::parse(&terms_doc(
                "R7_topic_competitor",
                json!({"competitors":["C++","機密"]})
            ))
            .is_some()
        );
    }
    #[test]
    fn gwy60_redact_mode_stays_refused_on_r7() {
        // The streaming seam redacts with the static list; a tenant rule must never yield Redact.
        assert!(Policy::parse(&json!({"rails":{"R7_topic_competitor":{"mode":"redact","terms":{"competitors":["A"]}}}})).is_none());
    }
    #[test]
    fn gwy60_parse_compiles_terms_once_and_clones_share_it() {
        let p = Policy::parse(&terms_doc(
            "R7_topic_competitor",
            json!({"competitors":["Initech"]}),
        ))
        .unwrap();
        let a = p.rails["R7_topic_competitor"]
            .compiled_terms
            .clone()
            .unwrap();
        let cloned = p.clone();
        assert!(std::sync::Arc::ptr_eq(
            &a,
            cloned.rails["R7_topic_competitor"]
                .compiled_terms
                .as_ref()
                .unwrap()
        ));
    }
    #[test]
    fn gwy60_terms_refused_on_any_other_rail() {
        assert!(Policy::parse(&terms_doc("R8_injection", json!({"competitors":["x"]}))).is_none());
    }
    #[test]
    fn gwy60_terms_refuse_unknown_fields() {
        assert!(Policy::parse(&terms_doc("R7_topic_competitor", json!({"regex":["x"]}))).is_none());
    }
    #[test]
    fn gwy60_terms_refuse_blank_and_control_characters() {
        for bad in ["", "   ", "a\u{0}b", "a\u{1b}[31m"] {
            assert!(
                Policy::parse(&terms_doc(
                    "R7_topic_competitor",
                    json!({"competitors":[bad]})
                ))
                .is_none(),
                "{bad:?} must be refused"
            );
        }
    }
    #[test]
    fn gwy60_terms_bounds_come_from_the_reference_table() {
        let seed: serde_json::Value =
            serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).unwrap();
        let count = seed["policy"]["guardrail_terms"]["list_count"]
            .as_u64()
            .unwrap() as usize;
        let bytes = seed["policy"]["guardrail_terms"]["term_bytes"]
            .as_u64()
            .unwrap() as usize;
        let at = |n: usize, len: usize| {
            Policy::parse(&terms_doc(
                "R7_topic_competitor",
                json!({"denied_topics": (0..n).map(|i| format!("{i:0>len$}")).collect::<Vec<_>>()}),
            ))
        };
        assert!(at(count, bytes).is_some(), "the bound itself is allowed");
        assert!(
            at(count + 1, 8).is_none(),
            "one term over the count is refused"
        );
        assert!(
            at(1, bytes + 1).is_none(),
            "one byte over the length is refused"
        );
    }
    #[test]
    fn gwy60_terms_without_mode_default_to_observe() {
        let p = Policy::parse(&terms_doc(
            "R7_topic_competitor",
            json!({"competitors":["Initech"]}),
        ))
        .unwrap();
        assert!(!p.enforces("R7_topic_competitor"));
        assert_eq!(
            p.apply("R7_topic_competitor", RailOutcome::block("TOPIC_DENIED"))
                .outcome,
            Outcome::Warn
        );
    }
    #[test]
    fn gwy60_terms_change_the_policy_fingerprint() {
        let gate = super::super::rail::RailGate::all();
        let a = Policy::parse(&terms_doc(
            "R7_topic_competitor",
            json!({"competitors":["A"]}),
        ))
        .unwrap();
        let b = Policy::parse(&terms_doc(
            "R7_topic_competitor",
            json!({"competitors":["B"]}),
        ))
        .unwrap();
        assert_ne!(fingerprint(&a, &gate, "r"), fingerprint(&b, &gate, "r"));
    }
    #[test]
    fn og30_observe_records_a_hit_without_blocking() {
        let policy = Policy::parse(&json!({"rails":{"R8_injection":{"mode":"observe"}}})).unwrap();
        let out = policy.apply("R8_injection", RailOutcome::block("INJECTION"));
        assert_eq!(
            out.outcome,
            Outcome::Warn,
            "an explicit observe policy must not block"
        );
    }
    #[test]
    fn og30_block_is_opt_in_and_changes_a_warning() {
        let policy = Policy::parse(&json!({"rails":{"R5_format":{"mode":"block"}}})).unwrap();
        assert_eq!(
            policy
                .apply("R5_format", RailOutcome::warn("FORMAT_INVALID_JSON"))
                .outcome,
            Outcome::Block
        );
    }
    #[test]
    fn og30_invalid_policy_falls_back_to_defaults() {
        for value in [
            json!({"rails":{"invented":{}}}),
            json!({"rails":{"R8_injection":{"thresholds":{"score":2.0}}}}),
            json!({"rails":{"R8_injection":{"mode":"redact"}}}),
            json!({"rails":{"R7_topic_competitor":{"mode":"redact"}}}),
            json!({"rails":{"R2_secrets_pii":{"thresholds":{"score":0.5}}}}),
        ] {
            assert!(Policy::parse(&value).is_none(), "must reject {value}");
        }
    }

    /// B-638: a key or project R7 rule that does not mention `terms` keeps the workspace's
    /// lists; an explicit `terms` (even empty) replaces them.
    #[test]
    fn b638_scoped_r7_rule_without_terms_keeps_the_workspace_lists() {
        let key = uuid::Uuid::new_v4();
        let project = uuid::Uuid::new_v4();
        let mut p = Policies {
            workspace: Some(terms_doc(
                "R7_topic_competitor",
                json!({"denied_topics":["merger plans"],"competitors":["Initech"]}),
            )),
            ..Default::default()
        };
        p.keys.insert(
            key,
            json!({"rails":{"R7_topic_competitor":{"mode":"block"}}}),
        );
        let merged = p.effective(Some(&key.to_string()), None);
        let r7 = merged.rails.get("R7_topic_competitor").expect("r7");
        assert_eq!(r7.mode, Mode::Block, "the key's mode applies");
        assert_eq!(
            r7.terms.as_ref().map(|t| t.competitors.clone()),
            Some(vec!["Initech".to_owned()]),
            "and the workspace lists survive"
        );
        assert!(r7.compiled_terms.is_some());
        // A key under a project inherits the project's own lists.
        p.key_projects.insert(key, project);
        p.projects.insert(
            project,
            terms_doc("R7_topic_competitor", json!({"competitors":["Globex"]})),
        );
        let merged = p.effective(Some(&key.to_string()), Some(project));
        assert_eq!(
            merged.rails["R7_topic_competitor"]
                .terms
                .as_ref()
                .map(|t| t.competitors.clone()),
            Some(vec!["Globex".to_owned()])
        );
        // Explicit empty lists replace: a scope can opt out on purpose.
        p.keys.insert(
            key,
            json!({"rails":{"R7_topic_competitor":{"mode":"block","terms":{}}}}),
        );
        let merged = p.effective(Some(&key.to_string()), Some(project));
        assert_eq!(
            merged.rails["R7_topic_competitor"].terms,
            Some(Terms::default())
        );
        // Another rail never gains terms.
        p.keys
            .insert(key, json!({"rails":{"R8_injection":{"mode":"block"}}}));
        let merged = p.effective(Some(&key.to_string()), None);
        assert!(merged.rails["R8_injection"].terms.is_none());
    }

    /// M3 (security review, 2026-10-05): one invalid scoped (key / project) policy reset
    /// the WHOLE effective policy to defaults, discarding a stricter WORKSPACE layer. An
    /// invalid layer is now skipped — that scope falls back to what is above it — and the
    /// earlier layers stand.
    #[test]
    fn m3_an_invalid_scoped_layer_never_discards_the_stricter_workspace_layer() {
        let key = uuid::Uuid::new_v4();
        let project = uuid::Uuid::new_v4();
        let mut p = Policies {
            workspace: Some(json!({"rails":{"R8_injection":{"mode":"block"}}})),
            ..Default::default()
        };
        p.key_projects.insert(key, project);
        p.projects
            .insert(project, json!({"rails":{"R5_format":{"mode":"block"}}}));
        p.keys.insert(key, json!({"rails":{"invented_rail":{}}}));
        let merged = p.effective(Some(&key.to_string()), Some(project));
        assert_eq!(
            merged.rails.get("R8_injection").map(|r| r.mode),
            Some(Mode::Block),
            "the workspace's block survives an invalid key layer"
        );
        assert!(
            merged.degraded,
            "and the effective policy says a layer was skipped"
        );
        assert_eq!(
            merged.rails.get("R5_format").map(|r| r.mode),
            Some(Mode::Block),
            "and so does the project's"
        );
        p.projects
            .insert(project, json!({"rails":{"R8_injection":{"mode":"redact"}}}));
        let merged = p.effective(None, Some(project));
        assert_eq!(
            merged.rails.get("R8_injection").map(|r| r.mode),
            Some(Mode::Block),
            "an invalid project layer cannot weaken the workspace either"
        );
        assert!(merged.degraded);
        assert!(
            !p.effective(None, None).degraded,
            "the workspace alone is valid"
        );
    }
}
