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
        let policy: Self = serde_json::from_value(value.clone()).ok()?;
        for (name, rule) in &policy.rails {
            if rule
                .pii
                .as_ref()
                .is_some_and(|p| name != "R2_secrets_pii" || !p.valid())
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
                Some(policy) => out.rails.extend(policy.rails),
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
