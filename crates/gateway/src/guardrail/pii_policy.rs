//! Class selection and literal exceptions over the existing detector set.
use super::policy::Mode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracelane_policy::pii::{
    RedactionEntry, ReversibleRedaction, is_secret_category, redact_reversible_from,
};

/// One class's action. `off` exists only here — never as a rail mode — so disabling a
/// class is always an explicit, visible choice (M2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassAction {
    Observe,
    Redact,
    Block,
    Off,
}

/// The built-in R2 behaviour of a class nobody listed (M2): redact, except IP addresses,
/// which are outside R2's default scope (`rails/r2_secrets_pii.rs` `Findings`).
fn builtin_default(class: &str) -> Option<Mode> {
    match class {
        "ipv4" | "ipv6" => None,
        _ => Some(Mode::Redact),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiiPolicy {
    /// Per-class overrides. A class NOT listed keeps its built-in default (M2, security
    /// review 2026-10-05 — it used to mean "no action", so `{}` disabled `secrets`).
    pub classes: BTreeMap<String, ClassAction>,
    #[serde(default)]
    pub allowlist: Vec<String>,
}
impl PiiPolicy {
    pub fn valid(&self) -> bool {
        let Some(limits) = limits() else { return false };
        self.classes.keys().all(|c| {
            matches!(
                c.as_str(),
                "secrets" | "email" | "phone" | "ipv4" | "ipv6" | "card" | "ssn"
            )
        }) && self.allowlist.len() <= limits.allowlist_count
            && self
                .allowlist
                .iter()
                .all(|s| !s.is_empty() && s.len() <= limits.allowlist_value_bytes)
    }
    pub fn action(&self, entry: &RedactionEntry) -> Option<Mode> {
        if self.allowlist.iter().any(|s| s == &entry.original) {
            return None;
        }
        let class = if is_secret_category(entry.category) {
            "secrets"
        } else if entry.category == "credit_card" {
            "card"
        } else {
            entry.category
        };
        match self.classes.get(class) {
            None => builtin_default(class),
            Some(ClassAction::Off) => None,
            Some(ClassAction::Observe) => Some(Mode::Observe),
            Some(ClassAction::Redact) => Some(Mode::Redact),
            Some(ClassAction::Block) => Some(Mode::Block),
        }
    }
    /// Does the policy CONFIGURE enforcement? Only explicit classes count — an unlisted
    /// class's built-in default is the same default a workspace with no policy gets, and
    /// that is not "configured" enforcement either (`Policy::enforces`).
    pub fn enforces(&self) -> bool {
        self.classes
            .values()
            .any(|m| matches!(m, ClassAction::Redact | ClassAction::Block))
    }
}

#[derive(Deserialize)]
struct Limits {
    allowlist_count: usize,
    allowlist_value_bytes: usize,
}
fn limits() -> Option<&'static Limits> {
    static LIMITS: std::sync::OnceLock<Option<Limits>> = std::sync::OnceLock::new();
    LIMITS
        .get_or_init(|| {
            let seed: serde_json::Value =
                serde_json::from_str(include_str!("../../../../apps/web/db/plans.v3.json")).ok()?;
            serde_json::from_value(seed["policy"]["guardrail_pii"].clone()).ok()
        })
        .as_ref()
}

/// Selective reversible rewrite. Entries restored here never reach the returned map.
/// Renumber retained placeholders densely to preserve uniqueness across request fields.
pub fn redact(text: &str, base: usize, policy: Option<&PiiPolicy>) -> ReversibleRedaction {
    let raw = redact_reversible_from(text, base);
    let Some(policy) = policy else { return raw };
    let mut out = ReversibleRedaction {
        redacted: raw.redacted,
        entries: Vec::new(),
    };
    for mut entry in raw.entries {
        if policy.action(&entry) == Some(Mode::Redact) {
            let placeholder = format!(
                "{{{{TL_REDACT:{}:{}}}}}",
                entry.category,
                base + out.entries.len()
            );
            out.redacted = out.redacted.replace(&entry.placeholder, &placeholder);
            entry.placeholder = placeholder;
            out.entries.push(entry);
        } else {
            out.redacted = out.redacted.replace(&entry.placeholder, &entry.original);
        }
    }
    out
}

pub fn residual(text: &str, policy: Option<&PiiPolicy>) -> bool {
    match policy {
        None => tracelane_policy::pii::contains_redactable(text),
        Some(p) => redact_reversible_from(text, 0)
            .entries
            .iter()
            .any(|e| matches!(p.action(e), Some(Mode::Redact | Mode::Block))),
    }
}

pub fn output(text: &str, policy: Option<&PiiPolicy>) -> String {
    let Some(p) = policy else {
        return tracelane_policy::pii::redact(text);
    };
    let r = redact(text, 0, Some(p));
    let mut out = r.redacted;
    for entry in r.entries {
        out = out.replace(
            &entry.placeholder,
            &format!("[REDACTED:{}]", entry.category),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn og33_selected_reversible_map_has_unique_dense_indices_across_fields() {
        let policy: PiiPolicy = serde_json::from_value(json!({
            "classes":{"email":"redact","secrets":"observe"},
            "allowlist":["allow@example.com"]
        }))
        .unwrap();
        let first = redact(
            "sk-abcdefghijklmnopqrstuvwxyz012345 allow@example.com a@example.com b@example.com",
            0,
            Some(&policy),
        );
        let second = redact("c@example.com", first.entries.len(), Some(&policy));
        let map: Vec<_> = first.entries.iter().chain(&second.entries).collect();
        assert_eq!(map.len(), 3);
        let unique: std::collections::BTreeSet<_> =
            map.iter().map(|e| e.placeholder.as_str()).collect();
        assert_eq!(unique.len(), 3);
        let mut entries = first.entries.clone();
        entries.extend(second.entries);
        let restored = tracelane_policy::pii::reinsert(
            &format!("{} {}", first.redacted, second.redacted),
            &entries,
        );
        assert_eq!(
            restored,
            "sk-abcdefghijklmnopqrstuvwxyz012345 allow@example.com a@example.com b@example.com c@example.com"
        );
    }

    #[test]
    fn og33_empty_classes_and_literal_matching_are_exact_and_bounded() {
        // M2: an empty map no longer disables anything — see the test below.
        let empty: PiiPolicy = serde_json::from_value(json!({"classes":{}})).unwrap();
        assert_ne!(
            redact("person@example.com", 0, Some(&empty)).redacted,
            "person@example.com"
        );
        let mut policy: PiiPolicy = serde_json::from_value(
            json!({"classes":{"email":"redact"},"allowlist":["person@example.com"]}),
        )
        .unwrap();
        assert!(
            redact("person@example.com", 0, Some(&policy))
                .entries
                .is_empty()
        );
        assert!(
            !redact("xperson@example.com", 0, Some(&policy))
                .entries
                .is_empty()
        );
        assert!(
            !redact("Person@example.com", 0, Some(&policy))
                .entries
                .is_empty()
        );
        policy.allowlist = vec!["x".into(); limits().unwrap().allowlist_count + 1];
        assert!(!policy.valid());
    }

    /// M2 (security review, 2026-10-05): a class not listed kept NO action, so
    /// `{"classes":{}}` silently disabled every redaction — `secrets` included. An
    /// unlisted class now keeps the built-in R2 default; turning one off is explicit.
    #[test]
    fn m2_unlisted_classes_keep_the_builtin_default_and_off_is_explicit() {
        const SECRET: &str = "sk-abcdefghijklmnopqrstuvwxyz012345";
        let text = format!("{SECRET} person@example.com");
        let empty: PiiPolicy = serde_json::from_value(json!({"classes":{}})).unwrap();
        let r = redact(&text, 0, Some(&empty));
        assert!(
            !r.redacted.contains(SECRET),
            "an empty class map must not disable secret redaction"
        );
        assert!(!r.redacted.contains("person@example.com"));
        assert!(residual(&text, Some(&empty)));
        assert!(!output(&text, Some(&empty)).contains(SECRET));

        let email_only: PiiPolicy =
            serde_json::from_value(json!({"classes":{"email":"observe"}})).unwrap();
        let r = redact(&text, 0, Some(&email_only));
        assert!(
            !r.redacted.contains(SECRET),
            "unlisted secrets keep the default"
        );
        assert!(
            r.redacted.contains("person@example.com"),
            "listed email observes"
        );

        let off: PiiPolicy = serde_json::from_value(json!({"classes":{"email":"off"}})).unwrap();
        assert!(off.valid());
        let r = redact(&text, 0, Some(&off));
        assert!(r.redacted.contains("person@example.com"), "explicit off");
        assert!(!r.redacted.contains(SECRET));
        // IPs stay out of the default R2 scope unless selected.
        assert!(redact("10.1.2.3", 0, Some(&empty)).entries.is_empty());
        // `off` is a class action only, never a rail mode.
        assert!(
            super::super::policy::Policy::parse(&json!({"rails":{"R8_injection":{"mode":"off"}}}))
                .is_none()
        );
    }
}
