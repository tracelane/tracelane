//! Class selection and literal exceptions over the existing detector set.
use super::policy::Mode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The `RedactionEntry::category` of every custom-entity match; the entity's name rides in
/// the placeholder (`{{TL_REDACT:custom_<name>:<idx>}}`).
pub const CUSTOM_CATEGORY: &str = "custom";

/// The entity name inside a custom placeholder.
fn custom_name(placeholder: &str) -> Option<&str> {
    placeholder
        .strip_prefix("{{TL_REDACT:custom_")?
        .split(':')
        .next()
}

/// The label a placeholder and an output marker carry: the category, or `custom_<name>`.
fn label(entry: &RedactionEntry) -> String {
    match custom_name(&entry.placeholder) {
        Some(name) if entry.category == CUSTOM_CATEGORY => format!("custom_{name}"),
        _ => entry.category.to_owned(),
    }
}

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
    /// A workspace's own regex entities (GWY-63), matched after the built-in detectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom: Vec<CustomEntity>,
    /// `custom` compiled once by `Policy::parse` (see [`PiiPolicy::compile`]).
    #[serde(skip)]
    pub compiled: Option<Arc<Compiled>>,
}

/// One named pattern and what a match does.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomEntity {
    /// `[a-z0-9_]{1,32}`: it rides in the placeholder and the `[REDACTED:custom_<name>]` marker.
    pub name: String,
    pub pattern: String,
    pub action: ClassAction,
}

/// The compiled custom entities: one `Regex` per entity, same order. No `RegexSet`: over
/// the same patterns it took 15 s on a 2 MiB adversarial text against <= 4.6 ms per
/// single regex (measured 2026-11-15, release; security review M2).
#[derive(Debug)]
pub struct Compiled {
    regexes: Vec<regex::Regex>,
}

/// Placeholder category prefix for a custom entity; the name follows it.
const CUSTOM_PREFIX: &str = "custom_";

/// The longest text `pattern` can match, in bytes, or `None` when unbounded or unparsable.
/// Bounded so a match always fits the stream hold-back (security review M3): an unbounded
/// pattern (`[^\n]+`) could match past it and leak its prefix before the match completes.
fn max_match_bytes(pattern: &str) -> Option<usize> {
    let hir = regex_syntax::parse(pattern).ok()?;
    // A Unicode word boundary makes the lazy DFA give up on non-ASCII text and fall back to
    // the slow engine (112 ms vs 3.4 ms per 2 MiB, measured 2026-11-15); `(?-u:\b)` is the
    // fast equivalent for ASCII identifiers.
    if hir.properties().look_set().contains_word_unicode() {
        return None;
    }
    hir.properties().maximum_len()
}

fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Compile with the reference-table program-size bound. `None` on any failure.
fn build(patterns: &[&str], compiled_bytes: usize) -> Option<Compiled> {
    let regexes = patterns
        .iter()
        .map(|p| {
            regex::RegexBuilder::new(p)
                .size_limit(compiled_bytes)
                .dfa_size_limit(compiled_bytes)
                .build()
                .ok()
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Compiled { regexes })
}

/// Shared compiled entities, keyed by the exact pattern list, so a policy parsed on every
/// request compiles once per distinct list (regex compilation costs milliseconds).
fn compiled_for(patterns: &[&str], compiled_bytes: usize) -> Option<Arc<Compiled>> {
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::LazyLock;
    // Bound: distinct live pattern lists on one node (single-digit tenants, 2026-11-15);
    // clearing at the cap costs a recompile, never a wrong answer.
    // Each entry is bounded by custom_count x custom_compiled_bytes, so the
    // cap also bounds memory: 16 x 10 x 256 KiB x 2 (program + DFA cache) = 80 MiB at
    // worst (security review M2).
    const CACHE_CAP: usize = 16;
    static CACHE: LazyLock<RwLock<HashMap<[u8; 32], Arc<Compiled>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
    let mut hash = blake3::Hasher::new();
    hash.update(&(compiled_bytes as u64).to_le_bytes());
    for p in patterns {
        hash.update(&(p.len() as u64).to_le_bytes());
        hash.update(p.as_bytes());
    }
    let key = *hash.finalize().as_bytes();
    if let Some(hit) = CACHE.read().get(&key) {
        return Some(Arc::clone(hit));
    }
    let compiled = Arc::new(build(patterns, compiled_bytes)?);
    let mut cache = CACHE.write();
    if cache.len() >= CACHE_CAP {
        cache.clear();
    }
    Some(Arc::clone(cache.entry(key).or_insert(compiled)))
}

impl PiiPolicy {
    /// Compile `custom` (bounded, cached). Called by `Policy::parse` after [`Self::valid`].
    /// Returns `false` if a pattern does not compile within the bound.
    pub fn compile(&mut self) -> bool {
        if self.custom.is_empty() {
            self.compiled = None;
            return true;
        }
        let Some(limits) = limits() else { return false };
        let patterns: Vec<&str> = self.custom.iter().map(|c| c.pattern.as_str()).collect();
        self.compiled = compiled_for(&patterns, limits.custom_compiled_bytes);
        self.compiled.is_some()
    }

    fn compiled(&self) -> Option<&Compiled> {
        self.compiled.as_deref()
    }

    /// Custom entities matching anywhere in `text` (cheap pre-check, one pass).
    pub fn custom_matches(&self, text: &str) -> bool {
        self.compiled()
            .is_some_and(|c| c.regexes.iter().any(|re| re.is_match(text)))
    }

    /// The custom pass, run on the ORIGINAL text before the built-in detectors (security
    /// review H1/M1: after them, a built-in placeholder, or a fake `{{TL_REDACT:` the caller
    /// typed, could hide or truncate a custom match).
    ///
    /// Enforcing matches (redact / block) become reversible
    /// `{{TL_REDACT:custom_<name>:<idx>}}` placeholders in the returned text; indices start
    /// at `base`. Observe matches are recorded as entries but left in the text, so an
    /// observe span never shadows a built-in redaction inside it. Overlaps resolve in
    /// favour of enforcing matches, then leftmost-longest.
    ///
    /// Returns `complete = false` (text unchanged, no entries) when the text holds more
    /// than `custom_max_matches` matches; callers fail CLOSED on that.
    pub fn custom_pass(&self, text: &str, base: usize) -> (String, Vec<RedactionEntry>, bool) {
        let unchanged = || (text.to_owned(), Vec::new(), true);
        let Some(c) = self.compiled() else {
            return unchanged();
        };
        let cap = limits().map_or(0, |l| l.custom_max_matches);
        let mut enforcing: Vec<(usize, usize, usize)> = Vec::new();
        let mut observing: Vec<(usize, usize, usize)> = Vec::new();
        let mut seen = 0usize;
        for (i, re) in c.regexes.iter().enumerate() {
            // An allowlisted literal is not a custom match, so the built-ins still scan it
            // (re-review L-a: as a span it would have hidden a secret inside it).
            for m in re
                .find_iter(text)
                .filter(|m| !m.is_empty() && !self.allowlist.iter().any(|a| a == m.as_str()))
            {
                seen += 1;
                if seen > cap {
                    return (text.to_owned(), Vec::new(), false);
                }
                match self.custom[i].action {
                    ClassAction::Redact | ClassAction::Block => {
                        enforcing.push((m.start(), m.end(), i))
                    }
                    _ => observing.push((m.start(), m.end(), i)),
                }
            }
        }
        let pick = |mut spans: Vec<(usize, usize, usize)>, taken: &[(usize, usize, usize)]| {
            spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
            let mut out: Vec<(usize, usize, usize)> = Vec::new();
            for span in spans {
                let clear = |o: &(usize, usize, usize)| span.1 <= o.0 || span.0 >= o.1;
                if out.last().is_none_or(clear) && taken.iter().all(clear) {
                    out.push(span);
                }
            }
            out
        };
        // Overlapping enforcing matches MERGE into their union under the strictest entity
        // (block over redact), never drop one: a dropped block-mode match would leave its
        // tail unredacted and lose the block (re-review N1).
        let strict = |i: usize| u8::from(self.custom[i].action == ClassAction::Block);
        enforcing.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut merged: Vec<(usize, usize, usize)> = Vec::with_capacity(enforcing.len());
        for (s, e, i) in enforcing {
            match merged.last_mut() {
                Some(last) if s < last.1 => {
                    last.1 = last.1.max(e);
                    if strict(i) > strict(last.2) {
                        last.2 = i;
                    }
                }
                _ => merged.push((s, e, i)),
            }
        }
        let enforcing = merged;
        let observing = pick(observing, &enforcing);
        let mut entries = Vec::with_capacity(enforcing.len() + observing.len());
        let entry = |(s, e, i): (usize, usize, usize), entries: &mut Vec<RedactionEntry>| {
            let placeholder = format!(
                "{{{{TL_REDACT:{CUSTOM_PREFIX}{}:{}}}}}",
                self.custom[i].name,
                base + entries.len()
            );
            entries.push(RedactionEntry {
                category: CUSTOM_CATEGORY,
                placeholder: placeholder.clone(),
                original: text[s..e].to_owned(),
            });
            placeholder
        };
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for span in &enforcing {
            out.push_str(&text[at..span.0]);
            out.push_str(&entry(*span, &mut entries));
            at = span.1;
        }
        out.push_str(&text[at..]);
        for span in observing {
            entry(span, &mut entries);
        }
        (out, entries, true)
    }

    pub fn valid(&self) -> bool {
        let Some(limits) = limits() else { return false };
        let custom_ok = self.custom.len() <= limits.custom_count
            && self.custom.iter().all(|c| {
                valid_name(&c.name)
                    && !c.pattern.is_empty()
                    && c.pattern.len() <= limits.custom_pattern_bytes
                    && c.action != ClassAction::Off
                    && max_match_bytes(&c.pattern)
                        .is_some_and(|n| n <= limits.custom_max_match_bytes)
            })
            && {
                let mut names: Vec<&str> = self.custom.iter().map(|c| c.name.as_str()).collect();
                names.sort_unstable();
                names.windows(2).all(|w| w[0] != w[1])
            };
        if !custom_ok {
            return false;
        }
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
        if entry.category == CUSTOM_CATEGORY {
            let name = custom_name(&entry.placeholder)?;
            return match self.custom.iter().find(|c| c.name == name)?.action {
                ClassAction::Off => None,
                ClassAction::Observe => Some(Mode::Observe),
                ClassAction::Redact => Some(Mode::Redact),
                ClassAction::Block => Some(Mode::Block),
            };
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
            .chain(self.custom.iter().map(|c| &c.action))
            .any(|m| matches!(m, ClassAction::Redact | ClassAction::Block))
    }
}

/// The custom-entity bounds the dashboard editor mirrors (`GET /v1/guardrails/policy`).
pub fn custom_limits() -> serde_json::Value {
    limits().map_or(serde_json::Value::Null, |l| {
        serde_json::json!({"custom_count": l.custom_count, "custom_pattern_bytes": l.custom_pattern_bytes})
    })
}

#[derive(Deserialize)]
struct Limits {
    allowlist_count: usize,
    allowlist_value_bytes: usize,
    custom_count: usize,
    custom_pattern_bytes: usize,
    custom_compiled_bytes: usize,
    custom_max_matches: usize,
    custom_max_match_bytes: usize,
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
/// The policy's custom entities (first, on the raw text), then the built-in detectors, as
/// one reversible map. `complete = false` means the custom match cap was reached and the
/// text is NOT redacted for custom entities; every caller fails CLOSED on it.
pub fn scan_checked(
    text: &str,
    base: usize,
    policy: Option<&PiiPolicy>,
) -> (ReversibleRedaction, bool) {
    let (pre, mut entries, complete) = match policy {
        Some(p) => p.custom_pass(text, base),
        None => (text.to_owned(), Vec::new(), true),
    };
    let builtin = redact_reversible_from(&pre, base + entries.len());
    entries.extend(builtin.entries);
    (
        ReversibleRedaction {
            redacted: builtin.redacted,
            entries,
        },
        complete,
    )
}

/// [`scan_checked`] for callers that pair it with [`residual`] or the R2 rail's verdict,
/// both of which fail closed on an incomplete scan.
pub fn scan(text: &str, base: usize, policy: Option<&PiiPolicy>) -> ReversibleRedaction {
    scan_checked(text, base, policy).0
}

/// Whether [`scan`] could find anything: the built-in pre-check or a custom match.
pub fn contains(text: &str, policy: Option<&PiiPolicy>) -> bool {
    tracelane_policy::pii::contains_redactable(text)
        || policy.is_some_and(|p| p.custom_matches(text))
}

pub fn redact(text: &str, base: usize, policy: Option<&PiiPolicy>) -> ReversibleRedaction {
    let raw = scan(text, base, policy);
    let Some(policy) = policy else { return raw };
    // One pass over the text, not one `replace` per entry (entries x length). A position
    // is swapped only when an EXACT entry placeholder starts there, so an unclosed
    // `{{TL_REDACT:` the caller typed cannot swallow a real one (security review L1).
    let mut out = ReversibleRedaction {
        redacted: String::with_capacity(raw.redacted.len()),
        entries: Vec::new(),
    };
    let mut swap: std::collections::HashMap<String, String> =
        std::collections::HashMap::with_capacity(raw.entries.len());
    for mut entry in raw.entries {
        if policy.action(&entry) == Some(Mode::Redact) {
            let placeholder = format!(
                "{{{{TL_REDACT:{}:{}}}}}",
                label(&entry),
                base + out.entries.len()
            );
            swap.insert(entry.placeholder.clone(), placeholder.clone());
            entry.placeholder = placeholder;
            out.entries.push(entry);
        } else {
            swap.insert(entry.placeholder.clone(), entry.original.clone());
        }
    }
    let text = raw.redacted;
    let mut at = 0;
    while let Some(rel) = text[at..].find("{{TL_REDACT:") {
        let open = at + rel;
        let exact = text[open..]
            .find("}}")
            .map(|c| &text[open..open + c + 2])
            .filter(|candidate| swap.contains_key(*candidate));
        out.redacted.push_str(&text[at..open]);
        match exact {
            Some(key) => {
                out.redacted.push_str(&swap[key]);
                at = open + key.len();
            }
            None => {
                out.redacted.push_str("{{");
                at = open + 2;
            }
        }
    }
    out.redacted.push_str(&text[at..]);
    out
}

pub fn residual(text: &str, policy: Option<&PiiPolicy>) -> bool {
    match policy {
        None => tracelane_policy::pii::contains_redactable(text),
        Some(p) => {
            let (r, complete) = scan_checked(text, 0, Some(p));
            !complete
                || r.entries
                    .iter()
                    .any(|e| matches!(p.action(e), Some(Mode::Redact | Mode::Block)))
        }
    }
}

pub fn output(text: &str, policy: Option<&PiiPolicy>) -> String {
    let Some(p) = policy else {
        return tracelane_policy::pii::redact(text);
    };
    let r = redact(text, 0, Some(p));
    let mut out = r.redacted;
    for entry in r.entries {
        out = out.replace(&entry.placeholder, &format!("[REDACTED:{}]", label(&entry)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn custom(entities: serde_json::Value) -> Option<PiiPolicy> {
        let mut p: PiiPolicy =
            serde_json::from_value(json!({"classes":{}, "custom": entities})).ok()?;
        (p.valid() && p.compile()).then_some(p)
    }
    fn emp(action: &str) -> PiiPolicy {
        custom(json!([{"name":"employee_id","pattern":"EMP-[0-9]{6}","action":action}])).unwrap()
    }

    #[test]
    fn gwy63_redact_is_reversible_and_labelled() {
        let p = emp("redact");
        let r = redact("ask EMP-123456 and EMP-654321", 0, Some(&p));
        assert!(!r.redacted.contains("EMP-123456"));
        assert!(
            r.redacted.contains("{{TL_REDACT:custom_employee_id:0}}"),
            "{}",
            r.redacted
        );
        assert_eq!(r.entries.len(), 2);
        assert_eq!(
            tracelane_policy::pii::reinsert(&r.redacted, &r.entries),
            "ask EMP-123456 and EMP-654321"
        );
        assert_eq!(
            output("id EMP-123456", Some(&p)),
            "id [REDACTED:custom_employee_id]"
        );
    }

    #[test]
    fn gwy63_indices_stay_unique_across_fields_and_with_builtins() {
        let p = emp("redact");
        let first = redact("a@example.com EMP-123456", 0, Some(&p));
        let second = redact("EMP-222222", first.entries.len(), Some(&p));
        let all: std::collections::BTreeSet<_> = first
            .entries
            .iter()
            .chain(&second.entries)
            .map(|e| e.placeholder.clone())
            .collect();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn gwy63_residual_and_contains_see_custom_matches() {
        let p = emp("block");
        assert!(residual("EMP-123456", Some(&p)));
        assert!(contains(
            "EMP-1",
            Some(&custom(json!([{"name":"e","pattern":"EMP-1","action":"redact"}])).unwrap())
        ));
        assert!(
            !contains("EMP-1", None),
            "below the built-in pre-check length"
        );
        assert!(!residual("EMP-123456", Some(&emp("observe"))));
    }

    #[test]
    fn gwy63_observe_leaves_text_unchanged_and_allowlist_wins() {
        assert_eq!(
            redact("EMP-123456", 0, Some(&emp("observe"))).redacted,
            "EMP-123456"
        );
        let mut p = emp("redact");
        p.allowlist = vec!["EMP-000000".into()];
        assert_eq!(redact("EMP-000000", 0, Some(&p)).redacted, "EMP-000000");
    }

    #[test]
    fn gwy63_never_matches_inside_an_existing_placeholder() {
        // Custom patterns run on the raw text first, so they never see a built-in placeholder
        // (whose index a digit pattern would otherwise rewrite).
        let p = custom(
            json!([{"name":"digits","pattern":"[0-9]{1,20}","action":"redact"},
                              {"name":"marker","pattern":"TL_REDACT","action":"redact"}]),
        )
        .unwrap();
        let r = redact("mail a@example.com", 0, Some(&p));
        assert_eq!(r.entries.len(), 1, "{:?}", r.redacted);
        assert_eq!(
            tracelane_policy::pii::reinsert(&r.redacted, &r.entries),
            "mail a@example.com"
        );
    }

    #[test]
    fn gwy63_empty_matches_produce_no_placeholders() {
        let p = custom(json!([{"name":"maybe","pattern":"x{0,5}","action":"redact"}])).unwrap();
        let r = redact("abc", 0, Some(&p));
        assert_eq!(r.redacted, "abc");
        assert!(r.entries.is_empty());
    }

    #[test]
    fn gwy63_validation_refuses_bad_names_patterns_and_actions() {
        let one = |name: &str, pattern: &str, action: &str| {
            custom(json!([{"name":name,"pattern":pattern,"action":action}]))
        };
        assert!(one("employee_id", "EMP-[0-9]{6}", "redact").is_some());
        for name in ["", "Employee", "a:b", "has space", &"x".repeat(33)] {
            assert!(one(name, "x", "redact").is_none(), "name {name:?}");
        }
        assert!(one("e", "", "redact").is_none(), "empty pattern");
        assert!(one("e", "(", "redact").is_none(), "does not compile");
        assert!(
            one("e", "x", "off").is_none(),
            "off is not an action for a custom entity"
        );
        let bytes = limits().unwrap().custom_pattern_bytes;
        assert!(one("e", &"x".repeat(bytes), "redact").is_some());
        assert!(one("e", &"x".repeat(bytes + 1), "redact").is_none());
        assert!(
            one("e", r"\w{1000}{1000}", "redact").is_none(),
            "over the compiled-size bound"
        );
        assert!(
            serde_json::from_value::<PiiPolicy>(json!({"classes":{},
            "custom":[{"name":"e","pattern":"x","action":"redact","flags":"i"}]}))
            .is_err()
        );
    }

    #[test]
    fn gwy63_validation_refuses_duplicates_and_too_many() {
        assert!(
            custom(json!([{"name":"e","pattern":"a","action":"redact"},
                              {"name":"e","pattern":"b","action":"block"}]))
            .is_none()
        );
        let n = limits().unwrap().custom_count;
        let many = |n: usize| {
            custom(serde_json::Value::Array(
                (0..n)
                    .map(|i| json!({"name":format!("e{i}"),"pattern":"x","action":"redact"}))
                    .collect(),
            ))
        };
        assert!(many(n).is_some());
        assert!(many(n + 1).is_none());
    }

    #[test]
    fn gwy63_many_matches_rewrite_in_linear_time() {
        // One `replace` per entry used to make this entries x length.
        let p = custom(json!([{"name":"e","pattern":"EMP-[0-9]{6}","action":"redact"}])).unwrap();
        let cap = limits().unwrap().custom_max_matches;
        let text = "EMP-123456 ".repeat(cap - 1);
        let r = redact(&text, 0, Some(&p));
        assert_eq!(r.entries.len(), cap - 1);
        assert!(!r.redacted.contains("EMP-123456"));
        assert_eq!(
            tracelane_policy::pii::reinsert(&r.redacted, &r.entries),
            text
        );
    }

    #[test]
    fn gwy63_review_h1_a_typed_placeholder_cannot_hide_a_custom_match() {
        let p = emp("redact");
        for text in [
            "{{TL_REDACT: EMP-123456 }}",
            "{{TL_REDACT: EMP-123456 then a@example.com",
        ] {
            let r = redact(text, 0, Some(&p));
            assert!(
                !r.redacted.contains("EMP-123456"),
                "{text} -> {}",
                r.redacted
            );
            assert!(residual(text, Some(&emp("block"))), "{text}");
        }
        let digits =
            custom(json!([{"name":"acct","pattern":"[0-9]{9}","action":"redact"}])).unwrap();
        let r = redact("{{TL_REDACT:x:123456789}}", 0, Some(&digits));
        assert!(!r.redacted.contains("123456789"), "{}", r.redacted);
    }

    #[test]
    fn gwy63_review_m1_a_builtin_inside_a_custom_span_cannot_truncate_it() {
        let mut p = custom(
            json!([{"name":"codename","pattern":"codename:[^\\n]{1,100}","action":"redact"}]),
        )
        .unwrap();
        p.classes.insert("email".into(), ClassAction::Observe);
        let r = redact(
            "codename: Bluebird, contact a@b.com, budget 4M",
            0,
            Some(&p),
        );
        assert!(!r.redacted.contains("budget 4M"), "{}", r.redacted);
        assert!(!r.redacted.contains("Bluebird"));
    }

    #[test]
    fn gwy63_review_m1_an_observe_span_never_shadows_a_builtin_redaction() {
        let p = custom(json!([{"name":"note","pattern":"note:[^\\n]{1,100}","action":"observe"}]))
            .unwrap();
        let r = redact("note: mail person@example.com", 0, Some(&p));
        assert!(!r.redacted.contains("person@example.com"), "{}", r.redacted);
    }

    #[test]
    fn gwy63_review_h2_custom_enforcing_entities_count_as_enforcing() {
        assert!(emp("block").enforces());
        assert!(emp("redact").enforces());
        assert!(!emp("observe").enforces());
    }

    #[test]
    fn gwy63_review_m3_unbounded_or_long_matches_are_refused() {
        let one = |pattern: &str| custom(json!([{"name":"e","pattern":pattern,"action":"redact"}]));
        for bad in ["[^\\n]+", "BEGIN[\\s\\S]*?END", "x.*", ".{300}"] {
            assert!(one(bad).is_none(), "{bad}");
        }
        assert!(one(".{1,100}").is_some(), "400 bytes at most");
        assert!(
            one(r"\bEMP-[0-9]{6}\b").is_none(),
            "Unicode word boundary forces the slow engine"
        );
        assert!(one(r"(?-u:\b)EMP-[0-9]{6}(?-u:\b)").is_some());
        assert!(
            limits().unwrap().custom_max_match_bytes
                < crate::guardrail::streaming::STREAM_HOLDBACK_CHARS,
            "a bounded match must fit the stream hold-back"
        );
    }

    #[test]
    fn gwy63_review_l1_an_unclosed_typed_opener_does_not_swallow_a_real_placeholder() {
        let p: PiiPolicy = serde_json::from_value(json!({"classes":{"email":"redact"}})).unwrap();
        let text = "{{TL_REDACT: oops person@example.com";
        let r = redact(text, 0, Some(&p));
        assert!(!r.redacted.contains("person@example.com"), "{}", r.redacted);
        assert_eq!(r.entries.len(), 1);
        assert_eq!(
            tracelane_policy::pii::reinsert(&r.redacted, &r.entries),
            text
        );
        // Observe must restore the original, not leave a stale placeholder behind.
        let observe: PiiPolicy =
            serde_json::from_value(json!({"classes":{"email":"observe"}})).unwrap();
        assert_eq!(redact(text, 0, Some(&observe)).redacted, text);
    }

    #[test]
    fn gwy63_rereview_n1_overlapping_enforcing_matches_merge_and_keep_block() {
        let p = custom(json!([
            {"name":"a","pattern":"ACCT-[0-9]{4}","action":"redact"},
            {"name":"b","pattern":"[0-9]{4}-[0-9]{6}","action":"block"}
        ]))
        .unwrap();
        let (out, entries, complete) = p.custom_pass("ACCT-1234-567890 ok", 0);
        assert!(complete);
        assert!(!out.contains("567890"), "{out}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].original, "ACCT-1234-567890");
        assert_eq!(
            p.action(&entries[0]),
            Some(Mode::Block),
            "the stricter entity wins"
        );
        assert!(residual("ACCT-1234-567890", Some(&p)));
    }

    #[test]
    fn gwy63_rereview_la_an_allowlisted_custom_match_is_still_scanned_by_builtins() {
        let mut p =
            custom(json!([{"name":"cfg","pattern":"cfg=[a-zA-Z0-9-]{1,60}","action":"redact"}]))
                .unwrap();
        p.allowlist = vec!["cfg=sk-abcdefghijklmnopqrstuvwxyz012345".into()];
        let r = redact("cfg=sk-abcdefghijklmnopqrstuvwxyz012345", 0, Some(&p));
        assert!(
            !r.redacted.contains("sk-abcdefghijklmnopqrstuvwxyz012345"),
            "{}",
            r.redacted
        );
    }

    #[test]
    fn gwy63_same_patterns_share_one_compiled_program() {
        let a = emp("redact");
        let b = emp("block");
        assert!(Arc::ptr_eq(
            a.compiled.as_ref().unwrap(),
            b.compiled.as_ref().unwrap()
        ));
    }

    #[test]
    fn gwy63_no_custom_keeps_builtin_behaviour() {
        let p: PiiPolicy = serde_json::from_value(json!({"classes":{}})).unwrap();
        assert!(p.valid());
        assert!(serde_json::to_value(&p).unwrap().get("custom").is_none());
        assert!(
            !redact("a@example.com", 0, Some(&p))
                .redacted
                .contains("a@example.com")
        );
    }

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
