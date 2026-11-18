//! R7 — Topic / competitor keyword blocklist, fast path (the guardrail spec
//! §3 R7): off-domain / brand-risk / competitor governance.
//!
//! Aho-Corasick multi-pattern match (ASCII case-insensitive, whole-word) over two per-workspace
//! term lists: a **denied-topic** list (a hit → **block** `TOPIC_DENIED`) and a
//! **competitor** list (a hit → **redact** each mention to `[COMPETITOR]`,
//! `COMPETITOR_MENTION`). Both sides; fail OPEN-LOUD; < 150µs. Semantic /
//! contextual topic detection is V1.1 (needs a model) — this is the keyword tier.
//!
//! Config & the seam: the term lists live in an [`R7Config`] shared (one `Arc`)
//! between this rail (detection → verdict) and the response-streaming seam
//! (which calls [`R7Config::redact_competitors`] to rewrite competitor mentions
//! in the streamed output). Empty lists → `not_applicable` (the safe default
//! until a workspace configures terms).
//!
//! **V1 boundary:** the denied-topic **block** is enforced on BOTH sides
//! (request → 403, response → the seam terminates the stream). Competitor
//! **redaction** is applied RESPONSE-side (via the seam) — a competitor mention
//! in the *request* is recorded but not rewritten (rewriting the user's own
//! mention going TO the model is low value; the governance concern is the model
//! OUTPUTTING competitor/denied content). Request-side competitor rewrite is a
//! documented follow-up.
//!
//! **Workspace lists (GWY-60):** a workspace supplies its own lists as `terms` on its
//! `R7_topic_competitor` policy rule (`guardrail::policy::Terms`, bounded by
//! `plans.v3.json` `policy.guardrail_terms`). They replace the built-in lists for that
//! request; the rule's mode then decides the action (observe by default, so a
//! configured list records verdicts before it blocks anything). Matching is whole-word,
//! ASCII case-insensitive, with whitespace runs collapsed.

use std::sync::Arc;

use aho_corasick::AhoCorasick;

use crate::guardrail::context::GuardrailContext;
use crate::guardrail::outcome::{FailMode, RailError, RailOutcome, Sides, reason_codes};
use crate::guardrail::rail::{GuardrailFeature, Rail, RailFuture};
use tracelane_shared::{ContentPart, MessageContent};

const COMPETITOR_MARKER: &str = "[COMPETITOR]";

/// The per-workspace R7 term lists, compiled to case-insensitive Aho-Corasick
/// automatons. Shared (one `Arc`) by the rail + the streaming seam.
#[derive(Debug, Default)]
pub struct R7Config {
    denied: Option<AhoCorasick>,
    competitors: Option<AhoCorasick>,
}

/// Collapse every whitespace run to one ASCII space, so `"a  b"` and `"a\nb"` match the
/// term `"a b"`. Detection only: redaction works on the raw text.
fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A word character for boundary purposes: a match must not continue a word on either
/// side, so the term `AcmeCorp` does not fire inside `AcmeCorpology` (labelled case
/// `r7_compound_configured`). A term whose edge is itself punctuation (`C++`) has no
/// boundary requirement on that edge. Scripts written without spaces between words
/// (Chinese, Japanese kana, Thai, Lao, Khmer, Myanmar) carry none either: there a
/// substring match is the only match available.
fn word_char(c: char) -> bool {
    (c.is_alphanumeric() || c == '_') && !spaceless_script(c)
}

fn spaceless_script(c: char) -> bool {
    matches!(c as u32,
        0x0E00..=0x0EFF   // Thai, Lao
        | 0x1000..=0x109F // Myanmar
        | 0x1780..=0x17FF // Khmer
        | 0x3040..=0x30FF // Hiragana, Katakana
        | 0x3400..=0x4DBF // CJK extension A
        | 0x4E00..=0x9FFF // CJK unified
        | 0xF900..=0xFAFF // CJK compatibility
        | 0x20000..=0x2FA1F) // CJK extensions B+
}

/// Whether `text[start..end]` stands as a whole word or phrase.
fn whole_word(text: &str, start: usize, end: usize) -> bool {
    let inner = &text[start..end];
    let edge_word = |c: Option<char>| c.is_some_and(word_char);
    let left_ok = !edge_word(inner.chars().next()) || !edge_word(text[..start].chars().next_back());
    let right_ok = !edge_word(inner.chars().next_back()) || !edge_word(text[end..].chars().next());
    left_ok && right_ok
}

/// The scan stopped at its match budget (security review H1): text built so that
/// terms overlap at every position would otherwise make one request unbounded work.
#[derive(Debug, PartialEq, Eq)]
pub struct BudgetExceeded;

/// Candidate matches a scan of `text` may examine: `max(min_matches_examined,
/// matches_per_byte x text bytes)` from `plans.v3.json` `policy.guardrail_terms`. It grows
/// with the input, so ordinary prose or padding built from a term (well under one
/// candidate per byte) never reaches it (security review M2); only nested terms over text
/// built for them do. Unreadable table -> 0, so a scan that sees any match stops rather
/// than running unbounded (no terms validate in that state anyway).
fn match_budget(text: &str) -> usize {
    crate::guardrail::policy::term_limits().map_or(0, |l| {
        l.min_matches_examined
            .max(l.matches_per_byte.saturating_mul(text.len()))
    })
}

/// Walk candidate matches, calling `accept` for each whole-word one until it returns
/// `false`. Examines at most `budget` candidates.
fn scan(
    ac: &AhoCorasick,
    text: &str,
    budget: usize,
    mut accept: impl FnMut(usize, usize) -> bool,
) -> Result<(), BudgetExceeded> {
    for (seen, m) in ac.find_overlapping_iter(text).enumerate() {
        if seen >= budget {
            return Err(BudgetExceeded);
        }
        if whole_word(text, m.start(), m.end()) && !accept(m.start(), m.end()) {
            return Ok(());
        }
    }
    Ok(())
}

fn any_whole_word(ac: &AhoCorasick, text: &str, budget: usize) -> Result<bool, BudgetExceeded> {
    let mut found = false;
    scan(ac, text, budget, |_, _| {
        found = true;
        false
    })?;
    Ok(found)
}

/// Whole-word matches, leftmost first, longest first at a tie, never overlapping. At the
/// budget it returns what it found so far (redaction is best-effort past that point).
fn whole_word_spans(ac: &AhoCorasick, text: &str, budget: usize) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    let _bounded = scan(ac, text, budget, |s, e| {
        hits.push((s, e));
        true
    });
    hits.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(hits.len());
    for hit in hits {
        if out.last().is_none_or(|last| hit.0 >= last.1) {
            out.push(hit);
        }
    }
    out
}

impl R7Config {
    /// Compile two term lists. Terms are whitespace-normalised and matched ASCII
    /// case-insensitively as whole words. Empty and blank terms are dropped.
    #[must_use]
    pub fn from_terms<S: AsRef<str>>(denied_topics: &[S], competitor_terms: &[S]) -> Self {
        Self {
            denied: Self::build(denied_topics),
            competitors: Self::build(competitor_terms),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn new<S: AsRef<str>>(denied_topics: &[S], competitor_terms: &[S]) -> Self {
        Self::from_terms(denied_topics, competitor_terms)
    }

    fn build<S: AsRef<str>>(terms: &[S]) -> Option<AhoCorasick> {
        let terms: Vec<String> = terms
            .iter()
            .map(|t| normalize(t.as_ref()))
            .filter(|t| !t.is_empty())
            .collect();
        if terms.is_empty() {
            return None;
        }
        // # Errors: a list that fails to compile is disabled with one WARN (fail-OPEN,
        // like the rail). Validated lists are bounded (`policy::Terms`), so this is not
        // expected outside a construction bug.
        match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&terms)
        {
            Ok(ac) => Some(ac),
            Err(err) => {
                tracing::warn!(error = %err, "R7 term list failed to compile — disabling that list");
                None
            }
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.denied.is_none() && self.competitors.is_none()
    }

    /// # Errors
    /// [`BudgetExceeded`] when the scan stops at its match budget (the rail decides the direction).
    pub fn has_denied(&self, text: &str) -> Result<bool, BudgetExceeded> {
        self.denied.as_ref().map_or(Ok(false), |ac| {
            let t = normalize(text);
            any_whole_word(ac, &t, match_budget(&t))
        })
    }

    /// # Errors
    /// [`BudgetExceeded`] when the scan stops at its match budget (the rail decides the direction).
    pub fn has_competitor(&self, text: &str) -> Result<bool, BudgetExceeded> {
        self.competitors.as_ref().map_or(Ok(false), |ac| {
            let t = normalize(text);
            any_whole_word(ac, &t, match_budget(&t))
        })
    }

    /// Rewrite each whole-word competitor mention in `text` to `[COMPETITOR]`.
    #[must_use]
    pub fn redact_competitors(&self, text: &str) -> (String, bool) {
        let Some(ac) = &self.competitors else {
            return (text.to_owned(), false);
        };
        let spans = whole_word_spans(ac, text, match_budget(text));
        if spans.is_empty() {
            return (text.to_owned(), false);
        }
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for (s, e) in spans {
            out.push_str(&text[at..s]);
            out.push_str(COMPETITOR_MARKER);
            at = e;
        }
        out.push_str(&text[at..]);
        (out, true)
    }
}

/// The compiled lists for a tenant policy's `terms`, shared across policies with the
/// same lists. Called by [`crate::guardrail::policy::Policy::parse`] (once per request's
/// effective policy: one hash and an uncontended read lock); the result rides on the rule
/// (`compiled_terms`), so clones of that policy, a stream's per-delta snapshots included,
/// never come back here.
pub(crate) fn tenant_config(terms: &crate::guardrail::policy::Terms) -> Arc<R7Config> {
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::LazyLock;
    // Bound: distinct live term lists across every tenant on one node. Prod has single-digit
    // tenants (2026-11-15); clearing at the cap costs one recompile per list, never a wrong answer.
    const CACHE_CAP: usize = 1024;
    static CACHE: LazyLock<RwLock<HashMap<[u8; 32], Arc<R7Config>>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));
    // Length-prefixed, so ["ab"] and ["a","b"] never share a key.
    let mut hash = blake3::Hasher::new();
    for (tag, list) in [(b'd', &terms.denied_topics), (b'c', &terms.competitors)] {
        hash.update(&[tag]);
        hash.update(&(list.len() as u64).to_le_bytes());
        for term in list {
            hash.update(&(term.len() as u64).to_le_bytes());
            hash.update(term.as_bytes());
        }
    }
    let key = *hash.finalize().as_bytes();
    if let Some(hit) = CACHE.read().get(&key) {
        return Arc::clone(hit);
    }
    let compiled = Arc::new(R7Config::from_terms(
        &terms.denied_topics,
        &terms.competitors,
    ));
    let mut cache = CACHE.write();
    if cache.len() >= CACHE_CAP {
        cache.clear();
    }
    Arc::clone(cache.entry(key).or_insert(compiled))
}

#[derive(Debug, Clone)]
pub struct R7TopicCompetitor {
    config: Arc<R7Config>,
}

impl Default for R7TopicCompetitor {
    fn default() -> Self {
        Self::new()
    }
}

impl R7TopicCompetitor {
    /// An R7 with no terms (matches nothing → `not_applicable`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(Arc::new(R7Config::default()))
    }

    /// An R7 sharing a compiled term-list config (the same `Arc` the seam reads).
    #[must_use]
    pub fn with_config(config: Arc<R7Config>) -> Self {
        Self { config }
    }

    /// Test and labelled-eval entry point; production goes through [`Rail::evaluate`].
    #[cfg(test)]
    pub fn evaluate_sync(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        self.try_evaluate(ctx)
            .expect("R7 scan within its match budget")
    }

    /// # Errors
    /// [`RailError::WorkBudgetExceeded`] when a scan stops at its match budget under an
    /// observe rule: the rail's fail mode (OPEN-loud) records a `fail_open` verdict. Under
    /// a rule the workspace set to Block, the same event is fail-CLOSED instead: a
    /// `DETECTOR_ERROR` block, so input built to exhaust the budget cannot turn an
    /// enforced list into a pass (security review M2).
    pub fn try_evaluate(&self, ctx: &GuardrailContext<'_>) -> Result<RailOutcome, RailError> {
        // A workspace's own lists (its guardrail policy) replace the built-in ones.
        let tenant = ctx
            .policy
            .rails
            .get("R7_topic_competitor")
            .and_then(|rule| {
                rule.compiled_terms
                    .clone()
                    .or_else(|| rule.terms.as_ref().map(tenant_config))
            });
        let config = tenant.as_ref().unwrap_or(&self.config);
        if config.is_empty() {
            return Ok(RailOutcome::not_applicable());
        }
        let text = collect_text(ctx);
        if text.trim().is_empty() {
            return Ok(RailOutcome::not_applicable());
        }
        let over = |_: BudgetExceeded| {
            if ctx.policy.enforces("R7_topic_competitor") {
                Ok(RailOutcome::block(reason_codes::DETECTOR_ERROR))
            } else {
                Err(RailError::WorkBudgetExceeded)
            }
        };
        let denied = match config.has_denied(&text) {
            Ok(hit) => hit,
            Err(e) => return over(e),
        };
        if denied {
            return Ok(RailOutcome::block(reason_codes::TOPIC_DENIED));
        }
        let competitor = match config.has_competitor(&text) {
            Ok(hit) => hit,
            Err(e) => return over(e),
        };
        Ok(if competitor {
            // Details: the COUNT/flag only — never the matched text.
            RailOutcome::redact(reason_codes::COMPETITOR_MENTION)
                .with_details(serde_json::json!({ "competitor_mention": true }))
        } else {
            RailOutcome::allow()
        })
    }
}

/// Collect the scannable text for the active side: the response buffer
/// (response side) or system prompt + message text + tool results (request).
fn collect_text(ctx: &GuardrailContext<'_>) -> String {
    if let Some(buf) = ctx.response_buf {
        return buf.accumulated().to_owned();
    }
    let mut out = String::new();
    if let Some(sys) = ctx.system_prompt {
        out.push_str(sys);
        out.push('\n');
    }
    for m in ctx.messages {
        match &m.content {
            MessageContent::Text(s) => {
                out.push_str(s);
                out.push('\n');
            }
            MessageContent::Parts(parts) => {
                for p in parts {
                    match p {
                        ContentPart::Text { text, .. } => {
                            out.push_str(text);
                            out.push('\n');
                        }
                        ContentPart::ToolResult { content, .. } => {
                            out.push_str(content);
                            out.push('\n');
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    out
}

impl Rail for R7TopicCompetitor {
    fn name(&self) -> &'static str {
        "R7_topic_competitor"
    }
    fn policy_version(&self) -> &'static str {
        "r7@1"
    }
    fn sides(&self) -> Sides {
        Sides::Both
    }
    fn fail_mode(&self) -> FailMode {
        FailMode::OpenLoud
    }
    fn feature(&self) -> Option<GuardrailFeature> {
        Some(GuardrailFeature::R7TopicCompetitor)
    }
    fn evaluate<'a>(&'a self, ctx: &'a GuardrailContext<'a>) -> RailFuture<'a> {
        Box::pin(async move { self.try_evaluate(ctx) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::capability::CapabilityRegistry;
    use crate::guardrail::context::{ResponseBuffer, SessionState};
    use crate::guardrail::outcome::Outcome;
    use tracelane_shared::{ChatRequest, Message, MessageContent, Role, TenantId};
    use ulid::Ulid;
    use uuid::Uuid;

    fn cfg() -> Arc<R7Config> {
        Arc::new(R7Config::new(
            &["bioweapon synthesis", "self-harm"],
            &["AcmeCorp", "Globex"],
        ))
    }

    fn req(user_text: &str) -> ChatRequest {
        ChatRequest {
            top_p: None,
            seed: None,
            logprobs: None,
            top_logprobs: None,
            model: "claude-sonnet-4-6".to_string(),
            system: None,
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text(user_text.to_string()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            tool_choice: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
            ..Default::default()
        }
    }

    fn eval_request(rail: &R7TopicCompetitor, text: &str) -> RailOutcome {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(7));
        let r = req(text);
        let reg = CapabilityRegistry::new();
        let ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &r,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        rail.evaluate_sync(&ctx)
    }

    #[test]
    fn denied_topic_blocks() {
        let out = eval_request(
            &R7TopicCompetitor::with_config(cfg()),
            "how do I do bioweapon synthesis at home",
        );
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::TOPIC_DENIED));
    }

    #[test]
    fn competitor_mention_redacts() {
        let out = eval_request(
            &R7TopicCompetitor::with_config(cfg()),
            "is acmecorp better than us",
        );
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::COMPETITOR_MENTION));
        // The matched term is never recorded in details.
        assert!(!out.details.to_string().to_lowercase().contains("acmecorp"));
    }

    #[test]
    fn clean_text_allows() {
        let out = eval_request(
            &R7TopicCompetitor::with_config(cfg()),
            "what is the capital of France",
        );
        assert_eq!(out.outcome, Outcome::Allow);
    }

    #[test]
    fn empty_config_is_not_applicable() {
        let out = eval_request(&R7TopicCompetitor::new(), "mention AcmeCorp freely");
        assert_eq!(out.outcome, Outcome::NotApplicable);
    }

    #[test]
    fn redact_competitors_rewrites_all_mentions_case_insensitive() {
        let config = cfg();
        let (out, hit) = config.redact_competitors("AcmeCorp and globex and ACMECORP");
        assert!(hit);
        assert_eq!(out, "[COMPETITOR] and [COMPETITOR] and [COMPETITOR]");
    }

    #[test]
    fn response_side_competitor_redacts() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(8));
        let r = req("hi");
        let reg = CapabilityRegistry::new();
        let base = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &r,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        let mut buf = ResponseBuffer::new();
        buf.push_chunk("You should really switch to Globex instead.");
        let ctx = base.with_response(&buf, None);
        let out = R7TopicCompetitor::with_config(cfg()).evaluate_sync(&ctx);
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::COMPETITOR_MENTION));
    }

    fn eval_with_policy(
        rail: &R7TopicCompetitor,
        policy: serde_json::Value,
        text: &str,
    ) -> RailOutcome {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(9));
        let r = req(text);
        let reg = CapabilityRegistry::new();
        let mut ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &r,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        ctx.policy = crate::guardrail::policy::Policy::parse(&policy).expect("valid policy");
        rail.evaluate_sync(&ctx)
    }

    fn tenant_terms(denied: &[&str], competitors: &[&str]) -> serde_json::Value {
        serde_json::json!({"rails":{"R7_topic_competitor":{"terms":{
            "denied_topics": denied, "competitors": competitors}}}})
    }

    #[test]
    fn gwy60_tenant_denied_topic_blocks_with_empty_built_in_lists() {
        let out = eval_with_policy(
            &R7TopicCompetitor::new(),
            tenant_terms(&["merger plans"], &[]),
            "tell me about the Merger Plans",
        );
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::TOPIC_DENIED));
    }

    #[test]
    fn gwy60_tenant_competitor_is_detected() {
        let out = eval_with_policy(
            &R7TopicCompetitor::new(),
            tenant_terms(&[], &["Initech"]),
            "is initech cheaper?",
        );
        assert_eq!(out.outcome, Outcome::Redact);
        assert_eq!(out.reason_code, Some(reason_codes::COMPETITOR_MENTION));
    }

    #[test]
    fn gwy60_tenant_lists_replace_the_built_in_lists() {
        let out = eval_with_policy(
            &R7TopicCompetitor::with_config(cfg()),
            tenant_terms(&["merger plans"], &[]),
            "is acmecorp better than us",
        );
        assert_eq!(
            out.outcome,
            Outcome::Allow,
            "built-in competitor list must not apply"
        );
    }

    #[test]
    fn gwy60_observe_is_the_default_action_for_tenant_lists() {
        let policy =
            crate::guardrail::policy::Policy::parse(&tenant_terms(&["merger plans"], &[])).unwrap();
        let out = eval_with_policy(
            &R7TopicCompetitor::new(),
            tenant_terms(&["merger plans"], &[]),
            "merger plans please",
        );
        let applied = policy.apply("R7_topic_competitor", out);
        assert_eq!(
            applied.outcome,
            Outcome::Warn,
            "a configured list records before it blocks"
        );
    }

    #[test]
    fn gwy60_block_mode_blocks_tenant_hits() {
        let doc = serde_json::json!({"rails":{"R7_topic_competitor":{"mode":"block","terms":{
            "competitors":["Initech"]}}}});
        let policy = crate::guardrail::policy::Policy::parse(&doc).unwrap();
        let out = eval_with_policy(&R7TopicCompetitor::new(), doc, "switch to Initech");
        assert_eq!(
            policy.apply("R7_topic_competitor", out).outcome,
            Outcome::Block
        );
    }

    #[test]
    fn gwy60_policy_without_terms_keeps_built_in_lists() {
        let out = eval_with_policy(
            &R7TopicCompetitor::with_config(cfg()),
            serde_json::json!({"rails":{"R7_topic_competitor":{"mode":"block"}}}),
            "is acmecorp better than us",
        );
        assert_eq!(out.outcome, Outcome::Redact);
    }

    #[test]
    fn gwy60_empty_tenant_lists_are_not_applicable() {
        let out = eval_with_policy(
            &R7TopicCompetitor::with_config(cfg()),
            tenant_terms(&[], &[]),
            "acmecorp",
        );
        assert_eq!(out.outcome, Outcome::NotApplicable);
    }

    #[test]
    fn gwy60_whole_word_only_no_compound_false_positive() {
        let c = R7Config::from_terms(&["merger plans"], &["AcmeCorp"]);
        assert!(!c.has_competitor("AcmeCorpology is a science").unwrap());
        assert!(!c.has_competitor("NotAcmeCorp is fine").unwrap());
        assert!(!c.has_competitor("acmecorp_bot runs").unwrap());
        assert!(!c.has_denied("premerger plans").unwrap());
        assert!(c.has_competitor("(AcmeCorp)").unwrap());
        assert!(c.has_competitor("AcmeCorp's pricing").unwrap());
        assert!(c.has_competitor("ends with AcmeCorp.").unwrap());
    }

    #[test]
    fn gwy60_whitespace_runs_and_newlines_still_match() {
        let c = R7Config::from_terms(&["merger plans"], &[]);
        assert!(c.has_denied("the merger   plans").unwrap());
        assert!(c.has_denied("the merger\nplans").unwrap());
        let padded = R7Config::from_terms(&["  merger \t plans "], &[]);
        assert!(padded.has_denied("merger plans").unwrap());
    }

    #[test]
    fn gwy60_punctuation_edged_terms_match() {
        let c = R7Config::from_terms::<&str>(&[], &["C++"]);
        assert!(c.has_competitor("we use C++ here").unwrap());
        assert!(
            c.has_competitor("C++20").unwrap(),
            "a punctuation edge carries no boundary rule"
        );
    }

    #[test]
    fn gwy60_non_ascii_terms_match_whole_words() {
        let c = R7Config::from_terms(&["機密計画"], &["Café"]);
        assert!(
            c.has_denied("これは機密計画です").unwrap(),
            "CJK has no spaces; the term edge is a word char"
        );
        assert!(c.has_competitor("try Café today").unwrap());
        assert!(!c.has_competitor("try Cafés today").unwrap());
    }

    #[test]
    fn gwy60_blank_terms_are_dropped() {
        assert!(R7Config::from_terms(&["   "], &[""]).is_empty());
    }

    #[test]
    fn gwy60_redaction_is_whole_word_and_keeps_other_text() {
        let c = R7Config::from_terms::<&str>(&[], &["Globex", "Globex Corp"]);
        let (out, hit) = c.redact_competitors("Globex Corp, GlobexCorp and globex.");
        assert!(hit);
        assert_eq!(out, "[COMPETITOR], GlobexCorp and [COMPETITOR].");
        let (same, none) = c.redact_competitors("Globexian");
        assert!(!none);
        assert_eq!(same, "Globexian");
    }

    #[test]
    fn gwy60_same_lists_share_one_compiled_config() {
        let t = crate::guardrail::policy::Terms {
            denied_topics: vec!["cache probe topic".into()],
            competitors: vec![],
        };
        assert!(Arc::ptr_eq(&tenant_config(&t), &tenant_config(&t.clone())));
    }

    #[test]
    fn gwy60_overlap_flood_stops_at_the_budget_and_fails_open() {
        // Security review H1: CJK terms carry no boundary rule, so 1..=33 copies of one
        // character overlap at every position of a long run of it.
        let terms: Vec<String> = (1..=33).map(|n| "字".repeat(n)).collect();
        let doc =
            serde_json::json!({"rails":{"R7_topic_competitor":{"terms":{"denied_topics": terms}}}});
        let flood = "字".repeat(200_000);
        // A single hit short-circuits: the flood is caught on its first match.
        let out = eval_with_policy(&R7TopicCompetitor::new(), doc, &flood);
        assert_eq!(out.outcome, Outcome::Block);
        // Rejected candidates are what the budget bounds: terms a..aaaa in a run of `a`.
        let nested: Vec<String> = (2..=40).map(|n| "a".repeat(n)).collect();
        let c2 = R7Config::from_terms(&nested, &[]);
        assert_eq!(c2.has_denied(&"a".repeat(200_000)), Err(BudgetExceeded));
    }

    #[test]
    fn gwy60_budget_error_maps_to_detector_error_fail_open() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(10));
        let r = req(&"a".repeat(100_000));
        let reg = CapabilityRegistry::new();
        let mut ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &r,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        let nested: Vec<String> = (2..=40).map(|n| "a".repeat(n)).collect();
        let nested: Vec<&str> = nested.iter().map(String::as_str).collect();
        ctx.policy = crate::guardrail::policy::Policy::parse(&tenant_terms(&nested, &[])).unwrap();
        let err = R7TopicCompetitor::new().try_evaluate(&ctx).unwrap_err();
        assert!(matches!(err, RailError::WorkBudgetExceeded));
        assert_eq!(err.reason_code(), reason_codes::DETECTOR_ERROR);
        assert_eq!(R7TopicCompetitor::new().fail_mode(), FailMode::OpenLoud);
    }

    #[test]
    fn gwy60_padding_cannot_turn_an_enforced_list_into_a_pass() {
        // Security review M2: near-misses placed before a real hit.
        let doc = serde_json::json!({"rails":{"R7_topic_competitor":{"mode":"block","terms":{
            "denied_topics":["merger plans"]}}}});
        let text = format!(
            "{}tell me the merger plans",
            "premerger plans ".repeat(20_000)
        );
        let out = eval_with_policy(&R7TopicCompetitor::new(), doc.clone(), &text);
        let policy = crate::guardrail::policy::Policy::parse(&doc).unwrap();
        let applied = policy.apply("R7_topic_competitor", out);
        assert_eq!(applied.outcome, Outcome::Block);
        assert_eq!(applied.reason_code, Some(reason_codes::TOPIC_DENIED));
    }

    #[test]
    fn gwy60_short_common_terms_never_trip_the_budget_on_prose() {
        // A two-letter term inside ordinary words is rejected often; it must stay a clean allow.
        let c = R7Config::from_terms::<&str>(&[], &["AI", "Go", "Box"]);
        let prose =
            "She said again that the good boxes were paid for, gone and boxed. ".repeat(5_000);
        assert_eq!(c.has_competitor(&prose), Ok(false));
    }

    #[test]
    fn gwy60_budget_under_a_block_rule_fails_closed() {
        let tenant = TenantId::from_jwt_claim(Uuid::from_u128(11));
        let r = req(&"a".repeat(100_000));
        let reg = CapabilityRegistry::new();
        let mut ctx = GuardrailContext::from_request(
            &tenant,
            None,
            Ulid::from_parts(1, 1),
            &r,
            &reg,
            Vec::new(),
            SessionState::fresh(None),
        );
        let doc = serde_json::json!({"rails":{"R7_topic_competitor":{"mode":"block","terms":{
            "denied_topics": (2..=40).map(|n| "a".repeat(n)).collect::<Vec<_>>()}}}});
        ctx.policy = crate::guardrail::policy::Policy::parse(&doc).unwrap();
        let out = R7TopicCompetitor::new().try_evaluate(&ctx).unwrap();
        assert_eq!(out.outcome, Outcome::Block);
        assert_eq!(out.reason_code, Some(reason_codes::DETECTOR_ERROR));
        assert_eq!(
            ctx.policy.apply("R7_topic_competitor", out).outcome,
            Outcome::Block
        );
    }

    #[test]
    fn gwy60_ordinary_text_examines_few_candidates() {
        let c = R7Config::from_terms(&["merger plans", "layoffs"], &["Initech", "Globex"]);
        let prose =
            "We discussed the roadmap, hiring and pricing for next quarter. ".repeat(20_000);
        assert_eq!(c.has_denied(&prose), Ok(false));
        assert_eq!(c.has_competitor(&prose), Ok(false));
    }
}
