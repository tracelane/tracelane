//! R7 — Topic / competitor keyword blocklist, fast path (the guardrail spec
//! §3 R7): off-domain / brand-risk / competitor governance.
//!
//! Aho-Corasick multi-pattern match (case-insensitive) over two per-workspace
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
//! OUTPUTTING competitor/denied content). Request-side competitor rewrite +
//! per-workspace term loading are documented follow-ups.

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
    n_competitors: usize,
}

impl R7Config {
    /// Compile the denied-topic + competitor term lists. Empty lists compile to
    /// `None` (match nothing). A malformed automaton degrades to `None` (logged)
    /// rather than failing construction — R7 is fail-open.
    #[must_use]
    pub fn new<S: AsRef<str>>(denied_topics: &[S], competitor_terms: &[S]) -> Self {
        Self {
            denied: Self::build(denied_topics),
            competitors: Self::build(competitor_terms),
            n_competitors: competitor_terms.len(),
        }
    }

    fn build<S: AsRef<str>>(terms: &[S]) -> Option<AhoCorasick> {
        if terms.is_empty() {
            return None;
        }
        match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(terms.iter().map(AsRef::as_ref))
        {
            Ok(ac) => Some(ac),
            Err(err) => {
                tracing::warn!(error = %err, "R7 term list failed to compile — disabling that list");
                None
            }
        }
    }

    /// Whether no terms are configured (R7 is `not_applicable`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.denied.is_none() && self.competitors.is_none()
    }

    /// Whether the text contains a denied-topic term.
    #[must_use]
    pub fn has_denied(&self, text: &str) -> bool {
        self.denied.as_ref().is_some_and(|ac| ac.is_match(text))
    }

    /// Redact every competitor mention to `[COMPETITOR]`. Returns the rewritten
    /// text and whether anything matched.
    #[must_use]
    pub fn redact_competitors(&self, text: &str) -> (String, bool) {
        match &self.competitors {
            Some(ac) if ac.is_match(text) => (
                ac.replace_all(text, &vec![COMPETITOR_MARKER; self.n_competitors]),
                true,
            ),
            _ => (text.to_owned(), false),
        }
    }
}

/// R7 topic / competitor blocklist (gated `R7TopicCompetitor`).
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

    pub fn evaluate_sync(&self, ctx: &GuardrailContext<'_>) -> RailOutcome {
        if self.config.is_empty() {
            return RailOutcome::not_applicable();
        }
        let text = collect_text(ctx);
        if text.trim().is_empty() {
            return RailOutcome::not_applicable();
        }
        if self.config.has_denied(&text) {
            return RailOutcome::block(reason_codes::TOPIC_DENIED);
        }
        let (_, competitor_hit) = self.config.redact_competitors(&text);
        if competitor_hit {
            // Details: the COUNT/flag only — never the matched text.
            RailOutcome::redact(reason_codes::COMPETITOR_MENTION)
                .with_details(serde_json::json!({ "competitor_mention": true }))
        } else {
            RailOutcome::allow()
        }
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
        Box::pin(async move { Ok::<_, RailError>(self.evaluate_sync(ctx)) })
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
            model: "claude-sonnet-4-6".to_string(),
            system: None,
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text(user_text.to_string()),
                tool_call_id: None,
                tool_calls: None,
            }],
            tools: None,
            max_tokens: None,
            temperature: None,
            stream: None,
            metadata: None,
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
}
