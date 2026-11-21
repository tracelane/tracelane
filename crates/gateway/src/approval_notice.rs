//! `GWY-81` — the visible text of an approval notification (Slack Block Kit, email, plain
//! fallback) and its deep link. Pure functions over the outbox payload; no I/O, no crate
//! state, so the full case matrix is unit-testable (compiled into the library as well as the
//! binary, like `rate_limiter`).
//!
//! SECURITY DECISION (specs/GWY-81): the text names the tool, server, rule and expiry only.
//! It reads NAMED payload keys, never iterates the payload, so a new field added upstream
//! (an argument preview, an amount, a hash) cannot reach a channel. The one opaque identifier
//! is the approval id inside the URL; the page behind it requires an SSO session.

use serde_json::{Value, json};

/// Longest visible value, in characters. A tool or server name is an identifier; 100 covers
/// every real one and bounds the message at 3 fields.
const MAX_FIELD_CHARS: usize = 100;
/// The approvals page (`apps/web/app/settings/gateway/[slot]`, slot `approvals`). A constant,
/// not the payload's `queue_path`, so a stored payload cannot steer the link.
const APPROVALS_PATH: &str = "/settings/gateway/approvals";
const BUTTON_TEXT: &str = "Review and approve";
const SETTINGS_HINT: &str = "Settings → Gateway → Approvals";

/// One held call, ready to render. Fields are control-stripped and truncated but NOT escaped;
/// each renderer escapes for its own format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalNotice {
    /// "Tool" or "Model" — what `subject` is.
    pub kind_label: &'static str,
    pub tool: String,
    pub server: Option<String>,
    pub rule: Option<String>,
    /// `YYYY-MM-DD HH:MM`, UTC. `None` when absent or unparseable (never "now").
    pub expires: Option<String>,
    /// Deep link to this approval. `None` when the base URL or the id is not safe.
    pub link: Option<String>,
    /// The protected path coalesces notices: other held calls may be waiting.
    pub more_may_wait: bool,
}

/// Zero-width and bidirectional-override characters: invisible, so they can disguise a name
/// (U+202E reverses what follows) or hide text between two visible ones.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{061C}'
            | '\u{2060}'..='\u{2064}'
            | '\u{00AD}'
            | '\u{180E}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{3164}'
            | '\u{FFA0}'
            | '\u{034F}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{2800}')
}

/// Make a value un-clickable: `https://x` becomes `https[:]//x` and `www.x` becomes `www[.]x`.
/// An agent-chosen tool name must not become an autolinked URL beside the real button
/// (phishing: `https://tracelane-approve.example/login`).
fn defang(s: &str) -> String {
    let s = s.replace("://", "[:]//");
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (i, _) in lower.match_indices("www.") {
        out.push_str(&s[last..i + 3]);
        out.push_str("[.]");
        last = i + 4;
    }
    out.push_str(&s[last..]);
    defang_dots(&out)
}

/// Every character a reader or mail client treats as a full stop in a domain.
fn is_dot(c: char) -> bool {
    matches!(c, '.' | '\u{3002}' | '\u{FF0E}' | '\u{FF61}')
}

/// A dot between two alphanumerics and followed by a letter (any script) reads as a domain
/// (`evil.com/login`, `пример.рф`), and a run of four 1-3 digit groups reads as an IPv4
/// address; mail clients linkify both. Each such dot becomes `[.]`. Versions such as
/// `gpt-4.1` or `claude-3.5` (digit after the dot, fewer than four groups) are untouched.
fn defang_dots(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut hit = vec![false; chars.len()];
    for i in 1..chars.len().saturating_sub(1) {
        if is_dot(chars[i]) && chars[i - 1].is_alphanumeric() && chars[i + 1].is_alphabetic() {
            hit[i] = true;
        }
    }
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_digit() || is_dot(chars[j])) {
                j += 1;
            }
            let run: String = chars[i..j].iter().collect();
            let groups: Vec<&str> = run.split(is_dot).collect();
            if groups.len() == 4
                && groups
                    .iter()
                    .all(|g| (1..=3).contains(&g.len()) && g.bytes().all(|b| b.is_ascii_digit()))
            {
                for (k, c) in chars[i..j].iter().enumerate() {
                    if is_dot(*c) {
                        hit[i + k] = true;
                    }
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    let mut out = String::with_capacity(s.len());
    for (c, h) in chars.iter().zip(hit) {
        if h {
            out.push_str("[.]");
        } else {
            out.push(*c);
        }
    }
    out
}

/// Drop invisible characters, turn control characters into spaces, collapse to one line.
fn normalize(raw: &str) -> String {
    let one_line: String = raw
        .chars()
        .filter(|c| !is_invisible(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    one_line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cap(s: String) -> String {
    if s.chars().count() > MAX_FIELD_CHARS {
        let mut cut: String = s.chars().take(MAX_FIELD_CHARS).collect();
        cut.push('…');
        cut
    } else {
        s
    }
}

/// Stripped and capped, NOT defanged: for the webhook body, which no human reads and where a
/// name like `anthropic.claude-3` must arrive intact.
fn strip(raw: &str) -> String {
    cap(normalize(raw))
}

/// Stripped, defanged and capped: for every human-facing renderer.
fn clean(raw: &str) -> String {
    cap(defang(&normalize(raw)))
}

fn field(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(clean)
        .filter(|s| !s.is_empty())
}

fn field_stripped(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(strip)
        .filter(|s| !s.is_empty())
}

/// `<base>/settings/gateway/approvals?id=<uuid>`. `None` unless the base is a plain http(s)
/// origin (no whitespace, quotes, angle brackets, pipes, backslashes) and `id` is a UUID.
fn deep_link(base: &str, approval_id: &str) -> Option<String> {
    let base = base.trim().trim_end_matches('/');
    let rest = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))?;
    let unsafe_char = |c: char| {
        c.is_control()
            || c.is_whitespace()
            || matches!(c, '<' | '>' | '|' | '"' | '\'' | '`' | '\\' | '@')
    };
    if rest.is_empty() || rest.starts_with('/') || base.chars().any(unsafe_char) {
        return None;
    }
    let id = uuid::Uuid::parse_str(approval_id).ok()?;
    Some(format!("{base}{APPROVALS_PATH}?id={}", id.hyphenated()))
}

/// Slack mrkdwn control characters (`&`, `<`, `>`) and a backtick (which would close our
/// code span) neutralised.
fn mrkdwn(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('`', "'")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Build the notice for an `approval.requested` payload; `None` for any other payload.
#[must_use]
pub fn approval_notice(payload: &Value, base_url: &str) -> Option<ApprovalNotice> {
    if payload.get("type").and_then(Value::as_str) != Some("approval.requested") {
        return None;
    }
    let expires = payload
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| {
            t.with_timezone(&chrono::Utc)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        });
    Some(ApprovalNotice {
        kind_label: if payload.get("subject_kind").and_then(Value::as_str) == Some("model") {
            "Model"
        } else {
            "Tool"
        },
        tool: field(payload, "subject").unwrap_or_else(|| "a protected call".to_owned()),
        server: field(payload, "server_name"),
        rule: field(payload, "rule"),
        expires,
        link: payload
            .get("approval_id")
            .and_then(Value::as_str)
            .and_then(|id| deep_link(base_url, id)),
        more_may_wait: payload.get("protected") == Some(&Value::Bool(true)),
    })
}

/// The generic-webhook body: the stored payload plus `event_id`, and `url` for an approval.
#[must_use]
pub fn webhook_body(payload: &Value, event_id: uuid::Uuid, base_url: &str) -> Value {
    let mut body = payload.clone();
    if let Some(n) = approval_notice(payload, base_url) {
        // ALLOWLIST for approvals: only these keys leave, so a field added to the payload
        // later (a preview, an amount, a key) cannot reach a customer endpoint. Free-text
        // fields are cleaned exactly like every other channel.
        const KEEP: [&str; 6] = [
            "type",
            "approval_id",
            "subject_kind",
            "protected",
            "expires_at",
            "queue_path",
        ];
        let mut out = serde_json::Map::new();
        for k in KEEP {
            if let Some(v) = payload.get(k) {
                out.insert(k.to_owned(), v.clone());
            }
        }
        out.insert(
            "subject".to_owned(),
            Value::String(
                field_stripped(payload, "subject").unwrap_or_else(|| "a protected call".to_owned()),
            ),
        );
        for key in ["server_name", "rule"] {
            if let Some(v) = field_stripped(payload, key) {
                out.insert(key.to_owned(), Value::String(v));
            }
        }
        if let Some(link) = n.link {
            out.insert("url".to_owned(), Value::String(link));
        }
        body = Value::Object(out);
    }
    body["event_id"] = Value::String(event_id.to_string());
    body
}

impl ApprovalNotice {
    fn lines(&self, wrap: impl Fn(&str) -> String) -> Vec<String> {
        let mut out = vec![format!("{} {}", self.kind_label, wrap(&self.tool))];
        if let Some(s) = &self.server {
            out.push(format!("Server: {}", wrap(s)));
        }
        if let Some(r) = &self.rule {
            out.push(format!("Rule: {}", wrap(r)));
        }
        if let Some(e) = &self.expires {
            out.push(format!("Expires {e} UTC"));
        }
        if self.more_may_wait {
            out.push("Other calls may also be waiting.".to_owned());
        }
        out
    }

    /// The Slack `text` field (notification preview and non-Block-Kit clients). mrkdwn-escaped.
    #[must_use]
    pub fn fallback_text(&self) -> String {
        let mut t = format!(
            "Tracelane approval needed: {} `{}`",
            self.kind_label.to_lowercase(),
            mrkdwn(&self.tool)
        );
        if let Some(s) = &self.server {
            t.push_str(&format!(" on `{}`", mrkdwn(s)));
        }
        if let Some(r) = &self.rule {
            t.push_str(&format!(" (rule `{}`)", mrkdwn(r)));
        }
        if let Some(e) = &self.expires {
            t.push_str(&format!(", expires {e} UTC"));
        }
        t.push('.');
        if self.more_may_wait {
            t.push_str(" Other calls may also be waiting.");
        }
        match &self.link {
            Some(l) => t.push_str(&format!(" Review and approve: {l}")),
            None => t.push_str(&format!(" Review it in {SETTINGS_HINT}.")),
        }
        t
    }

    /// Slack Block Kit: one section and, when the link is safe, ONE URL button. A URL button
    /// needs no Slack app and no interactivity endpoint.
    #[must_use]
    pub fn slack_blocks(&self) -> Value {
        let body = format!(
            "*Approval needed*\n{}",
            self.lines(|v| format!("`{}`", mrkdwn(v))).join("\n")
        );
        let mut blocks = vec![json!({"type":"section","text":{"type":"mrkdwn","text":body}})];
        match &self.link {
            Some(l) => blocks.push(json!({"type":"actions","elements":[
                {"type":"button","text":{"type":"plain_text","text":BUTTON_TEXT},"url":l}]})),
            None => blocks.push(json!({"type":"context","elements":[
                {"type":"mrkdwn","text":format!("Review it in {SETTINGS_HINT}.")}]})),
        }
        Value::Array(blocks)
    }

    /// Plain-text body (email `text` part). Angle brackets become parentheses: some clients
    /// autolink `<https://...>` and we never want a sender-chosen value to form one.
    #[must_use]
    pub fn plain(&self) -> String {
        let mut lines = self.lines(|v| v.replace('<', "(").replace('>', ")"));
        match &self.link {
            Some(l) => lines.push(format!("Review and approve: {l}")),
            None => lines.push(format!("Review it in {SETTINGS_HINT}.")),
        }
        lines.join("\n")
    }

    /// Email `html` part. Every value and the URL are HTML-escaped.
    #[must_use]
    pub fn html(&self) -> String {
        let mut h = String::from("<p><strong>Approval needed</strong></p><p>");
        h.push_str(
            &self
                .lines(|v| format!("<code>{}</code>", html_escape(v)))
                .join("<br>"),
        );
        h.push_str("</p>");
        match &self.link {
            Some(l) => {
                let l = html_escape(l);
                h.push_str(&format!("<p><a href=\"{l}\">{BUTTON_TEXT}</a></p>"));
            }
            None => h.push_str(&format!("<p>Review it in {SETTINGS_HINT}.</p>")),
        }
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(p: &Value, base: &str) -> String {
        approval_notice(p, base)
            .expect("approval payload")
            .fallback_text()
    }
    const BASE: &str = "https://app.tracelane.dev";
    const ID: &str = "0b9a7f0e-5d55-4c3e-9a57-6a1f3e2c8d11";
    fn protected_payload() -> Value {
        serde_json::json!({"type":"approval.requested","approval_id":ID,"subject":"pay","subject_kind":"tool","protected":true,"expires_at":"2026-11-09T14:05:33+00:00","queue_path":"/settings/gateway/approvals","server_name":"billing","rule":"action policy v3","args_preview":"SECRET-PREVIEW","amount":"1500000"})
    }
    fn legacy_payload() -> Value {
        serde_json::json!({"type":"approval.requested","approval_id":ID,"subject":"delete_repo","subject_kind":"tool","expires_at":"2026-11-09T14:05:33+00:00","queue_path":"/settings/gateway/approvals","server_name":"github","rule":"delete_*","args_preview":"SECRET-PREVIEW","amount":"1500000","key":"tlane_sk_live_abc"})
    }
    fn notice(p: &Value) -> ApprovalNotice {
        approval_notice(p, BASE).expect("approval payload")
    }
    fn every_rendering(p: &Value, base: &str) -> Vec<String> {
        let n = approval_notice(p, base).expect("approval payload");
        vec![
            text(p, base),
            n.slack_blocks().to_string(),
            n.html(),
            n.plain(),
            n.fallback_text(),
        ]
    }
    fn link() -> String {
        format!("{BASE}/settings/gateway/approvals?id={ID}")
    }
    // positive
    #[test]
    fn p1_names_the_tool() {
        assert!(text(&legacy_payload(), BASE).contains("`delete_repo`"));
    }
    #[test]
    fn p2_names_the_server() {
        assert!(text(&legacy_payload(), BASE).contains("`github`"));
    }
    #[test]
    fn p3_names_the_rule() {
        assert!(text(&legacy_payload(), BASE).contains("`delete_*`"));
    }
    #[test]
    fn p4_expiry_is_utc_minute() {
        assert!(text(&legacy_payload(), BASE).contains("2026-11-09 14:05 UTC"));
    }
    #[test]
    fn p5_link_carries_the_exact_id() {
        assert_eq!(
            notice(&legacy_payload()).link.as_deref(),
            Some(link().as_str())
        );
    }
    #[test]
    fn p6_trailing_slash_base_is_tolerated() {
        let n = approval_notice(&legacy_payload(), "https://app.tracelane.dev/").unwrap();
        assert_eq!(n.link.as_deref(), Some(link().as_str()));
    }
    #[test]
    fn p7_http_selfhost_base_is_accepted() {
        let n = approval_notice(&legacy_payload(), "http://localhost:3000").unwrap();
        assert!(
            n.link
                .unwrap()
                .starts_with("http://localhost:3000/settings/")
        );
    }
    #[test]
    fn p8_slack_blocks_have_one_url_button() {
        let b = notice(&legacy_payload()).slack_blocks();
        let actions: Vec<_> = b
            .as_array()
            .unwrap()
            .iter()
            .filter(|x| x["type"] == "actions")
            .collect();
        assert_eq!(actions.len(), 1);
        let els = actions[0]["elements"].as_array().unwrap();
        assert_eq!(els.len(), 1);
        assert_eq!(els[0]["type"], "button");
        assert_eq!(els[0]["text"]["text"], "Review and approve");
        assert_eq!(els[0]["url"], link());
    }
    #[test]
    fn p9_plain_fallback_carries_the_link() {
        assert!(notice(&legacy_payload()).fallback_text().contains(&link()));
        assert!(text(&legacy_payload(), BASE).contains(&link()));
    }
    #[test]
    fn p10_email_html_has_facts_and_escaped_link() {
        let h = notice(&legacy_payload()).html();
        assert!(h.contains("delete_repo") && h.contains("github") && h.contains("delete_*"));
        assert!(h.contains("2026-11-09 14:05 UTC"));
        assert!(h.contains(&format!("href=\"{}\"", link())), "{h}");
    }
    #[test]
    fn p11_webhook_body_gains_the_url() {
        let b = webhook_body(&legacy_payload(), uuid::Uuid::nil(), BASE);
        assert_eq!(b["url"], link());
        assert_eq!(b["approval_id"], ID);
        assert_eq!(b["event_id"], uuid::Uuid::nil().to_string());
    }
    #[test]
    fn p12_protected_names_policy_version_and_more_waiting() {
        let t = text(&protected_payload(), BASE);
        assert!(t.contains("`pay`") && t.contains("action policy v3"), "{t}");
        assert!(t.contains("Other calls may also be waiting"), "{t}");
    }
    #[test]
    fn p13_old_outbox_row_without_new_keys_still_renders() {
        let p = serde_json::json!({"type":"approval.requested","approval_id":ID,"subject":"pay","subject_kind":"tool","queue_path":"/settings/gateway/approvals"});
        let t = text(&p, BASE);
        assert!(t.contains("`pay`") && t.contains(&link()), "{t}");
        assert!(!t.contains("Server:") && !t.contains("Rule:"), "{t}");
    }
    #[test]
    fn p14_model_call_is_labelled_model() {
        let mut p = legacy_payload();
        p["subject_kind"] = serde_json::json!("model");
        p["subject"] = serde_json::json!("gpt-5");
        assert!(text(&p, BASE).contains("model `gpt-5`"));
    }
    // negative
    #[test]
    fn n1_to_n3_no_argument_amount_or_key_in_any_rendering() {
        for p in [legacy_payload(), protected_payload()] {
            for t in every_rendering(&p, BASE) {
                for leak in [
                    "SECRET-PREVIEW",
                    "1500000",
                    "tlane_sk_live_abc",
                    "args_preview",
                ] {
                    assert!(!t.contains(leak), "{leak} leaked into {t}");
                }
            }
        }
    }
    #[test]
    fn n4_no_uuid_in_visible_text_other_than_inside_the_url() {
        for p in [legacy_payload(), protected_payload()] {
            let n = notice(&p);
            let visible = [
                n.plain().replace(&link(), ""),
                n.fallback_text().replace(&link(), ""),
            ];
            for t in visible {
                assert!(!t.contains(ID), "{t}");
            }
            let blocks = n.slack_blocks();
            assert!(!blocks[0]["text"]["text"].as_str().unwrap().contains(ID));
        }
    }
    #[test]
    fn n5_slack_and_html_control_syntax_is_escaped() {
        let mut p = legacy_payload();
        p["subject"] = serde_json::json!("<!channel> <https://x|y> a&b");
        p["server_name"] = serde_json::json!("<!here>");
        p["rule"] = serde_json::json!("<@U123>");
        let n = notice(&p);
        for t in [text(&p, BASE), n.slack_blocks().to_string(), n.html()] {
            for bad in ["<!channel>", "<!here>", "<@U123>", "<https://x"] {
                assert!(!t.contains(bad), "{bad} in {t}");
            }
        }
        assert!(text(&p, BASE).contains("&lt;!channel&gt; &lt;https[:]//x|y&gt; a&amp;b"));
    }
    #[test]
    fn n6_backtick_cannot_break_out_of_code_formatting() {
        let mut p = legacy_payload();
        p["subject"] = serde_json::json!("x` *bold* `y");
        let t = text(&p, BASE);
        assert!(!t.contains("x` *bold*"), "{t}");
        assert_eq!(t.matches('`').count() % 2, 0, "{t}");
    }
    #[test]
    fn n7_newlines_and_control_chars_are_stripped() {
        let mut p = legacy_payload();
        p["subject"] = serde_json::json!("a\nb\r\u{7}c");
        let n = notice(&p);
        assert!(!n.tool.contains(['\n', '\r', '\u{7}']), "{:?}", n.tool);
    }
    #[test]
    fn n8_long_values_are_truncated() {
        let mut p = legacy_payload();
        p["subject"] = serde_json::json!("t".repeat(500));
        let n = notice(&p);
        assert_eq!(n.tool.chars().count(), 101);
        assert!(n.tool.ends_with('…'));
    }
    #[test]
    fn n9_n11_unsafe_bases_yield_no_link() {
        for base in [
            "javascript:alert(1)",
            "",
            "ftp://x",
            "https://a b",
            "https://x/>|<",
            "//evil",
            "https://x\"onclick=",
            "https://user@evil.example",
        ] {
            assert!(
                approval_notice(&legacy_payload(), base)
                    .unwrap()
                    .link
                    .is_none(),
                "{base}"
            );
        }
    }
    #[test]
    fn n10_non_uuid_id_yields_no_link_and_falls_back_to_settings_path() {
        for id in [
            "a",
            "../../x",
            "",
            "0b9a7f0e-5d55-4c3e-9a57-6a1f3e2c8d11&x=1",
        ] {
            let mut p = legacy_payload();
            p["approval_id"] = serde_json::json!(id);
            let n = notice(&p);
            assert!(n.link.is_none(), "{id}");
            assert!(n.fallback_text().contains("Settings → Gateway → Approvals"));
            assert!(n.slack_blocks().to_string().find("\"button\"").is_none());
        }
    }
    #[test]
    fn n12_email_html_escapes_script() {
        let mut p = legacy_payload();
        p["subject"] = serde_json::json!("<script>alert(1)</script>");
        assert!(!notice(&p).html().contains("<script>"));
    }
    #[test]
    fn n13_unknown_payload_keys_are_never_rendered() {
        let mut p = legacy_payload();
        p["zz_new_field"] = serde_json::json!("CANARY-VALUE");
        p["policy_hash"] = serde_json::json!("CANARY-HASH");
        for t in every_rendering(&p, BASE) {
            assert!(!t.contains("CANARY"), "{t}");
        }
        let w = webhook_body(&p, uuid::Uuid::nil(), BASE).to_string();
        assert!(!w.contains("CANARY"), "{w}");
    }
    #[test]
    fn n14_garbage_expiry_drops_the_line_never_prints_now() {
        let mut p = legacy_payload();
        p["expires_at"] = serde_json::json!("soon");
        let t = text(&p, BASE);
        assert!(!t.contains("xpires"), "{t}");
    }

    /// Tier-A invariant sweep: every hostile value in every text field through every renderer.
    #[test]
    fn sweep_hostile_values_never_reach_a_renderer_raw() {
        let hostile: Vec<String> = vec![
            "<!channel>".into(),
            "<https://e|t>".into(),
            "`".into(),
            "&".into(),
            "a\nb\r\tc\u{7}d".into(),
            "x\u{202E}y".into(),
            "x\u{200B}y".into(),
            "q".repeat(500),
            "https://tracelane-approve.example/login".into(),
            "www.evil.example".into(),
            "WWW.Evil.example HTTP://x.example".into(),
            "x\u{2060}y\u{00AD}z\u{061C}\u{180E}\u{E0041}w".into(),
            "evil.com/login".into(),
            "EVIL.CO".into(),
            "x.y.example/z".into(),
            "tracelane-approve.com/login sso.tracelane-app.io/approve".into(),
            "пример.рф/login".into(),
            "evil.рф".into(),
            "例え.jp/approve".into(),
            "evil。com/x".into(),
            "evil\u{FF0E}com".into(),
            "192.0.2.1/login".into(),
            "a\u{115F}b\u{1160}c\u{3164}d\u{FFA0}e\u{034F}f\u{FE0F}g\u{2800}h".into(),
        ];
        let forbidden_markup = ["<!channel>", "<https://e|t>", "<!", "<@", "<h"];
        for field in ["subject", "server_name", "rule"] {
            for h in &hostile {
                let mut p = legacy_payload();
                p[field] = serde_json::json!(h);
                let n = notice(&p);
                let body = webhook_body(&p, uuid::Uuid::nil(), BASE);
                let renders = [
                    ("slack text", n.fallback_text()),
                    ("block kit", n.slack_blocks().to_string()),
                    ("email text", n.plain()),
                    ("email html", n.html()),
                ];
                for (name, t) in &renders {
                    let t = t.replace(&link(), "");
                    for bad in forbidden_markup {
                        assert!(!t.contains(bad), "{field}={h:?} {name}: raw {bad} in {t}");
                    }
                    for bad in [
                        '\u{202E}',
                        '\u{200B}',
                        '\u{7}',
                        '\t',
                        '\u{2060}',
                        '\u{00AD}',
                        '\u{061C}',
                        '\u{180E}',
                        '\u{E0041}',
                        '\u{115F}',
                        '\u{1160}',
                        '\u{3164}',
                        '\u{FFA0}',
                        '\u{034F}',
                        '\u{FE0F}',
                        '\u{2800}',
                    ] {
                        assert!(!t.contains(bad), "{field}={h:?} {name}: invisible {bad:?}");
                    }
                    // Phishing: no clickable URL form survives outside the real deep link.
                    let lower = t.to_ascii_lowercase();
                    let cs: Vec<char> = lower.chars().collect();
                    let dot = |c: char| matches!(c, '.' | '\u{3002}' | '\u{FF0E}' | '\u{FF61}');
                    let bare_domain = cs
                        .windows(3)
                        .any(|w| w[0].is_alphanumeric() && dot(w[1]) && w[2].is_alphabetic())
                        || cs.windows(7).any(|w| {
                            [0, 2, 4, 6].iter().all(|&k| w[k].is_ascii_digit())
                                && [1, 3, 5].iter().all(|&k| dot(w[k]))
                        });
                    assert!(
                        !bare_domain,
                        "{field}={h:?} {name}: bare domain survives in {t}"
                    );
                    assert!(
                        !lower.contains("://") && !lower.contains("www."),
                        "{field}={h:?} {name}: URL survives in {t}"
                    );
                }
                for v in [Some(&n.tool), n.server.as_ref(), n.rule.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    assert!(v.chars().count() <= MAX_FIELD_CHARS + 1, "not capped: {v}");
                }
                let slack = n.fallback_text();
                assert_eq!(slack.matches('`').count() % 2, 0, "{field}={h:?}: {slack}");
                // Webhook: cleaned, capped, and no key beyond the payload's own plus event_id/url.
                for key in ["subject", "server_name", "rule"] {
                    let v = body[key].as_str().unwrap();
                    assert!(v.chars().count() <= MAX_FIELD_CHARS + 1, "{key} not capped");
                    assert!(!v.contains(['\u{202E}', '\u{200B}', '\u{7}', '\n', '\t']));
                }
                let mut keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
                keys.sort();
                let mut want: Vec<String> = [
                    "type",
                    "approval_id",
                    "subject",
                    "subject_kind",
                    "expires_at",
                    "queue_path",
                    "server_name",
                    "rule",
                    "event_id",
                    "url",
                ]
                .map(String::from)
                .to_vec();
                want.sort();
                // The fixture also carries args_preview, amount and key: they must be ABSENT.
                for leaked in ["args_preview", "amount", "key"] {
                    assert!(body.get(leaked).is_none(), "{leaked} reached the webhook");
                }
                assert_eq!(keys, want, "webhook body keys");
            }
        }
    }
    #[test]
    fn invisible_and_bidi_characters_are_dropped_not_spaced() {
        let mut p = legacy_payload();
        p["subject"] = serde_json::json!("ab\u{200B}\u{200F}\u{202A}\u{2066}\u{FEFF}c");
        assert_eq!(notice(&p).tool, "abc");
    }

    #[test]
    fn versions_are_not_defanged() {
        for v in ["gpt-4.1", "claude-3.5", "v1.2", "1.2.3"] {
            assert_eq!(clean(v), v);
        }
    }
    #[test]
    fn webhook_values_are_stripped_but_not_defanged() {
        let mut p = legacy_payload();
        p["subject"] = serde_json::json!("anthropic.claude-3\u{202E}\n");
        p["server_name"] = serde_json::json!("evil.com");
        p["rule"] = serde_json::json!("192.0.2.1/x");
        let b = webhook_body(&p, uuid::Uuid::nil(), BASE);
        assert_eq!(b["subject"], "anthropic.claude-3");
        assert_eq!(b["server_name"], "evil.com");
        assert_eq!(b["rule"], "192.0.2.1/x");
        // ...while every human-facing renderer defangs the same values.
        assert!(text(&p, BASE).contains("evil[.]com"));
    }
}
