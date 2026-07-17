//! PII redaction for span attributes.
//!
//! Before span attributes are written to ClickHouse, user-supplied
//! content (prompts, tool results, agent goals) is scanned for PII
//! and redacted. The TRD mandates 100% recall on synthetic patterns
//! (PIR-001 eval); this module is the implementation behind that gate.
//!
//! Categories (in match-priority order — high-specificity first so
//! generic patterns don't swallow specific ones):
//!   1. AWS access key IDs            `AKIA[0-9A-Z]{16}`
//!   2. GitHub personal access tokens `gh[ps]_[A-Za-z0-9_]{36,}`
//!      and `github_pat_[A-Za-z0-9_]{82}`
//!   3. Stripe secret keys            `sk_live_[A-Za-z0-9]{24,}`
//!      and `sk_test_[A-Za-z0-9]{24,}`
//!   4. Email addresses               local@host.tld
//!   5. US Social Security Numbers    `\d{3}-\d{2}-\d{4}`
//!   6. Credit card numbers           Luhn-valid 13–19 digit groups
//!   7. Phone numbers                 E.164 + common US formats
//!   8. IPv4 addresses
//!   9. IPv6 addresses (compact subset — covers most real-world)
//!
//! Redacted values are replaced with `[REDACTED:<category>]`. The
//! original character span is shrunk to a fixed marker so downstream
//! consumers never see raw secrets even in error logs.

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

/// One PII category — a regex + a replacement marker + a stable category
/// name + a secret-vs-PII class. The order in `RULES` matters:
/// high-specificity patterns run first so e.g. a Stripe key string isn't
/// partially matched by the credit-card rule.
///
/// `category` and `is_secret` drive the **reversible** redactor
/// ([`redact_reversible`], used by guardrail R2): the placeholder is
/// `{{TL_REDACT:<category>:<idx>}}` and `is_secret` separates the
/// fail-closed secret class from the redact-or-warn PII class. The one-way
/// [`redact`] path uses only `marker` — its output bytes are unchanged by
/// this addition, so the PIR-001 recall gate cannot regress.
struct Rule {
    pattern: Regex,
    marker: &'static str,
    category: &'static str,
    is_secret: bool,
}

static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    // (pattern, one-way marker, reversible category, is_secret)
    let raw: &[(&str, &str, &str, bool)] = &[
        // --- Secrets first (high specificity, won't false-match other rules) ---
        // Convergence with `tracelane_shared::redact` (A25) — span-attribute
        // redaction and log-line redaction now cover the same shapes.
        (r"AKIA[0-9A-Z]{16}", "[REDACTED:aws_key]", "aws_key", true),
        (
            r"gh[opsu]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}",
            "[REDACTED:github_token]",
            "github_token",
            true,
        ),
        (
            r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
            "[REDACTED:stripe_key]",
            "stripe_key",
            true,
        ),
        // rk_live_ / whsec_ — Stripe restricted + webhook secrets
        (
            r"rk_(?:live|test)_[A-Za-z0-9]{24,}",
            "[REDACTED:stripe_restricted]",
            "stripe_restricted",
            true,
        ),
        (
            r"whsec_[A-Za-z0-9+/=]{24,}",
            "[REDACTED:webhook_secret]",
            "webhook_secret",
            true,
        ),
        // OpenAI-shaped keys (covers sk-proj-, sk-svcacct-, classic sk-)
        (
            r"sk-[A-Za-z0-9_-]{20,}",
            "[REDACTED:openai_key]",
            "openai_key",
            true,
        ),
        // OpenAI org IDs
        (
            r"org-[A-Za-z0-9]{20,}",
            "[REDACTED:openai_org]",
            "openai_org",
            true,
        ),
        // Google AI / Cloud API key — classic "Standard" format. Still issued
        // for non-Gemini Google APIs (Maps, YouTube), so this rule stays.
        (
            r"AIza[0-9A-Za-z\-_]{35}",
            "[REDACTED:google_api_key]",
            "google_api_key",
            true,
        ),
        // Google "Authentication Key" (AQ.) — the 2026 successor format; AI
        // Studio issues only these now, and Gemini rejects all Standard keys
        // from Sept 2026. Length floor, not a pinned length: the format is
        // undocumented (Google treats the key as opaque), so a pinned length
        // would let a slightly-different key through SILENTLY. See B-112 /
        // runbooks/RCA-b112-google-key-redaction.md.
        (
            r"AQ\.[A-Za-z0-9_\-]{20,}",
            "[REDACTED:google_api_key]",
            "google_auth_key",
            true,
        ),
        // Bare Bearer tokens (catches the `Bearer xxx` shape inside string
        // payloads without the Authorization header prefix)
        (
            r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{12,}",
            "Bearer [REDACTED]",
            "bearer",
            true,
        ),
        // JWT three-segment shape
        (
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "[REDACTED:jwt]",
            "jwt",
            true,
        ),
        // Polar.sh personal access tokens
        (
            r"polar_pat_[A-Za-z0-9_-]{16,}",
            "[REDACTED:polar_pat]",
            "polar_pat",
            true,
        ),
        (
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
            "[REDACTED:slack_token]",
            "slack_token",
            true,
        ),
        (
            r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----",
            "[REDACTED:private_key]",
            "private_key",
            true,
        ),
        // --- Identity (structured PII) ---
        (
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            "[REDACTED:email]",
            "email",
            false,
        ),
        (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED:ssn]", "ssn", false),
        // Phone: E.164 + (xxx) xxx-xxxx + xxx-xxx-xxxx + xxx.xxx.xxxx
        (
            r"\+\d{1,3}[ -]?\d{3,4}[ -]?\d{3,4}[ -]?\d{0,4}|\(\d{3}\)[ -]?\d{3}[ -]?\d{4}|\b\d{3}[-.]\d{3}[-.]\d{4}\b",
            "[REDACTED:phone]",
            "phone",
            false,
        ),
        // Credit card: 13-19 digits with optional separators. Luhn is
        // applied to the regex MATCH after this fast filter — see
        // `refine_credit_cards` (one-way) / `redact_cards_reversible`.
        (
            r"\b(?:\d[ -]?){12,18}\d\b",
            "[REDACTED:credit_card_candidate]",
            "credit_card",
            false,
        ),
        // Network
        (
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "[REDACTED:ipv4]",
            "ipv4",
            false,
        ),
        // IPv6 — "full" form; we don't aggressively match :: shorthands
        // because they'd produce false positives on hex strings.
        (
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            "[REDACTED:ipv6]",
            "ipv6",
            false,
        ),
    ];
    raw.iter()
        .map(|(pat, marker, category, is_secret)| Rule {
            pattern: Regex::new(pat).expect("PII rule regex must compile"),
            marker,
            category,
            is_secret: *is_secret,
        })
        .collect()
});

/// Credit-card candidate matcher, shared by the one-way and reversible
/// paths (13–19 digit runs; Luhn-gated by the caller).
static CC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").expect("cc regex compiles"));

/// Apply PII redaction to a string. Returns a new String with all
/// detected PII replaced with `[REDACTED:<category>]` markers.
///
/// Hot-path note: the regex set is compiled once via `Lazy` and the
/// per-call cost is `O(rules * input_len)` regex scans. For the
/// typical 1–4 KB span attribute this finishes well under 100 µs on
/// modern hardware — comfortably under our predictive-layer budget.
pub fn redact(value: &str) -> String {
    let mut result = value.to_owned();
    for rule in RULES.iter() {
        if rule.pattern.is_match(&result) {
            result = rule.pattern.replace_all(&result, rule.marker).into_owned();
        }
    }
    // Second pass: the credit_card_candidate marker may have replaced
    // non-card numeric runs (timestamps, ids). Re-scan and unmark
    // anything that wasn't Luhn-valid in the original.
    refine_credit_cards(&mut result, value);
    result
}

/// Verify every credit-card-candidate marker corresponds to a Luhn-
/// valid number in the ORIGINAL input. The first pass over-fires on
/// any 13-19 digit run; here we look at each candidate position in
/// the original and either keep the marker (Luhn-valid) or replace
/// with the original digits (false positive — e.g. timestamp).
fn refine_credit_cards(redacted: &mut String, original: &str) {
    let cc_marker = "[REDACTED:credit_card_candidate]";
    if !redacted.contains(cc_marker) {
        return;
    }
    // Find every numeric run in the original 13-19 digits (ignoring
    // separators) and check Luhn. Build a list of (orig_substring,
    // luhn_valid).
    let candidates: Vec<(String, bool)> = CC_RE
        .find_iter(original)
        .map(|m| {
            let s = m.as_str().to_owned();
            let valid = luhn_check(&s);
            (s, valid)
        })
        .collect();

    // Replace markers in order. For Luhn-valid -> swap to
    // [REDACTED:credit_card]. For invalid -> restore the original digits.
    let mut out = String::with_capacity(redacted.len());
    let mut idx = 0usize;
    let mut cursor = 0usize;
    while let Some(pos) = redacted[cursor..].find(cc_marker) {
        let abs = cursor + pos;
        out.push_str(&redacted[cursor..abs]);
        match candidates.get(idx) {
            Some((orig, true)) => {
                let _ = orig;
                out.push_str("[REDACTED:credit_card]");
            }
            Some((orig, false)) => out.push_str(orig),
            None => out.push_str("[REDACTED:credit_card]"),
        }
        idx += 1;
        cursor = abs + cc_marker.len();
    }
    out.push_str(&redacted[cursor..]);
    *redacted = out;
}

/// Luhn check digit verification. Returns true for valid card numbers
/// after stripping spaces and dashes; false for any string with non-
/// digit content other than separators or with bad checksum.
fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        if i % 2 == 1 {
            let dd = d * 2;
            sum += if dd > 9 { dd - 9 } else { dd };
        } else {
            sum += d;
        }
    }
    sum.is_multiple_of(10)
}

/// Recursively redact PII from a JSON value. Object keys are not
/// redacted (they're schema, not payload); only string values + nested
/// containers.
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(redact(s)),
        Value::Array(arr) => Value::Array(arr.iter().map(redact_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

// ── Reversible redaction (guardrail R2, the guardrail spec §3 R2) ──────────
//
// Unlike the one-way [`redact`] (observability span attributes), the guardrail
// R2 rail needs **reversible** redaction: each detected secret/PII run is
// replaced with a `{{TL_REDACT:<category>:<idx>}}` placeholder and the original
// is held in a per-request in-memory map so the streamed response can re-insert
// it (the placeholders egress to the provider; the user sees their original
// data restored). Same `RULES` source as `redact` — one detector set, two
// output shapes.

/// `{{TL_REDACT:<category>:<idx>}}` placeholder prefix.
const REDACT_OPEN: &str = "{{TL_REDACT:";

/// One reversible redaction: the placeholder that replaced an original run +
/// the original text. The original is sensitive (secret/PII) — held in memory
/// per request, never logged or persisted. `category` is the stable detector
/// name (`openai_key`, `credit_card`, `email`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionEntry {
    pub category: &'static str,
    pub placeholder: String,
    pub original: String,
}

impl RedactionEntry {
    /// Whether this entry is a secret-class detection (vs structured PII).
    /// Secrets are fail-CLOSED in R2; PII is redact-or-warn.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        is_secret_category(self.category)
    }
}

/// The result of a reversible redaction: the rewritten text (placeholders in
/// place of secrets/PII) plus the ordered map needed to restore the originals.
#[derive(Debug, Clone, Default)]
pub struct ReversibleRedaction {
    pub redacted: String,
    pub entries: Vec<RedactionEntry>,
}

impl ReversibleRedaction {
    /// No secrets/PII detected — the text is unchanged.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether any detected entry is a secret (R2 fail-closed class).
    #[must_use]
    pub fn has_secret(&self) -> bool {
        self.entries.iter().any(RedactionEntry::is_secret)
    }
}

/// Whether a detector category is a secret (vs structured PII). Resolved from
/// the single `RULES` source. Unknown categories default to non-secret.
#[must_use]
pub fn is_secret_category(category: &str) -> bool {
    RULES
        .iter()
        .find(|r| r.category == category)
        .is_some_and(|r| r.is_secret)
}

/// Reversibly redact a string: replace every detected secret/PII run with a
/// `{{TL_REDACT:<category>:<idx>}}` placeholder and return the placeholder→
/// original map. Credit cards are Luhn-gated (only valid numbers redact).
/// `idx` is globally unique + monotonic across categories within one call.
///
/// Reuses the same `RULES` as [`redact`]; rules run in priority order on the
/// progressively-redacted text so a placeholder is never re-matched.
#[must_use]
pub fn redact_reversible(value: &str) -> ReversibleRedaction {
    redact_reversible_from(value, 0)
}

/// Like [`redact_reversible`] but with placeholder indices starting at `base`.
/// Use this to redact MULTIPLE fields of one request into a single map without
/// placeholder-index collisions: pass `map.len()` as `base` per field so every
/// `{{TL_REDACT:<cat>:<idx>}}` across the whole request is unique (re-insertion
/// replaces by exact placeholder string, so duplicate indices would corrupt it).
#[must_use]
pub fn redact_reversible_from(value: &str, base: usize) -> ReversibleRedaction {
    let mut text = value.to_owned();
    let mut entries: Vec<RedactionEntry> = Vec::new();

    for rule in RULES.iter() {
        // Credit cards need Luhn gating — handled in a dedicated pass below so
        // non-card numeric runs (timestamps, ids) are not redacted.
        if rule.category == "credit_card" {
            continue;
        }
        if !rule.pattern.is_match(&text) {
            continue;
        }
        let replaced = rule
            .pattern
            .replace_all(&text, |caps: &regex::Captures| {
                let original = caps.get(0).map_or("", |m| m.as_str()).to_owned();
                let idx = base + entries.len();
                let placeholder = format!("{REDACT_OPEN}{}:{idx}}}}}", rule.category);
                entries.push(RedactionEntry {
                    category: rule.category,
                    placeholder: placeholder.clone(),
                    original,
                });
                placeholder
            })
            .into_owned();
        text = replaced;
    }

    redact_cards_reversible(&mut text, &mut entries, base);
    ReversibleRedaction {
        redacted: text,
        entries,
    }
}

/// Luhn-gated reversible credit-card pass: each 13–19 digit run that passes
/// Luhn becomes a `{{TL_REDACT:credit_card:<idx>}}` placeholder; invalid runs
/// (timestamps, ids) are left untouched.
fn redact_cards_reversible(text: &mut String, entries: &mut Vec<RedactionEntry>, base: usize) {
    if !CC_RE.is_match(text) {
        return;
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for m in CC_RE.find_iter(text) {
        out.push_str(&text[last..m.start()]);
        let original = m.as_str();
        if luhn_check(original) {
            let idx = base + entries.len();
            let placeholder = format!("{REDACT_OPEN}credit_card:{idx}}}}}");
            entries.push(RedactionEntry {
                category: "credit_card",
                placeholder: placeholder.clone(),
                original: original.to_owned(),
            });
            out.push_str(&placeholder);
        } else {
            out.push_str(original);
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    *text = out;
}

/// Restore originals into a (possibly model-transformed) response string by
/// swapping each placeholder back to its original. Used by the response-side
/// re-insertion (guardrail R5/R6 SSE wiring). A placeholder the model dropped
/// is simply skipped; one it echoed is restored.
#[must_use]
pub fn reinsert(text: &str, entries: &[RedactionEntry]) -> String {
    let mut out = text.to_owned();
    for e in entries {
        if out.contains(&e.placeholder) {
            out = out.replace(&e.placeholder, &e.original);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_string_unchanged() {
        assert_eq!(redact("hello world"), "hello world");
        assert_eq!(redact("the quick brown fox"), "the quick brown fox");
    }

    #[test]
    fn redacts_email() {
        let r = redact("Contact me at jane.doe+filter@example.co.uk for details");
        assert!(r.contains("[REDACTED:email]"));
        assert!(!r.contains("jane.doe"));
    }

    #[test]
    fn redacts_ssn() {
        let r = redact("SSN: 123-45-6789");
        assert!(r.contains("[REDACTED:ssn]"));
        assert!(!r.contains("123-45-6789"));
    }

    #[test]
    fn redacts_aws_access_key() {
        let r = redact("AKIAIOSFODNN7EXAMPLE keep going");
        assert!(r.contains("[REDACTED:aws_key]"));
        assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn redacts_classic_google_api_key() {
        let r = redact("GOOGLE_API_KEY=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456789 done");
        assert!(r.contains("[REDACTED:google_api_key]"), "got: {r}");
        assert!(!r.contains("SyAbCdEf"), "got: {r}");
    }

    /// B-112: AI Studio issues only `AQ.` Authentication Keys now, and Gemini
    /// rejects all classic `AIza` keys from Sept 2026 — so this is the format
    /// customer keys will actually have.
    #[test]
    fn redacts_google_aq_auth_key() {
        let r = redact("GOOGLE_API_KEY=AQ.AbUNIT-TEST-FAKE-KEY-do-not-use-in-prod-0000 done");
        assert!(r.contains("[REDACTED:google_api_key]"), "got: {r}");
        assert!(!r.contains("UNIT-TEST-FAKE-KEY"), "got: {r}");
        assert!(r.contains("done"), "surrounding text must survive: {r}");
    }

    /// The length floor is what separates a key from prose — `FAQ.` and friends
    /// must not be eaten.
    #[test]
    fn short_aq_string_is_not_a_key() {
        let input = "see FAQ.md and AQ.short for details";
        assert_eq!(redact(input), input);
    }

    #[test]
    fn redacts_github_pat_ghp() {
        // 36+ chars after ghp_
        let r = redact("token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa next");
        assert!(r.contains("[REDACTED:github_token]"));
    }

    #[test]
    fn redacts_stripe_secret() {
        // Split literal: no contiguous Stripe-key shape in source (GitHub push protection);
        // concat! rebuilds the identical string the redactor is tested against.
        let secret = concat!("sk_live_", "abcdefghijklmnopqrstuvwx");
        let r = redact(&format!("{secret} is the secret"));
        assert!(r.contains("[REDACTED:stripe_key]"));
        assert!(!r.contains(secret));
    }

    #[test]
    fn redacts_slack_bot_token() {
        let r = redact("xoxb-1234567890-abcdefghij is leaked");
        assert!(r.contains("[REDACTED:slack_token]"));
    }

    #[test]
    fn redacts_phone_e164() {
        let r = redact("Call +1 415 555 0123 today");
        assert!(r.contains("[REDACTED:phone]"));
    }

    #[test]
    fn redacts_phone_us_dashed() {
        let r = redact("Call 415-555-0123 today");
        assert!(r.contains("[REDACTED:phone]"));
    }

    #[test]
    fn redacts_phone_us_parens() {
        let r = redact("Call (415) 555-0123 today");
        assert!(r.contains("[REDACTED:phone]"));
    }

    #[test]
    fn redacts_ipv4() {
        let r = redact("source=192.168.1.42 dest=10.0.0.7");
        assert!(r.contains("[REDACTED:ipv4]"));
        assert!(!r.contains("192.168.1.42"));
    }

    #[test]
    fn redacts_ipv6_full() {
        let r = redact("addr=2001:0db8:85a3:0000:0000:8a2e:0370:7334 done");
        assert!(r.contains("[REDACTED:ipv6]"));
    }

    #[test]
    fn redacts_private_key_pem() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let r = redact(pem);
        assert!(r.contains("[REDACTED:private_key]"));
        assert!(!r.contains("MIIE"));
    }

    #[test]
    fn redacts_valid_credit_card_visa() {
        // Known Luhn-valid Visa test number.
        let r = redact("Charge to 4111 1111 1111 1111 please");
        assert!(r.contains("[REDACTED:credit_card]"));
        assert!(!r.contains("4111 1111 1111 1111"));
    }

    #[test]
    fn redacts_valid_credit_card_amex() {
        // Known Luhn-valid Amex test number (15 digits).
        let r = redact("amex=378282246310005");
        assert!(r.contains("[REDACTED:credit_card]"));
    }

    #[test]
    fn does_not_redact_non_luhn_long_number() {
        // 16 digits but not Luhn-valid. Should NOT be redacted as cc.
        let r = redact("session_id=1234567890123456 — not a card");
        assert!(!r.contains("[REDACTED:credit_card]"));
        // The candidate marker should also be gone.
        assert!(!r.contains("credit_card_candidate"));
    }

    #[test]
    fn luhn_check_known_vectors() {
        // Standard test set from the Luhn spec.
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("378282246310005")); // Amex test
        assert!(luhn_check("5555555555554444")); // MC test
        assert!(!luhn_check("1234567890123456")); // not Luhn
        assert!(!luhn_check("12345")); // too short
    }

    #[test]
    fn json_recurses_into_arrays() {
        let v = serde_json::json!(["hello", "user@example.com", "world"]);
        let red = redact_json(&v);
        let arr = red.as_array().unwrap();
        assert_eq!(arr[0], "hello");
        assert!(arr[1].as_str().unwrap().contains("[REDACTED:email]"));
        assert_eq!(arr[2], "world");
    }

    #[test]
    fn json_recurses_into_objects() {
        let v = serde_json::json!({
            "name": "Jane",
            "contact": {
                "email": "jane@example.com",
                "phone": "+1 415 555 0199",
            },
        });
        let red = redact_json(&v);
        let email = red.pointer("/contact/email").unwrap().as_str().unwrap();
        assert!(email.contains("[REDACTED:email]"));
        let phone = red.pointer("/contact/phone").unwrap().as_str().unwrap();
        assert!(phone.contains("[REDACTED:phone]"));
        // Object keys are not redacted.
        assert!(red.get("contact").is_some());
    }

    #[test]
    fn multiple_categories_in_one_string() {
        let input = "Contact jane@example.com or call 415-555-0123, ssn 123-45-6789";
        let r = redact(input);
        assert!(r.contains("[REDACTED:email]"));
        assert!(r.contains("[REDACTED:phone]"));
        assert!(r.contains("[REDACTED:ssn]"));
    }

    #[test]
    fn idempotent_redact() {
        // Redacting an already-redacted string should be a no-op.
        let once = redact("user@example.com");
        let twice = redact(&once);
        assert_eq!(once, twice);
    }

    // ── Reversible redactor (guardrail R2) ───────────────────────────────────

    #[test]
    fn reversible_secret_redacts_and_restores() {
        let input = "use key sk-abcdefghijklmnopqrstuvwxyz012345 now";
        let r = redact_reversible(input);
        assert!(!r.is_clean());
        assert!(r.has_secret(), "openai_key is a secret class");
        assert!(r.redacted.contains("{{TL_REDACT:openai_key:0}}"));
        assert!(
            !r.redacted.contains("sk-abcdefghijklmnop"),
            "the secret must not survive in the redacted text"
        );
        // Reversible: re-inserting restores the exact original input.
        assert_eq!(reinsert(&r.redacted, &r.entries), input);
    }

    #[test]
    fn reversible_credit_card_luhn_gated_and_restores() {
        let input = "card 4111 1111 1111 1111 and id 1234567890123456";
        let r = redact_reversible(input);
        // The Luhn-valid card is redacted; the non-Luhn 16-digit id is not.
        assert!(r.redacted.contains("{{TL_REDACT:credit_card:0}}"));
        assert!(r.redacted.contains("1234567890123456"));
        assert!(!r.redacted.contains("4111 1111 1111 1111"));
        assert!(!r.has_secret(), "credit_card is PII, not secret");
        assert_eq!(reinsert(&r.redacted, &r.entries), input);
    }

    #[test]
    fn reversible_pii_email_is_not_secret_class() {
        let r = redact_reversible("ping jane@example.com please");
        assert!(r.redacted.contains("{{TL_REDACT:email:0}}"));
        assert!(!r.has_secret());
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].category, "email");
        assert!(!r.entries[0].is_secret());
    }

    #[test]
    fn reversible_clean_text_is_noop() {
        let r = redact_reversible("the quick brown fox");
        assert!(r.is_clean());
        assert_eq!(r.redacted, "the quick brown fox");
        assert_eq!(reinsert(&r.redacted, &r.entries), "the quick brown fox");
    }

    #[test]
    fn reversible_indices_are_unique_across_categories() {
        let input = "mail a@b.com and a@b.com, key sk-abcdefghijklmnopqrstuvwxyz0123";
        let r = redact_reversible(input);
        // Two emails + one key → three entries, monotonically indexed 0,1,2.
        assert_eq!(r.entries.len(), 3);
        let placeholders: Vec<&str> = r.entries.iter().map(|e| e.placeholder.as_str()).collect();
        assert!(placeholders.iter().all(|p| p.starts_with("{{TL_REDACT:")));
        // Every placeholder is distinct (no idx collision).
        let mut seen = std::collections::HashSet::new();
        assert!(r.entries.iter().all(|e| seen.insert(e.placeholder.clone())));
        assert_eq!(reinsert(&r.redacted, &r.entries), input);
    }

    #[test]
    fn reinsert_restores_only_echoed_placeholders() {
        // The model echoes one placeholder and drops the other — re-insertion
        // restores what it echoed, leaves the rest of the text alone.
        let r = redact_reversible("a@b.com then c@d.com");
        let model_response = format!("I noted {} for you", r.entries[0].placeholder);
        let restored = reinsert(&model_response, &r.entries);
        assert_eq!(restored, "I noted a@b.com for you");
    }

    #[test]
    fn reversible_from_base_gives_globally_unique_indices() {
        // Two fields redacted into one map: passing map.len() as base keeps
        // every placeholder unique so re-insertion can't collide.
        let mut map = Vec::new();
        let f1 = redact_reversible_from("key sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaa", map.len());
        map.extend(f1.entries.clone());
        let f2 = redact_reversible_from("other sk-bbbbbbbbbbbbbbbbbbbbbbbbbbbb", map.len());
        map.extend(f2.entries.clone());
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].placeholder, "{{TL_REDACT:openai_key:0}}");
        assert_eq!(map[1].placeholder, "{{TL_REDACT:openai_key:1}}");
        assert_ne!(map[0].placeholder, map[1].placeholder);
        // Re-inserting the second field's text restores ITS original, not the first.
        assert_eq!(
            reinsert(&f2.redacted, &map),
            "other sk-bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn is_secret_category_classifies() {
        assert!(is_secret_category("openai_key"));
        assert!(is_secret_category("aws_key"));
        assert!(is_secret_category("private_key"));
        assert!(!is_secret_category("email"));
        assert!(!is_secret_category("credit_card"));
        assert!(!is_secret_category("unknown_made_up"));
    }
}
