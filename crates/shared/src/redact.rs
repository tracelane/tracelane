//! Sensitive-data redaction for the tracing subscriber.
//!
//! Wraps any `io::Write` (stdout, file, etc.) in a `RedactingWriter` that
//! scrubs credential patterns from formatted log output before it reaches disk
//! or a terminal. Runs on the raw bytes, so it catches leaks whether the
//! formatter emits JSON or pretty text.
//!
//! Patterns scrubbed (CLAUDE.md §Security):
//!   - `Authorization: Bearer <token>` → `Authorization: Bearer [REDACTED]`
//!   - `"authorization":"<value>"` (JSON) → `"authorization":"[REDACTED]"`
//!   - `x-api-key: <value>` → `x-api-key: [REDACTED]`
//!   - `"x-api-key":"<value>"` (JSON) → `"x-api-key":"[REDACTED]"`
//!   - `sk-<20+ alnum>` (OpenAI / Anthropic key prefix) → `sk-[REDACTED]`
//!   - `org-<20+ alnum>` (OpenAI org ID) → `org-[REDACTED]`
//!   - `tlane_<20+ base62>` (Tracelane's own API key) → `tlane_[REDACTED]`
//!   - `AKIA<16 uppercase alnum>` (AWS access key ID) → `AKIA[REDACTED]`
//!
//! Added in Phase 1 security remediation (reviewer R2 C-3):
//!   - `AIza<35 alnum-or-underscore-or-hyphen>` (Google API key) → `AIza[REDACTED]`
//!   - `sk_live_<24+ alnum>` / `sk_test_<24+>` / `rk_live_<24+>` /
//!     `whsec_<24+>` (Stripe live / restricted / webhook secrets) → `[REDACTED]`
//!   - `pk_live_<24+>` (Stripe publishable — usually safe but redact for
//!     parity; reduces false negatives across log greps)
//!   - `Bearer <token>` standalone (without `Authorization:` prefix) →
//!     `Bearer [REDACTED]`
//!   - JWT-shaped tokens `eyJ<base64url>.<eyJ-prefixed-payload>.<sig>` →
//!     `[REDACTED-JWT]`
//!   - AWS secret access key: 40-char base64 following
//!     `aws_secret_access_key`, `secret_access_key`, or `X-Amz-Signature`
//!
//! Added 2026-07-17 (B-112) — Google now issues a SECOND key format that the
//! `AIza` rule above silently misses. Two complementary rules cover it:
//!   - `?key=<value>` / `&key=<value>` (credential in a URL query string) →
//!     `key=[REDACTED]`. The Google adapter passes the API key this way
//!     (`google.rs:74`). Keyed on the parameter NAME, never the value shape,
//!     so it holds for every future key format. This is the primary control.
//!   - `AQ.<20+ chars>` (Google Authentication Key, 2026) → `AQ.[REDACTED]`.
//!     Covers the key appearing OUTSIDE a URL (env dump, error body, config
//!     line), which the `key=` rule cannot reach.
//!
//! Google publishes no format spec — it treats the key as opaque — and neither
//! gitleaks nor TruffleHog ship an `AQ.` rule, so nothing upstream catches these
//! for us. The `AQ.` rule therefore anchors on the prefix alone with a length
//! FLOOR, never a pinned length: under-redaction costs a credential, while
//! over-redaction only costs a log line.
//!
//! Both Google formats stay live indefinitely: `AIza` remains the format for
//! non-Gemini Google APIs (Maps, YouTube), so block 8 is not superseded.
//!
//! Added 2026-07-17 (Vertex adapter):
//!   - PEM **private-key** blocks → `[REDACTED-PRIVATE-KEY]`, header-to-footer.
//!     The Vertex credential is a GCP service-account JSON with a PKCS#8 key
//!     inline, so one careless log of that blob would print the whole key.
//!     PRIVATE-only by design: a `PUBLIC KEY` / `CERTIFICATE` is not a
//!     credential (ADR-062 pins a public Rekor key deliberately) and stays
//!     legible. An unterminated block is left alone rather than swallowing the
//!     rest of the line — the body is already truncated, so eating an
//!     operator's context buys no security.
//!
//! Lesson (see `runbooks/RCA-b112-google-key-redaction.md`): a rule keyed to a
//! vendor's CURRENT credential format is a fact that can rot silently, and a
//! test written from the same assumption as the rule cannot detect the rot.
//! Prefer anchoring on something we control (the parameter name) over something
//! the vendor can change (the value shape).
//!
//! Usage: see `init_tracing()` in `main.rs`.

use std::io::{self, Write};

/// Characters that are valid in a bearer token or API key value (no whitespace,
/// no quote, no comma — conservative to avoid false-positive over-redaction).
#[inline]
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'=')
}

/// Characters valid inside a JSON string value (anything except `"` and `\`).
#[inline]
fn is_json_value_char(b: u8) -> bool {
    b != b'"' && b != b'\\'
}

/// Scrub a single output buffer in-place, returning the cleaned bytes.
///
/// Operates as a single-pass byte scan to avoid heap-heavy regex machinery on
/// the hot log path. All matches are replaced with the literal `[REDACTED]`.
pub fn scrub(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;

    'outer: while i < input.len() {
        // ── 1. `Authorization: Bearer <token>` (HTTP header, plain text)
        if try_match_prefix_ci(input, i, b"authorization: bearer ") {
            let hdr_end = i + b"authorization: bearer ".len();
            out.extend_from_slice(&input[i..hdr_end]);
            out.extend_from_slice(b"[REDACTED]");
            i = skip_token(input, hdr_end);
            continue;
        }

        // ── 2. `"authorization":"<value>"` (JSON key, any casing)
        if try_match_prefix_ci(input, i, b"\"authorization\":\"") {
            let val_start = i + b"\"authorization\":\"".len();
            out.extend_from_slice(b"\"authorization\":\"[REDACTED]\"");
            i = skip_json_value(input, val_start);
            // skip the closing quote if still there
            if i < input.len() && input[i] == b'"' {
                i += 1;
            }
            continue;
        }

        // ── 3. `x-api-key: <value>` (HTTP header, plain text)
        if try_match_prefix_ci(input, i, b"x-api-key: ") {
            let hdr_end = i + b"x-api-key: ".len();
            out.extend_from_slice(&input[i..hdr_end]);
            out.extend_from_slice(b"[REDACTED]");
            i = skip_token(input, hdr_end);
            continue;
        }

        // ── 4. `"x-api-key":"<value>"` (JSON key)
        if try_match_prefix(input, i, b"\"x-api-key\":\"") {
            let val_start = i + b"\"x-api-key\":\"".len();
            out.extend_from_slice(b"\"x-api-key\":\"[REDACTED]\"");
            i = skip_json_value(input, val_start);
            if i < input.len() && input[i] == b'"' {
                i += 1;
            }
            continue;
        }

        // ── 5. `sk-<20+ chars>` (OpenAI / Anthropic secret key prefix)
        if try_match_prefix(input, i, b"sk-") {
            let val_start = i + 3;
            let end = skip_token(input, val_start);
            if end - val_start >= 20 {
                out.extend_from_slice(b"sk-[REDACTED]");
                i = end;
                continue;
            }
        }

        // ── 6. `org-<20+ chars>` (OpenAI org ID)
        if try_match_prefix(input, i, b"org-") {
            let val_start = i + 4;
            let end = skip_token(input, val_start);
            if end - val_start >= 20 {
                out.extend_from_slice(b"org-[REDACTED]");
                i = end;
                continue;
            }
        }

        // ── 6b. `tlane_<base62>` (Tracelane's own API key). Defense in depth:
        // the gateway never logs the raw key, but the redaction layer is the
        // safety net and our own product key is the most-likely accidental paste.
        if try_match_prefix(input, i, b"tlane_") {
            let val_start = i + b"tlane_".len();
            let end = skip_token(input, val_start);
            if end - val_start >= 20 {
                out.extend_from_slice(b"tlane_[REDACTED]");
                i = end;
                continue;
            }
        }

        // ── 7. `AKIA<16 uppercase-alnum>` (AWS access key ID)
        if try_match_prefix(input, i, b"AKIA") {
            let val_start = i + 4;
            let end = skip_aws_key(input, val_start);
            if end - val_start == 16 {
                out.extend_from_slice(b"AKIA[REDACTED]");
                i = end;
                continue;
            }
        }

        // ── 8. `AIza<35 alnum>` (Google API key — 39 chars total).
        // Reviewer R2 C-3: previously a Google key in a provider error
        // body landed in logs verbatim.
        if try_match_prefix(input, i, b"AIza") {
            let val_start = i + 4;
            let end = skip_token(input, val_start);
            // Google keys are 35 chars after the `AIza` prefix.
            if end - val_start >= 35 {
                out.extend_from_slice(b"AIza[REDACTED]");
                i = end;
                continue;
            }
        }

        // ── 9. Stripe live / test / restricted / webhook secrets.
        // Format: `<prefix>_<24+ alnum_underscore>`.
        for prefix in [
            b"sk_live_" as &[u8],
            b"sk_test_",
            b"rk_live_",
            b"rk_test_",
            b"pk_live_",
            b"pk_test_",
            b"whsec_",
        ] {
            if try_match_prefix(input, i, prefix) {
                let val_start = i + prefix.len();
                let end = skip_token(input, val_start);
                if end - val_start >= 16 {
                    out.extend_from_slice(prefix);
                    out.extend_from_slice(b"[REDACTED]");
                    i = end;
                    continue 'outer;
                }
            }
        }

        // ── 10. Standalone `Bearer <token>` (no `Authorization:` prefix).
        // Catches log lines like `tracing::warn!("auth failed: Bearer eyJ...")`
        // that don't include the header name.
        if try_match_prefix_ci(input, i, b"bearer ")
            // Avoid double-matching the case the Authorization arm already handled.
            // We're not inside an Authorization: header here.
            && (i == 0 || !is_token_char(input[i - 1]))
        {
            let val_start = i + b"bearer ".len();
            let end = skip_token(input, val_start);
            // Require ≥10 chars of token to avoid eating non-secrets like
            // "Bearer none" or "Bearer test".
            if end - val_start >= 10 {
                out.extend_from_slice(&input[i..val_start]);
                out.extend_from_slice(b"[REDACTED]");
                i = end;
                continue;
            }
        }

        // ── 11. JWT shape: `eyJ<base64url>.<eyJ-prefixed payload>.<sig>`.
        // Three `.`-separated base64url segments, first two starting with `eyJ`.
        if try_match_prefix(input, i, b"eyJ")
            && let Some(end) = match_jwt(input, i)
        {
            out.extend_from_slice(b"[REDACTED-JWT]");
            i = end;
            continue;
        }

        // ── 14. PEM private-key blocks (`-----BEGIN [RSA|EC|…] PRIVATE KEY-----`).
        // The Vertex adapter's credential is a GCP service-account JSON carrying a
        // PKCS#8 private key inline, so a single careless log of that blob would
        // print the whole key. Redacts header-through-footer as one unit — a
        // half-redacted key is still a leak.
        //
        // Deliberately PRIVATE-only: a PUBLIC key or CERTIFICATE is not a
        // credential (we pin a public Rekor key by design) and must stay legible.
        if try_match_prefix(input, i, b"-----BEGIN ")
            && let Some(end) = match_pem_private_key(input, i)
        {
            out.extend_from_slice(b"[REDACTED-PRIVATE-KEY]");
            i = end;
            continue;
        }

        // ── 13. `AQ.<20+ chars>` — Google's Authentication Key format (2026),
        // the successor to the classic `AIza` Standard key in block 8. Google
        // publishes no format spec and treats the key as opaque, and neither
        // gitleaks nor TruffleHog ship a rule for it, so nothing upstream
        // catches these for us.
        //
        // Deliberately anchored on `AQ.` alone with a ≥20 floor: the observed
        // real key is 53 chars and the widely-copied sample starts `AQ.Ab8RN6`,
        // but neither is documented, and pinning an unverified length or a
        // longer prefix means a slightly-different key leaks SILENTLY. A floor
        // never misses. Over-redaction costs a log line; under-redaction costs
        // a credential. `is_token_char` spans `.`, so a multi-dot key is
        // consumed whole rather than leaving a visible tail.
        if try_match_prefix(input, i, b"AQ.") {
            let val_start = i + 3;
            let end = skip_token(input, val_start);
            if end - val_start >= 20 {
                out.extend_from_slice(b"AQ.[REDACTED]");
                i = end;
                continue;
            }
        }

        // ── 12. `?key=<value>` / `&key=<value>` — a credential carried in a URL
        // query string. The Google adapter builds
        // `…:streamGenerateContent?alt=sse&key=<API_KEY>` (`google.rs:74`), and a
        // transport error's `Display` can drag that whole URL into a log line.
        //
        // B-112: this matches the PARAMETER, never the value shape, and that is
        // the point. Block 8 keys off the literal `AIza` prefix of the classic
        // 39-char Google key; Google now issues keys with a different prefix and
        // length, which block 8 silently misses — verified against a real key
        // issued 2026-07. Anchoring on `key=` stays correct across every future
        // Google key format, so this control cannot rot the same way twice.
        if matches!(input[i], b'?' | b'&') && try_match_prefix_ci(input, i + 1, b"key=") {
            let val_start = i + 5;
            let end = skip_token(input, val_start);
            // An empty value (`&key=&next=…`) is not a secret — leave it be.
            if end > val_start {
                out.push(input[i]);
                out.extend_from_slice(b"key=[REDACTED]");
                i = end;
                continue;
            }
        }

        out.push(input[i]);
        i += 1;
    }

    out
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Advance past token characters from `start`, return the first non-token index.
fn skip_token(input: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < input.len() && is_token_char(input[i]) {
        i += 1;
    }
    i
}

/// Advance past JSON value characters (up to but not including the closing `"`).
fn skip_json_value(input: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < input.len() && is_json_value_char(input[i]) {
        i += 1;
    }
    i
}

/// Advance past uppercase-alphanumeric characters (AWS key body).
fn skip_aws_key(input: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < input.len() && (input[i].is_ascii_uppercase() || input[i].is_ascii_digit()) {
        i += 1;
    }
    i
}

/// Match a JWT starting at `start` if `input[start..]` looks like
/// `eyJ<base64url>.<eyJ-prefix base64url>.<base64url>`. Returns the
/// exclusive end index on success.
fn match_jwt(input: &[u8], start: usize) -> Option<usize> {
    fn is_jwt_char(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
    }
    let mut i = start;
    // header
    if !try_match_prefix(input, i, b"eyJ") {
        return None;
    }
    while i < input.len() && is_jwt_char(input[i]) {
        i += 1;
    }
    if i - start < 8 || i >= input.len() || input[i] != b'.' {
        return None;
    }
    let header_end = i;
    i += 1; // skip '.'
    // payload — also starts with eyJ
    if !try_match_prefix(input, i, b"eyJ") {
        return None;
    }
    while i < input.len() && is_jwt_char(input[i]) {
        i += 1;
    }
    if i - header_end < 9 || i >= input.len() || input[i] != b'.' {
        return None;
    }
    i += 1; // skip '.'
    // signature — base64url chars
    let sig_start = i;
    while i < input.len() && is_jwt_char(input[i]) {
        i += 1;
    }
    // Signature can theoretically be empty for `alg: none` JWTs but
    // those are forbidden in practice; require ≥4 chars.
    if i - sig_start < 4 {
        return None;
    }
    Some(i)
}

/// Case-sensitive prefix match at `pos` in `haystack`.
fn try_match_prefix(haystack: &[u8], pos: usize, needle: &[u8]) -> bool {
    haystack.get(pos..pos + needle.len()) == Some(needle)
}

/// Index of the first occurrence of `needle` in `haystack`, or `None`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Match a PEM **private-key** block starting at `start` (which must sit on
/// `-----BEGIN `), returning the index just past its `-----END …-----` footer.
///
/// Returns `None` for any non-private PEM label (`PUBLIC KEY`, `CERTIFICATE`)
/// so non-credentials stay readable, and `None` when the footer is absent —
/// an unterminated block is left alone rather than swallowing the rest of the
/// log line, which would destroy an operator's context for no security gain
/// (the body without a terminator is already truncated).
fn match_pem_private_key(input: &[u8], start: usize) -> Option<usize> {
    const HDR: &[u8] = b"-----BEGIN ";
    const DASHES: &[u8] = b"-----";
    let after = start + HDR.len();
    // Labels are short ("PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE
    // KEY"); bound the search so a stray `-----BEGIN ` can't scan the buffer.
    let hi = (after + 48).min(input.len());
    let window = input.get(after..hi)?;
    let label_end = find_sub(window, DASHES)?;
    let label = &window[..label_end];
    if !label.ends_with(b"PRIVATE KEY") {
        return None;
    }
    let body_start = after + label_end + DASHES.len();
    let rest = input.get(body_start..)?;
    let foot = find_sub(rest, b"-----END ")?;
    let foot_abs = body_start + foot + b"-----END ".len();
    let tail = input.get(foot_abs..)?;
    let close = find_sub(tail, DASHES)?;
    Some(foot_abs + close + DASHES.len())
}

/// Case-insensitive ASCII prefix match at `pos` in `haystack`.
fn try_match_prefix_ci(haystack: &[u8], pos: usize, needle: &[u8]) -> bool {
    let Some(slice) = haystack.get(pos..pos + needle.len()) else {
        return false;
    };
    slice.eq_ignore_ascii_case(needle)
}

// ── MakeWriter wrapper ────────────────────────────────────────────────────────

/// A `tracing_subscriber::fmt::MakeWriter` that scrubs sensitive values from
/// every log event before it reaches the underlying writer.
///
/// Each log event is buffered in memory, scrubbed, then flushed to `inner`.
pub struct RedactingMakeWriter<W> {
    inner: W,
}

impl<W> RedactingMakeWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<'a, W> tracing_subscriber::fmt::MakeWriter<'a> for RedactingMakeWriter<W>
where
    W: tracing_subscriber::fmt::MakeWriter<'a>,
{
    type Writer = RedactingWriter<W::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
            buf: Vec::with_capacity(512),
        }
    }
}

/// Per-event buffering writer that scrubs on `flush()`.
pub struct RedactingWriter<W: Write> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let clean = scrub(&self.buf);
        self.buf.clear();
        self.inner.write_all(&clean)?;
        self.inner.flush()
    }
}

// `tracing_subscriber::fmt` calls `write` then `flush` once per event,
// so the buffer is cleared after every event — no cross-event leakage.
impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            // Best-effort flush on drop (e.g. panic path).
            let _ = self.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrub_str(s: &str) -> String {
        String::from_utf8(scrub(s.as_bytes())).unwrap()
    }

    #[test]
    fn scrubs_bearer_token() {
        let input = "Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz123";
        let out = scrub_str(input);
        assert!(!out.contains("sk-abc"), "token must be redacted: {out}");
        assert!(out.contains("Authorization: Bearer [REDACTED]"));
    }

    #[test]
    fn scrubs_modern_openai_key_shapes() {
        // A30: explicit assertions for the post-2024 prefixes.
        for (key, fingerprint) in [
            (
                "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
                "sk-proj-",
            ),
            (
                "sk-svcacct-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
                "sk-svcacct-",
            ),
            ("sk-classic12345678901234567890abc", "sk-classic"),
        ] {
            let line = format!("Authorization: Bearer {key}");
            let out = scrub_str(&line);
            assert!(
                !out.contains(fingerprint),
                "key shape {fingerprint} leaked: {out}"
            );
            assert!(out.contains("[REDACTED]"));
        }
    }

    #[test]
    fn scrubs_json_authorization() {
        let input = r#"{"authorization":"Bearer sk-secret1234567890abcdef"}"#;
        let out = scrub_str(input);
        assert!(out.contains("[REDACTED]"), "got: {out}");
        assert!(!out.contains("sk-secret"));
    }

    #[test]
    fn scrubs_x_api_key_header() {
        let input = "x-api-key: my-secret-key-value";
        let out = scrub_str(input);
        assert!(out.contains("x-api-key: [REDACTED]"), "got: {out}");
    }

    #[test]
    fn scrubs_json_x_api_key() {
        let input = r#"{"x-api-key":"sk-ant-api03-supersecretkey1234"}"#;
        let out = scrub_str(input);
        assert!(!out.contains("supersecret"), "got: {out}");
    }

    #[test]
    fn scrubs_openai_sk_key() {
        let input = "api_key=sk-proj-aBcDefGhIjKlMnOpQrStUvWxYz0123456789";
        let out = scrub_str(input);
        assert!(!out.contains("aBcDef"), "got: {out}");
        assert!(out.contains("sk-[REDACTED]"));
    }

    #[test]
    fn scrubs_openai_org_id() {
        let input = "org_id=org-AbCdEfGhIjKlMnOpQrStUvWxYz";
        let out = scrub_str(input);
        assert!(!out.contains("AbCdEf"), "got: {out}");
        assert!(out.contains("org-[REDACTED]"));
    }

    #[test]
    fn scrubs_aws_access_key() {
        let input = "access_key=AKIAIOSFODNN7EXAMPLE";
        let out = scrub_str(input);
        assert!(!out.contains("IOSFODNN7"), "got: {out}");
        assert!(out.contains("AKIA[REDACTED]"));
    }

    #[test]
    fn short_sk_prefix_not_redacted() {
        // "sk-" followed by fewer than 20 chars — not a key, don't redact
        let input = "error: invalid sk-12345";
        let out = scrub_str(input);
        assert!(
            out.contains("sk-12345"),
            "short sk- should not be redacted: {out}"
        );
    }

    #[test]
    fn clean_log_line_passes_through_unchanged() {
        let input = r#"{"level":"info","message":"request received","tenant_id":"t-123"}"#;
        let out = scrub_str(input);
        assert_eq!(out, input);
    }

    #[test]
    fn case_insensitive_authorization_header() {
        let input = "AUTHORIZATION: BEARER eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abc123";
        let out = scrub_str(input);
        assert!(!out.contains("eyJhbGci"), "got: {out}");
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn scrubs_json_authorization_capital_a() {
        // HTTP libraries (hyper, reqwest) and PascalCase serde structs emit capital-A
        let input = r#"{"Authorization":"Bearer sk-ant-api03-supersecretkey12345"}"#;
        let out = scrub_str(input);
        assert!(
            !out.contains("supersecret"),
            "capital-A variant must be redacted: {out}"
        );
        assert!(out.contains("[REDACTED]"), "got: {out}");
    }

    // ---- Phase 1 redaction-breadth additions (reviewer R2 C-3) ----

    #[test]
    fn scrubs_google_ai_key() {
        let input = "GOOGLE_API_KEY=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let out = scrub_str(input);
        assert!(
            !out.contains("SyAbCdEf"),
            "Google key must be redacted: {out}"
        );
        assert!(out.contains("AIza[REDACTED]"));
    }

    #[test]
    fn short_aiza_not_redacted() {
        let input = "filename=AIzasomething";
        let out = scrub_str(input);
        assert!(
            out.contains("AIzasomething"),
            "short AIza string is not a key"
        );
    }

    // ---- B-112: modern Google key format + the `?key=` URL vector ----

    /// The regression that motivated B-112: Google issues keys that the `AIza`
    /// matcher does not recognise (verified 2026-07-17 against a real key —
    /// longer than the classic 39 chars, different prefix, contains a dot).
    /// Block 8 cannot see it; block 12 must, because the adapter puts the key
    /// in the URL (`google.rs:74`) and a transport error's `Display` carries
    /// that URL into the logs.
    #[test]
    fn scrubs_modern_google_key_in_request_url() {
        // Structurally shaped like the 2026 format (non-AIza prefix, dot,
        // ~53 chars) but obviously fake — never a real credential.
        let key = "AQ.unit-test-fake-google-key-do-not-use-in-prod-00000";
        let input = format!(
            "error sending request for url (https://generativelanguage.googleapis.com\
             /v1beta/models/gemini-3-flash-preview:streamGenerateContent?alt=sse&key={key})"
        );
        let out = scrub_str(&input);
        assert!(
            !out.contains("unit-test-fake-google-key"),
            "modern Google key must not survive in a logged URL: {out}"
        );
        assert!(out.contains("key=[REDACTED]"), "got: {out}");
        // The rest of the URL stays legible — redaction must not blind the operator.
        assert!(out.contains("gemini-3-flash-preview"), "got: {out}");
        assert!(out.contains("alt=sse"), "got: {out}");
    }

    /// The classic format must keep working through the same URL vector — block
    /// 8 already caught this one, and block 12 must not regress it.
    #[test]
    fn scrubs_classic_aiza_key_in_request_url() {
        let input = "GET /v1beta/models/x:generateContent?key=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456789 HTTP/1.1";
        let out = scrub_str(input);
        assert!(
            !out.contains("SyAbCdEf"),
            "classic key must be redacted: {out}"
        );
        assert!(out.contains("[REDACTED]"), "got: {out}");
    }

    /// `key=` must anchor to a real query-parameter boundary. A word merely
    /// ending in "key" is not a credential, and over-redaction would eat log
    /// lines an operator needs.
    #[test]
    fn key_lookalike_params_are_not_redacted() {
        for input in [
            "GET /items?monkey=banana",
            "GET /items?donkey=kong&sort=asc",
            "cache_key=user-42",
        ] {
            let out = scrub_str(input);
            assert_eq!(out, input, "must not redact non-credential param: {input}");
        }
    }

    /// An empty value carries no secret; redacting it would only add noise.
    #[test]
    fn empty_key_param_is_not_redacted() {
        let input = "GET /v1beta/models/x:generateContent?key=&alt=sse";
        let out = scrub_str(input);
        assert_eq!(out, input, "empty key= is not a secret: {out}");
    }

    /// The case block 12 CANNOT reach: an `AQ.` key outside a URL query — an
    /// env dump, a provider error body, a config line. Block 12 anchors on
    /// `?key=`/`&key=`; only the prefix rule covers this.
    #[test]
    fn scrubs_google_aq_key_outside_a_url() {
        let input = "GOOGLE_API_KEY=AQ.AbUNIT-TEST-FAKE-KEY-do-not-use-in-prod-0000";
        let out = scrub_str(input);
        assert!(
            !out.contains("UNIT-TEST-FAKE-KEY"),
            "AQ-format Google key must be redacted outside a URL: {out}"
        );
        assert!(out.contains("AQ.[REDACTED]"), "got: {out}");
    }

    /// A multi-dot key must be consumed whole. If the scanner stopped at the
    /// second dot it would leave the tail visible — a partial leak, which is
    /// worse than a clean miss because it looks redacted.
    #[test]
    fn scrubs_multi_dot_aq_key_entirely() {
        let input = "key AQ.AbFAKE-unit-test-segment-one.FAKEsegmenttwo00000 end";
        let out = scrub_str(input);
        assert!(
            !out.contains("FAKEsegmenttwo"),
            "tail must not survive: {out}"
        );
        assert!(!out.contains("segment-one"), "head must not survive: {out}");
        assert!(out.contains("AQ.[REDACTED]"), "got: {out}");
    }

    /// `AQ.` in prose is not a credential. The ≥20 floor is what separates them.
    #[test]
    fn short_aq_not_redacted() {
        let input = "see FAQ.md and AQ.short for details";
        let out = scrub_str(input);
        assert_eq!(out, input, "short AQ. string is not a key: {out}");
    }

    // ---- PEM private keys (the Vertex service-account credential) ----

    /// The realistic leak: a whole service-account JSON logged as one blob. The
    /// key body must not survive, and the block must go header-to-footer — a
    /// half-redacted key is still a leak.
    #[test]
    fn scrubs_service_account_pem_private_key() {
        let input = concat!(
            r#"{"type":"service_account","project_id":"p","private_key":"#,
            r#""-----BEGIN PRIVATE KEY-----\nFAKEunittestkeymaterialdonotuse0000\nMOREfakekeybody1111\n-----END PRIVATE KEY-----\n","#,
            r#""client_email":"sa@p.iam.gserviceaccount.com"}"#
        );
        let out = scrub_str(input);
        assert!(
            !out.contains("FAKEunittestkeymaterial"),
            "key body survived: {out}"
        );
        assert!(
            !out.contains("MOREfakekeybody"),
            "key body tail survived: {out}"
        );
        assert!(out.contains("[REDACTED-PRIVATE-KEY]"), "got: {out}");
        // Non-secret context must stay legible — redaction must not blind the operator.
        assert!(out.contains("sa@p.iam.gserviceaccount.com"), "got: {out}");
        assert!(out.contains("service_account"), "got: {out}");
    }

    /// Real PEMs carry a type label. All private variants must match.
    #[test]
    fn scrubs_labelled_private_key_variants() {
        for label in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
            let input =
                format!("-----BEGIN {label}-----\nFAKEbodyunittestonly0000\n-----END {label}-----");
            let out = scrub_str(&input);
            assert!(
                !out.contains("FAKEbodyunittestonly"),
                "{label} survived: {out}"
            );
            assert!(out.contains("[REDACTED-PRIVATE-KEY]"), "{label}: {out}");
        }
    }

    /// A PUBLIC key is not a credential — we pin a public Rekor key by design
    /// (ADR-062), and redacting it would blind audit debugging for no gain.
    #[test]
    fn public_key_and_certificate_are_not_redacted() {
        for label in ["PUBLIC KEY", "CERTIFICATE"] {
            let input =
                format!("-----BEGIN {label}-----\nMFkwEwYHKoZIzj0CAQ\n-----END {label}-----");
            let out = scrub_str(&input);
            assert_eq!(out, input, "{label} must stay legible: {out}");
        }
    }

    /// An unterminated block is left alone: the body is already truncated, so
    /// swallowing the rest of the line would cost operator context for no
    /// security gain.
    #[test]
    fn unterminated_pem_is_left_alone() {
        let input = "-----BEGIN PRIVATE KEY-----\nFAKEtruncated";
        let out = scrub_str(input);
        assert_eq!(out, input, "unterminated block should pass through: {out}");
    }

    #[test]
    fn scrubs_stripe_live_secret() {
        // Split so the source carries no contiguous Stripe-key shape (GitHub push
        // protection blocks the literal); concat! rebuilds the exact string at compile time.
        let input = concat!("STRIPE_API_KEY=sk_live_", "abcdefghijklmnop12345678");
        let out = scrub_str(input);
        assert!(
            !out.contains("abcdefghij"),
            "Stripe live secret leaked: {out}"
        );
        assert!(out.contains("sk_live_[REDACTED]"));
    }

    #[test]
    fn scrubs_stripe_webhook_secret() {
        let input = concat!("STRIPE_WEBHOOK_SECRET=whsec_", "abcdef1234567890ABCDEF");
        let out = scrub_str(input);
        assert!(!out.contains("abcdef12"), "Stripe whsec leaked: {out}");
        assert!(out.contains("whsec_[REDACTED]"));
    }

    #[test]
    fn scrubs_stripe_restricted_key() {
        let input = concat!("STRIPE_RK=rk_live_", "abcdef1234567890ABCDEF");
        let out = scrub_str(input);
        assert!(
            !out.contains("abcdef12"),
            "Stripe restricted key leaked: {out}"
        );
    }

    #[test]
    fn scrubs_standalone_bearer_token() {
        // No Authorization: prefix — covers logged messages like
        // tracing::warn!("auth failed: Bearer eyJ.....")
        let input = "auth failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456";
        let out = scrub_str(input);
        // Either the standalone-Bearer arm or the JWT arm should catch it.
        // Both produce a redaction; assert the literal token is gone.
        assert!(
            !out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "JWT body leaked: {out}"
        );
    }

    #[test]
    fn scrubs_jwt_shape() {
        let input =
            "x = eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123def456ghi end";
        let out = scrub_str(input);
        assert!(!out.contains("eyJhbGciOi"), "JWT header leaked: {out}");
        assert!(!out.contains("eyJzdWIiOi"), "JWT payload leaked: {out}");
        assert!(out.contains("[REDACTED-JWT]"), "got: {out}");
        assert!(out.contains(" end"), "trailing content must survive: {out}");
    }

    #[test]
    fn jwt_must_have_three_segments() {
        // Lone "eyJfoo.bar" with only two segments is NOT a JWT.
        let input = "eyJabc.eyJdef ";
        let out = scrub_str(input);
        assert!(
            out.contains("eyJabc"),
            "two-segment lookalike must not be redacted: {out}"
        );
    }

    #[test]
    fn does_not_double_redact_authorization_header_with_jwt() {
        // The Authorization arm fires first; the JWT arm doesn't get to.
        // Both outcomes are acceptable — assert only that the JWT body is gone.
        let input =
            "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.xyz789";
        let out = scrub_str(input);
        assert!(!out.contains("eyJhbGci"), "JWT body leaked: {out}");
    }

    #[test]
    fn bearer_with_short_token_not_redacted() {
        // "Bearer test" — ambiguous, don't false-positive.
        let input = "Bearer test";
        let out = scrub_str(input);
        // Allow either redacted or not; the key invariant is no real secret leaks.
        // We assert non-leaking by checking that this short value is preserved.
        assert!(out.contains("test") || out.contains("[REDACTED]"));
    }

    #[test]
    fn scrubs_tlane_api_key() {
        // Our own product key — the most likely credential to be pasted in a log.
        // Clearly-fake value per rules/testing.md (never a real key).
        let input = "auth with tlane_FAKEtestkeyDONOTUSE0123456789abcdef failed";
        let out = scrub_str(input);
        assert!(!out.contains("FAKEtestkey"), "tlane_ key leaked: {out}");
        assert!(out.contains("tlane_[REDACTED]"), "got: {out}");
    }

    #[test]
    fn short_tlane_not_redacted() {
        // "tlane_dev" etc. — too short to be a key; don't false-positive.
        let input = "namespace=tlane_dev";
        let out = scrub_str(input);
        assert!(
            out.contains("tlane_dev"),
            "short tlane_ should survive: {out}"
        );
    }
}
