//! AFT failure-signature id shape (ADR-056 H1).
//!
//! One rule, two enforcement points, and they must not drift: the OTLP decode
//! boundary drops a malformed id before it enters `SpanAttributes`
//! ([`crate::otlp::decode`]), and ingest's federation writer drops it again
//! before it reaches the cross-tenant table. The decoder moved to `shared` for
//! `GWY-41`, so the predicate moved with it rather than being copied — a
//! duplicated validator is how one side quietly gets laxer than the other.
//!
//! `ingest::federation` re-exports this, so its call sites are unchanged.

/// Is `s` a well-formed AFT failure-signature id?
///
/// The predictive layer only ever emits `&'static` `AFT-…` constants (e.g.
/// `AFT-TOOL-DRIFT-001`, `AFT-MCP-RUGPULL-001`), so a valid id is: `AFT-`
/// prefixed, 5..=64 chars, ASCII uppercase / digit / `-` only.
///
/// This bounds the value to the taxonomy **SHAPE**, so attacker-supplied free
/// text — PII, storage bombs, lowercase sentences — is rejected, **without** a
/// brittle enumerated allowlist that could silently drop a newly-added class (a
/// green-while-broken trap).
#[must_use]
pub fn is_valid_aft_id(s: &str) -> bool {
    (5..=64).contains(&s.len())
        && s.starts_with("AFT-")
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_shapes_the_predictive_layer_emits() {
        assert!(is_valid_aft_id("AFT-TOOL-DRIFT-001"));
        assert!(is_valid_aft_id("AFT-MCP-RUGPULL-001"));
        assert!(is_valid_aft_id("AFT-1"));
    }

    /// The whole point: free text must not reach the cross-tenant table or a
    /// span attribute, whichever boundary sees it first.
    #[test]
    fn rejects_attacker_supplied_free_text() {
        assert!(!is_valid_aft_id(""));
        assert!(!is_valid_aft_id("AFT"));
        assert!(!is_valid_aft_id("aft-tool-drift-001"), "lowercase");
        assert!(!is_valid_aft_id("AFT-user@example.com"), "PII shape");
        assert!(!is_valid_aft_id("NOT-AFT-001"), "wrong prefix");
        assert!(
            !is_valid_aft_id(&format!("AFT-{}", "A".repeat(64))),
            "storage bomb"
        );
    }
}
