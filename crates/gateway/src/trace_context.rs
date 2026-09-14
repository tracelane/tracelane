//! Inbound W3C Trace Context on the proxy paths — ADR-075 / `GWY-46` / B-311.
//!
//! WHY. A customer who swaps their OpenAI base URL to the gateway was getting one span per
//! request under a RANDOM trace id, forever: the handlers read only the undocumented
//! `x-trace-id` header and built every span with `parent_span_id: None`. Their framework's
//! OTel HTTP instrumentation already sends `traceparent` on the request; nothing read it. So
//! the gateway leg could never sit inside the customer's own trace tree.
//!
//! WHAT. Strict W3C Trace Context level 1 (`00-<32 hex>-<16 hex>-<2 hex>`, lowercase). The ids
//! are converted with the SAME transforms the OTLP ingest path uses
//! (`tracelane_shared::otlp::decode::{otlp_trace_id_to_uuid, otlp_span_id_to_uuid}`) — the
//! parent is the 8-byte span id zero-padded in the HIGH 8 bytes. Anything else and a framework
//! span shipped to us via `POST /v1/traces` would never match its gateway child; the join is the
//! whole point, so the transform is shared, not copied.
//!
//! TRUST BOUNDARY (ADR-075 §4). `tenant_id` comes from the validated claim and every read
//! filters on it, so a customer-supplied trace id groups spans only inside that tenant — the
//! authority `x-trace-id` has always had, nothing more. No entitlement gate.
//!
//! FAIL-OPEN, by design (CLAUDE.md §10): a malformed header is an observability fault, not a
//! request fault. It is ignored and the request proceeds exactly as before — fresh v4 trace
//! id, no parent. No per-request log line (logging.md); a bad header is the caller's to notice.

use axum::http::HeaderMap;
use uuid::Uuid;

/// The trace the caller is in, and the span the gateway's span should hang under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundTraceContext {
    pub trace_id: Uuid,
    pub parent_span_id: Uuid,
}

/// Parse a `traceparent` value. `None` for anything that is not a well-formed version-00
/// header with non-zero ids — the W3C spec says a receiver MUST treat those as absent.
#[must_use]
pub fn parse_traceparent(value: &str) -> Option<InboundTraceContext> {
    let b = value.as_bytes();
    if b.len() != 55 || b[2] != b'-' || b[35] != b'-' || b[52] != b'-' {
        return None;
    }
    if &value[0..2] != "00" {
        // Version `ff` is forbidden; any other version would carry a different layout
        // we do not speak. Both are "absent" to us.
        return None;
    }
    let trace = decode_hex_lower(&value[3..35])?;
    let parent = decode_hex_lower(&value[36..52])?;
    decode_hex_lower(&value[53..55])?; // flags must be hex; the sampled bit is not consulted
    if trace.iter().all(|&x| x == 0) || parent.iter().all(|&x| x == 0) {
        return None;
    }
    Some(InboundTraceContext {
        trace_id: tracelane_shared::otlp::decode::otlp_trace_id_to_uuid(&trace).ok()?,
        parent_span_id: tracelane_shared::otlp::decode::otlp_span_id_to_uuid(&parent).ok()?,
    })
}

/// Lowercase hex only — the spec mandates lowercase on the wire, and every OTel exporter
/// emits it. Uppercase is rejected rather than tolerated so a hand-typed header fails the
/// same way it would fail an OTel receiver.
fn decode_hex_lower(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The trace identity for a proxied request: `(trace_id, parent_span_id)`.
///
/// Precedence: `traceparent` → `x-trace-id` (undocumented, kept for existing callers) → a
/// fresh v4. Only `traceparent` yields a parent; the other two never did.
#[must_use]
pub fn resolve_trace_identity(headers: &HeaderMap) -> (Uuid, Option<Uuid>) {
    if let Some(ctx) = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_traceparent)
    {
        return (ctx.trace_id, Some(ctx.parent_span_id));
    }
    let trace_id = headers
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);
    (trace_id, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const TP: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn valid_header_yields_the_otlp_transforms_byte_for_byte() {
        let ctx = parse_traceparent(TP).expect("valid");
        assert_eq!(
            ctx.trace_id,
            Uuid::parse_str("4bf92f35-77b3-4da6-a3ce-929d0e0e4736").unwrap()
        );
        // The parent is zero-padded in the HIGH 8 bytes — identical to what the OTLP ingest
        // path stores for a span id, which is what makes the join match.
        let p = ctx.parent_span_id.as_bytes();
        assert_eq!(&p[..8], &[0u8; 8]);
        assert_eq!(&p[8..], &[0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]);
        assert_eq!(
            ctx.parent_span_id,
            tracelane_shared::otlp::decode::otlp_span_id_to_uuid(&p[8..]).unwrap()
        );
    }

    #[test]
    fn malformed_headers_are_absent_not_errors() {
        let cases = [
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // forbidden version
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01", // zero trace id
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // zero parent
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", // uppercase
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",  // 54 chars
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011", // 56 chars
            "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // bad separator
            "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01", // non-hex
            "",
        ];
        for c in cases {
            assert_eq!(
                parse_traceparent(c),
                None,
                "{c:?} must be treated as absent"
            );
        }
    }

    #[test]
    fn precedence_traceparent_then_x_trace_id_then_fresh() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-trace-id",
            HeaderValue::from_static("11111111-1111-4111-8111-111111111111"),
        );
        h.insert("traceparent", HeaderValue::from_static(TP));
        let (t, p) = resolve_trace_identity(&h);
        assert_eq!(
            t,
            Uuid::parse_str("4bf92f35-77b3-4da6-a3ce-929d0e0e4736").unwrap()
        );
        assert!(p.is_some(), "traceparent yields a parent");

        let mut h = HeaderMap::new();
        h.insert(
            "x-trace-id",
            HeaderValue::from_static("11111111-1111-4111-8111-111111111111"),
        );
        let (t, p) = resolve_trace_identity(&h);
        assert_eq!(
            t,
            Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap()
        );
        assert_eq!(
            p, None,
            "x-trace-id never yielded a parent and still does not"
        );

        let h = HeaderMap::new();
        let (t, p) = resolve_trace_identity(&h);
        assert_eq!(t.get_version_num(), 4);
        assert_eq!(p, None);

        // A malformed traceparent falls through to the next source, fail-open.
        let mut h = HeaderMap::new();
        h.insert(
            "traceparent",
            HeaderValue::from_static("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        h.insert(
            "x-trace-id",
            HeaderValue::from_static("11111111-1111-4111-8111-111111111111"),
        );
        let (t, p) = resolve_trace_identity(&h);
        assert_eq!(
            t,
            Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap()
        );
        assert_eq!(p, None);
    }
}
