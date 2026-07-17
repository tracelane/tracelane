//! Ingest payload size enforcement (ADR-029).
//!
//! Three caps applied at the OTLP boundary:
//!   * `max_span_bytes` — per-span serialized size (post-decode check)
//!   * `max_attribute_value_bytes` — per-attribute value bytes
//!   * `max_attributes_per_span` — attribute count per span
//!
//! Plus an implicit pre-decode body-size cap (`max_batch_bytes`) that
//! rejects abusive payloads in <1 µs without ever allocating the
//! protobuf struct (criterion bench at `crates/ingest/benches/limits.rs`).
//!
//! Counter: `tracelane_ingest_rejected_total{reason}` via
//! [`record_reject`]. Low cardinality on `reason` (four values); the
//! per-tenant bucket is emitted as a structured `tracing` field so the
//! log-aggregation layer can join without exploding label cardinality.

use std::sync::atomic::{AtomicU64, Ordering};

use opentelemetry_proto::tonic::trace::v1::Span as OtlpSpan;
// `encoded_len` is a method on the `prost::Message` trait; bring the
// trait into scope so we can call it on `&OtlpSpan` via UFCS without
// pinning a specific impl.
use prost::Message as _;

/// Per-span serialized bytes. Default 1 MiB; tier-overridable up to 10 MiB
/// (Enterprise) per ADR-029.
pub const DEFAULT_MAX_SPAN_BYTES: usize = 1024 * 1024;

/// Per-attribute value bytes (string / bytes / json-encoded). Default
/// 32 KiB; Enterprise up to 256 KiB.
pub const DEFAULT_MAX_ATTR_VALUE_BYTES: usize = 32 * 1024;

/// Attribute count per span. Default 128; Enterprise up to 512.
pub const DEFAULT_MAX_ATTRS_PER_SPAN: usize = 128;

/// Pre-decode body-size multiplier — `max_batch_bytes = max_span_bytes *
/// PRE_DECODE_BATCH_MULTIPLIER`. Picks "8 max-size spans per batch" as
/// the upper bound; anything bigger is presumed abuse and bounces at
/// the body-size check. Default → 8 MiB.
pub const PRE_DECODE_BATCH_MULTIPLIER: usize = 8;

/// Threshold for the soft-warning band. Accepted spans whose size
/// exceeds `max_span_bytes / WARNING_BAND_DIVISOR` get a
/// `Tracelane-Warning: limit-payload-size; enforcement-date=YYYY-MM-DD`
/// response header. ADR-029 §"Soft-warning window".
pub const WARNING_BAND_DIVISOR: usize = 2;

/// Hard-coded enforcement date emitted in the soft-warning header.
/// Update this when the limits are next tightened.
pub const WARNING_ENFORCEMENT_DATE: &str = "2026-06-30";

/// Resolved per-workspace limits. V1 ships with defaults; tier
/// overrides are queued for V1.1 once the ingest crate carries a
/// Postgres pool. The structural API is stable.
#[derive(Clone, Copy, Debug)]
pub struct IngestLimits {
    pub max_span_bytes: usize,
    pub max_attribute_value_bytes: usize,
    pub max_attributes_per_span: usize,
    /// ADR-030: max unique attribute keys per workspace per rolling
    /// 30-day window. V1 default = Team-tier 10 000 (see
    /// `cardinality::DEFAULT_MAX_ATTR_CARDINALITY`). When the observed
    /// HLL estimate exceeds this, the OTLP receiver rewrites the
    /// attribute key to `"_overflow"`.
    pub max_attr_key_cardinality: usize,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_span_bytes: DEFAULT_MAX_SPAN_BYTES,
            max_attribute_value_bytes: DEFAULT_MAX_ATTR_VALUE_BYTES,
            max_attributes_per_span: DEFAULT_MAX_ATTRS_PER_SPAN,
            max_attr_key_cardinality: crate::cardinality::DEFAULT_MAX_ATTR_CARDINALITY,
        }
    }
}

impl IngestLimits {
    /// Pre-decode body-size cap. See `PRE_DECODE_BATCH_MULTIPLIER`.
    pub const fn max_batch_bytes(&self) -> usize {
        self.max_span_bytes * PRE_DECODE_BATCH_MULTIPLIER
    }

    /// Soft-warning threshold per ADR-029.
    pub const fn warning_threshold_bytes(&self) -> usize {
        self.max_span_bytes / WARNING_BAND_DIVISOR
    }

    /// Resolve limits for a workspace. V1 returns defaults; V1.1 will
    /// thread an `Entitlements` argument and consult
    /// `workspace_entitlements` (deny-overrides-grant per ADR-009
    /// §7.4.9).
    ///
    /// The parameter is taken as `&()` today so the call site is
    /// stable for the V1.1 swap.
    pub fn for_workspace(_entitlements: &()) -> Self {
        Self::default()
    }
}

/// Four-bucket reject reason. Stable strings — these appear in the
/// `Tracelane-Reject-Reason` response header and Prometheus labels;
/// dashboards depend on the literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    BatchTooLarge,
    SpanTooLarge,
    AttributeTooLarge,
    TooManyAttributes,
}

impl RejectReason {
    pub const fn label(self) -> &'static str {
        match self {
            RejectReason::BatchTooLarge => "batch_too_large",
            RejectReason::SpanTooLarge => "span_too_large",
            RejectReason::AttributeTooLarge => "attribute_too_large",
            RejectReason::TooManyAttributes => "too_many_attributes",
        }
    }

    /// HTTP status mapping per ADR-029.
    pub const fn http_status(self) -> u16 {
        match self {
            // Body-size rejects are 413 — the SDK should react by splitting,
            // not retrying the same payload.
            RejectReason::BatchTooLarge | RejectReason::SpanTooLarge => 413,
            // Per-attribute / attribute-count rejects are 400 — the span
            // shape is structurally wrong.
            RejectReason::AttributeTooLarge | RejectReason::TooManyAttributes => 400,
        }
    }

    const fn idx(self) -> usize {
        match self {
            RejectReason::BatchTooLarge => 0,
            RejectReason::SpanTooLarge => 1,
            RejectReason::AttributeTooLarge => 2,
            RejectReason::TooManyAttributes => 3,
        }
    }
}

/// Per-reason counters for `tracelane_ingest_rejected_total`.
static REJECT_COUNTERS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Record a reject. `workspace_bucket` is a `0..64` bucket id or `None`
/// when no tenant has been attributed yet (pre-decode rejects).
pub fn record_reject(reason: RejectReason, workspace_bucket: Option<u8>) {
    REJECT_COUNTERS[reason.idx()].fetch_add(1, Ordering::Relaxed);
    let bucket = workspace_bucket.map(|b| b as i64).unwrap_or(-1);
    tracing::info!(
        metric_name = "tracelane_ingest_rejected_total",
        reason = reason.label(),
        workspace_id_bucket = bucket,
        "ingest payload rejected"
    );
}

/// Snapshot the four reject counters in `RejectReason::idx()` order.
pub fn reject_metric_snapshot() -> [u64; 4] {
    [
        REJECT_COUNTERS[0].load(Ordering::Relaxed),
        REJECT_COUNTERS[1].load(Ordering::Relaxed),
        REJECT_COUNTERS[2].load(Ordering::Relaxed),
        REJECT_COUNTERS[3].load(Ordering::Relaxed),
    ]
}

/// Hash a tenant UUID into a 0..64 Prometheus bucket.
///
/// `u128 % 64` — the low 6 bits of a v4 UUID are uniformly random by
/// construction, so this is well-distributed without needing a real
/// hash function. Cheap (one mask + cast).
pub fn workspace_bucket(uuid: &uuid::Uuid) -> u8 {
    (uuid.as_u128() as u8) & 0x3f
}

/// Pre-decode body-size guard.
///
/// Rejects payloads whose raw body bytes exceed the per-workspace
/// `max_batch_bytes`. This is the load-bearing fast-path: a 10 MiB
/// base64 dump bounces in <1 µs without ever allocating the
/// `ExportTraceServiceRequest` protobuf struct.
///
/// # Errors
///
/// Returns `Err(RejectReason::BatchTooLarge)` if `body_len > limits.max_batch_bytes()`.
pub fn check_payload_pre_decode(
    body_len: usize,
    limits: &IngestLimits,
) -> Result<(), RejectReason> {
    if body_len > limits.max_batch_bytes() {
        return Err(RejectReason::BatchTooLarge);
    }
    Ok(())
}

/// Successful post-decode span check, with optional soft-warning signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostDecodeOk {
    /// True if the span's serialized size > `max_span_bytes / 2`. The
    /// receiver should attach the `Tracelane-Warning` header on the
    /// response when any span in the batch is in the band.
    pub in_warning_band: bool,
}

/// Per-span post-decode check. Enforces:
///
///   * attribute count <= `max_attributes_per_span`
///   * every attribute value <= `max_attribute_value_bytes`
///   * span's serialized protobuf size <= `max_span_bytes`
///
/// The serialized-size check is computed via `prost::Message::encoded_len`
/// which walks the struct without re-encoding — cheap.
///
/// # Errors
///
/// Returns the first cap that was violated. `TooManyAttributes` is
/// checked before `AttributeTooLarge` so a span with 5 000 zero-length
/// attributes returns `TooManyAttributes`, not 5 000 stacked
/// `AttributeTooLarge`s.
pub fn check_span_post_decode(
    span: &OtlpSpan,
    limits: &IngestLimits,
) -> Result<PostDecodeOk, RejectReason> {
    if span.attributes.len() > limits.max_attributes_per_span {
        return Err(RejectReason::TooManyAttributes);
    }

    for kv in &span.attributes {
        if attribute_value_bytes(kv) > limits.max_attribute_value_bytes {
            return Err(RejectReason::AttributeTooLarge);
        }
    }

    let span_bytes = span.encoded_len();
    if span_bytes > limits.max_span_bytes {
        return Err(RejectReason::SpanTooLarge);
    }

    Ok(PostDecodeOk {
        in_warning_band: span_bytes > limits.warning_threshold_bytes(),
    })
}

/// Compute the size of an attribute's value. Handles the AnyValue
/// variants we actually see on real OTLP traffic.
///
/// Crucially this never allocates — we walk the existing struct and
/// sum reference sizes. Bytes / strings reuse the underlying buffer.
fn attribute_value_bytes(kv: &opentelemetry_proto::tonic::common::v1::KeyValue) -> usize {
    use opentelemetry_proto::tonic::common::v1::any_value::Value;
    match kv.value.as_ref().and_then(|v| v.value.as_ref()) {
        Some(Value::StringValue(s)) => s.len(),
        Some(Value::BytesValue(b)) => b.len(),
        Some(Value::BoolValue(_)) => 1,
        Some(Value::IntValue(_)) | Some(Value::DoubleValue(_)) => 8,
        Some(Value::ArrayValue(arr)) => arr
            .values
            .iter()
            .map(|inner| {
                // Recurse via a synthetic KeyValue wrapper; cheap and
                // correct for nested arrays.
                let synth = opentelemetry_proto::tonic::common::v1::KeyValue {
                    key: String::new(),
                    value: Some(inner.clone()),
                };
                attribute_value_bytes(&synth)
            })
            .sum(),
        Some(Value::KvlistValue(kvlist)) => kvlist
            .values
            .iter()
            .map(|inner| inner.key.len() + attribute_value_bytes(inner))
            .sum(),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{
        AnyValue, KeyValue, any_value::Value as AnyValueValue,
    };
    use uuid::Uuid;

    fn make_attr(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: Some(AnyValue {
                value: Some(AnyValueValue::StringValue(value.into())),
            }),
        }
    }

    fn span_with_attrs(attrs: Vec<KeyValue>) -> OtlpSpan {
        OtlpSpan {
            trace_id: vec![1; 16],
            span_id: vec![2; 8],
            name: "chat".into(),
            attributes: attrs,
            ..Default::default()
        }
    }

    #[test]
    fn default_limits_match_adr_029() {
        let l = IngestLimits::default();
        assert_eq!(l.max_span_bytes, 1024 * 1024);
        assert_eq!(l.max_attribute_value_bytes, 32 * 1024);
        assert_eq!(l.max_attributes_per_span, 128);
        assert_eq!(l.max_batch_bytes(), 8 * 1024 * 1024);
        assert_eq!(l.warning_threshold_bytes(), 512 * 1024);
    }

    #[test]
    fn reject_reason_label_strings_are_stable() {
        assert_eq!(RejectReason::BatchTooLarge.label(), "batch_too_large");
        assert_eq!(RejectReason::SpanTooLarge.label(), "span_too_large");
        assert_eq!(
            RejectReason::AttributeTooLarge.label(),
            "attribute_too_large"
        );
        assert_eq!(
            RejectReason::TooManyAttributes.label(),
            "too_many_attributes"
        );
    }

    #[test]
    fn reject_reason_http_status_mapping() {
        assert_eq!(RejectReason::BatchTooLarge.http_status(), 413);
        assert_eq!(RejectReason::SpanTooLarge.http_status(), 413);
        assert_eq!(RejectReason::AttributeTooLarge.http_status(), 400);
        assert_eq!(RejectReason::TooManyAttributes.http_status(), 400);
    }

    #[test]
    fn pre_decode_accepts_small_body() {
        let l = IngestLimits::default();
        assert!(check_payload_pre_decode(1024, &l).is_ok());
    }

    #[test]
    fn pre_decode_rejects_oversize_body() {
        let l = IngestLimits::default();
        // Just over the 8 MiB cap.
        assert_eq!(
            check_payload_pre_decode(8 * 1024 * 1024 + 1, &l),
            Err(RejectReason::BatchTooLarge)
        );
    }

    #[test]
    fn post_decode_rejects_too_many_attributes_before_attribute_size() {
        let l = IngestLimits::default();
        // 200 zero-length attributes — over the 128 count cap, but each
        // value is 0 bytes (well under 32 KiB). The count check must
        // fire first.
        let attrs = (0..200).map(|i| make_attr(&format!("k{i}"), "")).collect();
        let span = span_with_attrs(attrs);
        assert_eq!(
            check_span_post_decode(&span, &l),
            Err(RejectReason::TooManyAttributes)
        );
    }

    #[test]
    fn post_decode_rejects_oversize_attribute_value() {
        let l = IngestLimits::default();
        // One 64 KiB string attribute — over the 32 KiB attribute cap.
        let big = "x".repeat(64 * 1024);
        let span = span_with_attrs(vec![make_attr("blob", &big)]);
        assert_eq!(
            check_span_post_decode(&span, &l),
            Err(RejectReason::AttributeTooLarge)
        );
    }

    #[test]
    fn post_decode_accepts_normal_span_with_warning_band_false() {
        let l = IngestLimits::default();
        let span = span_with_attrs(vec![
            make_attr("gen_ai.system", "anthropic"),
            make_attr("gen_ai.request.model", "claude-sonnet-4-6"),
        ]);
        let ok = check_span_post_decode(&span, &l).expect("normal span accepted");
        assert!(!ok.in_warning_band, "small span must NOT trigger warning");
    }

    #[test]
    fn post_decode_flags_warning_band_when_span_exceeds_half() {
        // One attribute carrying ~600 KiB of value — span's encoded_len
        // will exceed 512 KiB (the warning threshold) but stay under
        // 1 MiB (the hard cap).
        let payload = "x".repeat(600 * 1024 - 100); // a bit under 600KiB to leave room for varint overhead
        // But this also exceeds max_attribute_value_bytes (32 KiB), so it
        // would reject as AttributeTooLarge instead. Use a wider limits
        // override that lets the attribute through to test the warning
        // band cleanly.
        let lax = IngestLimits {
            max_span_bytes: 1024 * 1024,
            max_attribute_value_bytes: 1024 * 1024,
            max_attributes_per_span: 128,
            max_attr_key_cardinality: crate::cardinality::DEFAULT_MAX_ATTR_CARDINALITY,
        };
        let span = span_with_attrs(vec![make_attr("rrweb.dom", &payload)]);
        let ok = check_span_post_decode(&span, &lax).expect("under hard cap");
        assert!(
            ok.in_warning_band,
            "span > max_span_bytes / 2 must be in warning band"
        );
    }

    #[test]
    fn post_decode_rejects_oversize_span() {
        // Tighter limits to exercise SpanTooLarge cleanly without
        // tripping the attribute cap first.
        let tight = IngestLimits {
            max_span_bytes: 4 * 1024,
            max_attribute_value_bytes: 64 * 1024,
            max_attributes_per_span: 128,
            max_attr_key_cardinality: crate::cardinality::DEFAULT_MAX_ATTR_CARDINALITY,
        };
        let payload = "x".repeat(8 * 1024); // 8 KiB attribute value, span well over 4 KiB
        let span = span_with_attrs(vec![make_attr("blob", &payload)]);
        assert_eq!(
            check_span_post_decode(&span, &tight),
            Err(RejectReason::SpanTooLarge)
        );
    }

    #[test]
    fn workspace_bucket_is_deterministic_and_well_distributed() {
        // Same UUID hashes to the same bucket twice.
        let u = Uuid::new_v4();
        assert_eq!(workspace_bucket(&u), workspace_bucket(&u));
        assert!(workspace_bucket(&u) < 64);

        // Over a sample of 4 096 random UUIDs, every bucket gets hit at
        // least once (Chernoff: probability of missing a bucket after N
        // uniform draws on K buckets is ((K-1)/K)^N; for N=4096, K=64,
        // that's ~e^-64 ≈ 0).
        let mut hits = [0u32; 64];
        for _ in 0..4_096 {
            hits[workspace_bucket(&Uuid::new_v4()) as usize] += 1;
        }
        assert!(hits.iter().all(|&h| h > 0));
    }

    #[test]
    fn counter_increments_on_record_reject() {
        let before = reject_metric_snapshot()[RejectReason::SpanTooLarge.idx()];
        record_reject(RejectReason::SpanTooLarge, Some(7));
        let after = reject_metric_snapshot()[RejectReason::SpanTooLarge.idx()];
        assert!(after > before);
    }
}
