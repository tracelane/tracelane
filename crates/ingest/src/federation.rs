//! failure-signature substrate for opt-in federated detection across tenants,
//! accumulating from the first customer.
//!
//! Called from the ClickHouse batch writer AFTER a durable span flush: for every
//! flushed span whose redacted attributes carry a `tracelane_aft_id`, emit one
//! anonymized `federation_signals` row and batch-insert them.
//!
//! ## Privacy (this is the whole point — reviewed under `.claude/rules/security.md`)
//! - `tenant_id_hash = SHA256(tenant_id)` is ONE-WAY. The raw `tenant_id` is
//!   never written; reverse lookup is architecturally impossible.
//! - Rows carry NO content: `aft_class` is a bounded AFT taxonomy id, and
//!   `anonymized_hash` is a SHA256 of the already-PII-redacted span *name* shape,
//!   never the payload.
//! - There is NO cross-tenant read surface here (V1 = substrate only). The V2
//!   surface may expose ONLY a k-anonymized aggregate (ADR-056).
//!
//! ## Fail-open (span durability comes first)
//! A federation-write error is logged and swallowed — it NEVER fails or delays
//! the span write or its JetStream acks. Spans are the product; this substrate is
//! best-effort telemetry.

use std::time::Duration;

use clickhouse::Client;
use ring::digest;
use serde::Serialize;
use serde_json::Value;
use tokio::time::timeout;

/// One anonymized federation-signal row. Field order MUST match
/// `federation_signals` in `infra/dev/clickhouse/schema.sql` (migration 08).
/// `bucket_hour` is a `DateTime` column carried as raw unix seconds (`u32`), the
/// same RowBinary-wire convention `SpanRow` uses for its timestamps.
#[derive(Debug, Clone, PartialEq, Serialize, clickhouse::Row)]
pub(crate) struct FederationRow {
    tenant_id_hash: String,
    bucket_hour: u32,
    aft_class: String,
    signal_count: u32,
    /// SUM of per-span anomaly scores (the engine sums it alongside
    /// `signal_count`); V2 reads the mean as `confidence_sum / signal_count`.
    confidence_sum: f32,
    anonymized_hash: String,
}

/// Lowercase-hex SHA256 of `input`. One-way; used for the tenant pseudonym and
/// the content-free span-name shape hash.
fn sha256_hex(input: &str) -> String {
    hex::encode(digest::digest(&digest::SHA256, input.as_bytes()).as_ref())
}

/// Truncate a micros-since-epoch timestamp to the start of its UTC hour, as unix
/// seconds. Matches ClickHouse `toStartOfHour` semantics for the `bucket_hour`
/// column. Negative/absurd timestamps clamp to 0 (never panics).
fn hour_bucket_secs(start_time_micros: i64) -> u32 {
    let secs = start_time_micros.max(0) / 1_000_000;
    let hour = (secs / 3600) * 3600;
    u32::try_from(hour).unwrap_or(u32::MAX)
}

/// Is `s` a well-formed AFT failure-signature id? The predictive layer only ever
/// emits `&'static` `AFT-…` constants (e.g. `AFT-TOOL-DRIFT-001`,
/// `AFT-MCP-RUGPULL-001`), so a valid id is: `AFT-` prefixed, 5..=64 chars, ASCII
/// uppercase / digit / `-` only. This bounds the cross-tenant `aft_class` to the
/// taxonomy SHAPE (ADR-056 H1) so attacker-supplied free text — PII, storage
/// bombs, lowercase sentences — is rejected, WITHOUT a brittle enumerated
/// allowlist that could silently drop a newly-added class (a green-while-broken
/// trap). Also enforced at the ingest boundary (`otlp_decode.rs`) for defence in
/// depth so a poisoned value never enters `SpanAttributes` at all.
pub(crate) fn is_valid_aft_id(s: &str) -> bool {
    (5..=64).contains(&s.len())
        && s.starts_with("AFT-")
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

/// Build a federation row from one span's fields (read by the caller from the
/// `SpanRow` batch it already holds — no extra query). Returns `None` when the
/// span carries no `tracelane_aft_id` (the common case → zero federation cost),
/// or when the attributes JSON is unparseable.
///
/// `attributes` is the span's ALREADY-PII-REDACTED attribute JSON, so nothing
/// sensitive can reach the substrate through it.
pub(crate) fn row_from(
    tenant_id: &str,
    attributes: &str,
    start_time_micros: i64,
    span_name: &str,
) -> Option<FederationRow> {
    let attrs: Value = serde_json::from_str(attributes).ok()?;
    let aft_class = attrs.get("tracelane_aft_id")?.as_str()?.trim().to_owned();
    // Bounded-taxonomy enforcement (ADR-056 H1): only a well-formed AFT id may
    // enter the cross-tenant table. An attacker-supplied free-text value (PII /
    // storage-bomb classes) is not a real signal — drop it.
    if !is_valid_aft_id(&aft_class) {
        return None;
    }
    // Best-effort per-span confidence, SUMmed by the engine (V2 reads the mean as
    // confidence_sum / signal_count). Absent → 0.0 (never fabricated).
    #[allow(clippy::cast_possible_truncation)]
    let confidence_sum = attrs
        .get("tracelane_predictive_anomaly_score")
        .and_then(Value::as_f64)
        .unwrap_or(0.0) as f32;

    Some(FederationRow {
        tenant_id_hash: sha256_hex(tenant_id),
        bucket_hour: hour_bucket_secs(start_time_micros),
        aft_class,
        signal_count: 1,
        confidence_sum,
        anonymized_hash: sha256_hex(span_name),
    })
}

/// Insert the federation rows. **Fail-open:** any error is logged and swallowed
/// so span durability + acks are never affected (ADR-056). A no-op on empty.
pub(crate) async fn write_signals(client: &Client, rows: &[FederationRow]) {
    if rows.is_empty() {
        return;
    }
    // Bounded (ADR-056 L1): a degraded federation table must not stall the writer
    // loop between batches. Spans are already durably flushed + acked by now.
    match timeout(Duration::from_secs(3), insert_rows(client, rows)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(
            error = %err,
            signals = rows.len(),
            "federation_signals write failed — best-effort substrate, span durability unaffected (ADR-056)"
        ),
        Err(_elapsed) => tracing::warn!(
            signals = rows.len(),
            "federation_signals write timed out (3s) — best-effort substrate, this batch dropped (ADR-056)"
        ),
    }
}

async fn insert_rows(client: &Client, rows: &[FederationRow]) -> clickhouse::error::Result<()> {
    let mut insert = client.insert("tracelane.federation_signals")?;
    for row in rows {
        insert.write(row).await?;
    }
    insert.end().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attrs(v: serde_json::Value) -> String {
        v.to_string()
    }

    #[test]
    fn span_without_aft_id_yields_no_signal() {
        // The common case: an ordinary span contributes nothing (zero cost).
        assert!(
            row_from(
                "tenant-a",
                &attrs(json!({ "gen_ai_request_model": "claude-sonnet-4-6" })),
                1_700_000_000_000_000,
                "gen_ai.chat",
            )
            .is_none()
        );
        // Empty / whitespace aft id is also nothing.
        assert!(
            row_from(
                "tenant-a",
                &attrs(json!({ "tracelane_aft_id": "  " })),
                1_700_000_000_000_000,
                "gen_ai.chat",
            )
            .is_none()
        );
        // Unparseable attributes never panic — just no signal.
        assert!(row_from("tenant-a", "not json", 1, "n").is_none());
    }

    #[test]
    fn span_with_aft_id_extracts_anonymized_signal() {
        let r = row_from(
            "tenant-a",
            &attrs(json!({
                "tracelane_aft_id": "AFT-TOOL-DRIFT-001",
                "tracelane_predictive_anomaly_score": 0.87,
            })),
            1_700_000_003_600_000_000, // some micros
            "gen_ai.chat",
        )
        .expect("aft id present → a signal");

        assert_eq!(r.aft_class, "AFT-TOOL-DRIFT-001");
        assert_eq!(r.signal_count, 1);
        assert!((r.confidence_sum - 0.87).abs() < 1e-6);
        // tenant_id_hash is the SHA256 hex of the tenant — NEVER the raw id.
        assert_eq!(r.tenant_id_hash, sha256_hex("tenant-a"));
        assert_ne!(r.tenant_id_hash, "tenant-a");
        assert_eq!(r.tenant_id_hash.len(), 64);
        // anonymized_hash is a content-free hash of the span-name shape.
        assert_eq!(r.anonymized_hash, sha256_hex("gen_ai.chat"));
    }

    #[test]
    fn the_row_never_carries_raw_tenant_or_content() {
        // Guard the privacy contract structurally: serialize the row and assert
        // neither the raw tenant id nor any payload-ish string is present.
        let r = row_from(
            "acme-corp-tenant-42",
            &attrs(json!({
                "tracelane_aft_id": "AFT-TAINT-LETHAL-001",
                // A content-ish attribute that must NOT flow into the signal.
                "gen_ai_prompt": "my password is hunter2",
            })),
            1_700_000_000_000_000,
            "gen_ai.chat",
        )
        .unwrap();
        let serialized = format!("{r:?}");
        assert!(!serialized.contains("acme-corp-tenant-42"));
        assert!(!serialized.contains("hunter2"));
        assert!(!serialized.contains("password"));
    }

    #[test]
    fn missing_confidence_defaults_to_zero() {
        let r = row_from(
            "t",
            &attrs(json!({ "tracelane_aft_id": "AFT-PI-CASCADE-001" })),
            1_700_000_000_000_000,
            "n",
        )
        .unwrap();
        assert_eq!(r.confidence_sum, 0.0);
    }

    #[test]
    fn rejects_non_aft_free_text_aft_class() {
        // H1 (ADR-056): only well-formed AFT ids enter the cross-tenant table.
        // Attacker free text / PII / lowercase / oversized values → no signal.
        for bad in [
            "tool-definition-drift", // lowercase kebab (a signature id, not an AFT id)
            "ignore previous instructions", // free-text sentence
            "my ssn is 123-45-6789", // PII-shaped
            "aft-tool-drift-001",    // lowercase
            "NOT-AFT-PREFIXED",      // wrong prefix
            "AFT",                   // too short
            "",                      // empty
        ] {
            assert!(
                row_from(
                    "t",
                    &attrs(json!({ "tracelane_aft_id": bad })),
                    1_700_000_000_000_000,
                    "n"
                )
                .is_none(),
                "expected no signal for aft_class={bad:?}",
            );
        }
        // A 128-char AFT-shaped value is over the 64 cap → rejected (storage bomb).
        let oversized = format!("AFT-{}", "A".repeat(120));
        assert!(
            row_from(
                "t",
                &attrs(json!({ "tracelane_aft_id": oversized })),
                1_700_000_000_000_000,
                "n"
            )
            .is_none(),
        );
        // The canonical AFT ids the predictive layer actually emits are accepted.
        for good in [
            "AFT-TOOL-DRIFT-001",
            "AFT-MCP-RUGPULL-001",
            "AFT-TRAJ-ANOMALY-001",
            "AFT-PI-CASCADE-001",
            "AFT-A2UI-STUCKLOOP-001",
        ] {
            assert!(
                row_from(
                    "t",
                    &attrs(json!({ "tracelane_aft_id": good })),
                    1_700_000_000_000_000,
                    "n"
                )
                .is_some(),
                "expected a signal for aft_class={good:?}",
            );
        }
    }

    #[test]
    fn hour_bucket_truncates_to_the_hour() {
        // 01:59:59.999999 (micros) truncates to 01:00:00.
        let one_hour = 3600i64;
        let micros = (one_hour + 3599) * 1_000_000 + 999_999;
        assert_eq!(hour_bucket_secs(micros), u32::try_from(one_hour).unwrap());
        // Negative clamps to 0, never panics.
        assert_eq!(hour_bucket_secs(-5), 0);
    }
}
