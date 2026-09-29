//! RI-06 / B-449 — the durable record of a detected gap: one row per episode in
//! `tracelane.capture_gaps` (migration 27). Fleet-level by necessity — a trimmed
//! message's tenant went with its subject — so this table carries no `tenant_id` and is
//! never served by a tenant read route; it is operator evidence, and the input to a
//! chained gap attestation once the operator-chain decision exists (ADR-078 / ADR-077
//! Part III R2).
//!
//! Fail-OPEN: the counter (`degradation::note_n`) has already recorded the loss before
//! this runs; a failed insert is counted on its own kind and never delays an ack.
//!
//! The Rust row mirrors the columns EXACTLY — RowBinary is positional and typed, and a
//! `String` against a `DateTime64` or an `i64` against a `UInt64` desynchronises the
//! block silently (the B-292…B-297 class). The real-ClickHouse test in
//! `scripts/ci/run-clickhouse-integration.sh` is the only control that sees it.

use serde::Serialize;

use crate::gap_tracker::{Gap, GapKind};

/// The stream this ingest consumes; the `source` column's value.
pub const SOURCE_SPANS_STREAM: &str = "jetstream:TRACELANE_SPANS";

#[derive(Debug, Serialize, clickhouse::Row)]
pub struct CaptureGapRow {
    /// `DateTime64(6, 'UTC')` as raw microseconds since the epoch — the same shape
    /// `SpanRow.start_time` uses (`clickhouse_writer.rs:91`, `:253`), which the
    /// integration suite already proves against a real server.
    pub detected_at: i64,
    pub source: String,
    pub kind: String,
    pub first_missing_seq: u64,
    pub last_missing_seq: u64,
    pub lost: u64,
    pub ingest_instance: String,
    pub note: String,
}

impl CaptureGapRow {
    /// Build the row for one detected episode, stamped now.
    #[must_use]
    pub fn from_gap(gap: &Gap, instance: &str, note: String) -> Self {
        Self {
            detected_at: chrono::Utc::now().timestamp_micros(),
            source: SOURCE_SPANS_STREAM.to_string(),
            kind: match gap.kind {
                GapKind::BootTrim => "boot_trim",
                GapKind::Trim => "trim",
            }
            .to_string(),
            first_missing_seq: gap.first_missing,
            last_missing_seq: gap.last_missing,
            lost: gap.count(),
            ingest_instance: instance.to_string(),
            note,
        }
    }
}

/// Insert one row. Errors are the caller's to count; nothing here panics or blocks.
///
/// # Errors
/// The ClickHouse insert failed (connection, grant, or a type mismatch surfacing as
/// `InvalidTagEncoding`/a desync — which is why the integration test exists).
pub async fn record(ch: &clickhouse::Client, row: &CaptureGapRow) -> anyhow::Result<()> {
    let mut insert = ch.insert("capture_gaps")?;
    insert.write(row).await?;
    insert.end().await?;
    Ok(())
}

/// The process's name for the `ingest_instance` column: Docker sets `HOSTNAME` to the
/// container id; absent that, a stable literal rather than a guess.
#[must_use]
pub fn instance_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_mirrors_the_gap_exactly_and_names_its_kind() {
        let gap = Gap {
            first_missing: 4,
            last_missing: 18,
            kind: GapKind::BootTrim,
        };
        let row = CaptureGapRow::from_gap(&gap, "ingest-abc", "ack_floor=3 first_seq=19".into());
        assert_eq!(row.first_missing_seq, 4);
        assert_eq!(row.last_missing_seq, 18);
        assert_eq!(row.lost, 15);
        assert_eq!(row.kind, "boot_trim");
        assert_eq!(row.source, SOURCE_SPANS_STREAM);
        assert_eq!(row.ingest_instance, "ingest-abc");
        assert!(
            row.detected_at > 1_700_000_000_000_000,
            "microseconds, not seconds"
        );
        let trim = CaptureGapRow::from_gap(
            &Gap {
                first_missing: 20,
                last_missing: 20,
                kind: GapKind::Trim,
            },
            "x",
            String::new(),
        );
        assert_eq!((trim.kind.as_str(), trim.lost), ("trim", 1));
    }

    /// Against a REAL ClickHouse carrying `schema.sql`: the Rust row's RowBinary must
    /// match the eight declared columns byte for byte, and read back equal. This is the
    /// only control that sees the B-292…B-297 class (a `String` against a `DateTime64`, an
    /// `i64` against a `UInt64` — every one passes `cargo test` and fails on the server).
    ///
    /// Run: `CLICKHOUSE_TEST_URL=http://127.0.0.1:8123 cargo test -p ingest --bin ingest \
    ///   capture_gaps::tests::row_round_trips_against_a_real_clickhouse -- --ignored`
    #[tokio::test]
    #[ignore = "needs a real ClickHouse with schema.sql applied; set CLICKHOUSE_TEST_URL"]
    async fn row_round_trips_against_a_real_clickhouse() {
        let url = std::env::var("CLICKHOUSE_TEST_URL").expect("CLICKHOUSE_TEST_URL");
        let ch = clickhouse::Client::default()
            .with_url(url)
            .with_database("tracelane");
        let instance = format!("rt-{}", uuid::Uuid::new_v4());
        let gap = Gap {
            first_missing: 4,
            last_missing: 18,
            kind: GapKind::BootTrim,
        };
        let row = CaptureGapRow::from_gap(&gap, &instance, "ack_floor=3 first_seq=19".into());
        record(&ch, &row)
            .await
            .expect("insert must be accepted by the real schema");

        #[derive(Debug, serde::Deserialize, clickhouse::Row, PartialEq)]
        struct Back {
            detected_at: i64,
            source: String,
            kind: String,
            first_missing_seq: u64,
            last_missing_seq: u64,
            lost: u64,
            ingest_instance: String,
            note: String,
        }
        let back: Back = ch
            .query(
                "SELECT detected_at, source, kind, first_missing_seq, last_missing_seq, lost, \
                 ingest_instance, note FROM capture_gaps WHERE ingest_instance = ?",
            )
            .bind(&instance)
            .fetch_one()
            .await
            .expect("read back");
        assert_eq!(
            back.detected_at, row.detected_at,
            "DateTime64(6) micros round-trip"
        );
        assert_eq!(back.source, SOURCE_SPANS_STREAM);
        assert_eq!(back.kind, "boot_trim");
        assert_eq!(
            (back.first_missing_seq, back.last_missing_seq, back.lost),
            (4, 18, 15)
        );
        assert_eq!(back.note, "ack_floor=3 first_seq=19");
    }
}
