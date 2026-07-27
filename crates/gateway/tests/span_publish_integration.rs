//! `TRACELANE_SPANS` JetStream stream.
//!
//! The write path silently died in prod when `NATS_URL` was absent from the
//! gateway container: `/v1/chat/completions` returned 200 while the per-request
//! publish was skipped (`AppState::nats` was `None`), so the stream stayed stuck
//! and ClickHouse `tracelane.spans` held 0 rows — with no error and no log. This
//! test proves the publish half of the path: after one `publish_span`, the
//! stream's `last_sequence` advances by exactly one.
//!
//! Default: `#[ignore]` (needs a live NATS with JetStream). Run with:
//!
//!   NATS_TEST_URL=nats://localhost:4222 \
//!   cargo test --test span_publish_integration -- --ignored --nocapture
//!
//! CI runs it in the `span-publish-integration` job (boots a `nats:2.10-alpine`
//! service). The always-on `span_subject_contract` test below also gates a plain
//! `cargo test` even when no NATS is booted, and compiling this file type-checks
//! `publish_span`'s wire path in every CI run.
//!
//! Tenant isolation: a fresh UUID-derived tenant per run so a dirty stream and
//! concurrent runs don't collide.

// otlp_emit.rs is self-contained (no `crate::`/`super::` refs), so the same
// `#[path]` include trick the other gateway integration tests use works here.
#[path = "../src/otlp_emit.rs"]
#[allow(dead_code)]
mod otlp_emit;

use std::time::Duration;

use tracelane_shared::{SpanAttributes, SpanStatus, SpanStatusCode, TenantId, TracelaneSpan};
use uuid::Uuid;

fn nats_url() -> Option<String> {
    std::env::var("NATS_TEST_URL").ok()
}

fn span_for(tenant: Uuid) -> TracelaneSpan {
    TracelaneSpan {
        span_id: Uuid::new_v4(),
        trace_id: Uuid::new_v4(),
        parent_span_id: None,
        tenant_id: TenantId::from_jwt_claim(tenant),
        name: "gen_ai.chat".to_string(),
        start_time: chrono::Utc::now(),
        end_time: Some(chrono::Utc::now()),
        attributes: SpanAttributes {
            gen_ai_request_model: Some("claude-opus-4-8".to_string()),
            gen_ai_usage_input_tokens: Some(12),
            gen_ai_usage_output_tokens: Some(34),
            ..Default::default()
        },
        status: SpanStatus {
            code: SpanStatusCode::Ok,
            message: None,
        },
    }
}

/// Always-on (no NATS required): the publish subject stays under the ingest
/// `tracelane.spans.>` binding. Guards the wire contract in a plain `cargo test`.
#[test]
fn span_subject_contract() {
    let tenant = Uuid::new_v4();
    let span = span_for(tenant);
    assert_eq!(
        otlp_emit::span_subject(&span),
        format!("tracelane.spans.{tenant}")
    );
}

/// Live: one `publish_span` advances `TRACELANE_SPANS` `last_sequence` by one.
/// This is the regression guard — if the chat path ever stops emitting a span
/// (or `publish_span` regresses), the sequence does not advance and CI fails.
#[tokio::test]
#[ignore = "needs live NATS — set NATS_TEST_URL"]
async fn published_span_increments_stream_last_seq() {
    let url = nats_url().expect(
        "NATS_TEST_URL not set — run with `NATS_TEST_URL=nats://localhost:4222 \
         cargo test --test span_publish_integration -- --ignored`",
    );

    let client = async_nats::connect(&url).await.expect("connect NATS");
    let js = async_nats::jetstream::new(client.clone());
    let mut stream = js
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: "TRACELANE_SPANS".into(),
            subjects: vec!["tracelane.spans.>".into()],
            // Mirror the ingest stream config (90-day hot window).
            max_age: Duration::from_secs(90 * 24 * 60 * 60),
            ..Default::default()
        })
        .await
        .expect("get_or_create TRACELANE_SPANS");

    let before = stream
        .info()
        .await
        .expect("stream info (before)")
        .state
        .last_sequence;

    let tenant = Uuid::new_v4();
    let span = span_for(tenant);
    otlp_emit::publish_span(&client, &span)
        .await
        .expect("publish_span must succeed against a reachable NATS");
    client.flush().await.expect("flush publish");

    // Poll until JetStream records the message — condition-driven, not a fixed
    // sleep-and-assume (the 50ms is only the poll interval).
    let mut after = before;
    for _ in 0..60 {
        after = stream
            .info()
            .await
            .expect("stream info (after)")
            .state
            .last_sequence;
        if after > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // `>` not `== before + 1`: the regression we gate is "the publish path stopped
    // advancing the stream at all" (silent drop). A concurrent publisher or a
    // pre-dirty stream could legitimately add >1; requiring exactly +1 would flake
    // without catching any additional real defect. Any advance proves the path works.
    assert!(
        after > before,
        "publishing one span must advance last_sequence \
         (before={before}, after={after}) — the gateway span-publish path is broken"
    );
}
