//! JetStream stream limits that are ENFORCED on an existing stream, not merely declared.
//!
//! WHY — SRE audit register #50 (2026-09-04), fixed 2026-09-05. Every JetStream stream on
//! tl-node-1 was byte-UNBOUNDED (`max_bytes: -1` on `TRACELANE_SPANS`, `TRACELANE_AUDIT`
//! and `TRACELANE_SPANS_DLQ`, read from `jsz` on the node), on the one un-replicated
//! volume that also holds ClickHouse and the audit ledger. An ingest stall would have
//! filled the disk before anything bounded it, and ENOSPC takes ClickHouse and the ledger
//! down together.
//!
//! THE CLASS THIS MODULE EXISTS FOR — read before "just adding a field to the Config":
//! `Context::get_or_create_stream` binds to an existing stream WITHOUT touching its
//! config. It sends `STREAM.INFO` first and `STREAM.CREATE` only on a 404
//! (`async-nats 0.42`, `src/jetstream/context.rs`). So a limit added to the `Config`
//! literal in source is applied to a FRESH deployment only; every long-lived stream on
//! prod keeps whatever it was created with — `TRACELANE_SPANS` was created 2026-06-07 and
//! has never had its config re-read. `Stream::get_or_create_consumer` has the identical
//! shape, which is what left register #29's `max_ack_pending` inert on the durable
//! consumer that already existed. RCA:
//! `runbooks/RCA-jetstream-get-or-create-never-updates.md`.
//!
//! This helper makes the source literal the truth: create if absent, otherwise compare the
//! LIMIT fields against the live config and `STREAM.UPDATE` on drift. It runs once at boot
//! per stream, so the `info!` lines here are lifecycle, not per-request.

use anyhow::Context as _;
use async_nats::jetstream::consumer::pull;
use async_nats::jetstream::{self, consumer::Consumer, stream::Config, stream::Stream};

/// Create the stream if absent; otherwise reconcile its limit fields to `wanted`.
///
/// # Errors
///
/// Fails CLOSED only when the stream cannot be created or bound at all — the same
/// contract every caller already had. A stream that exists but REFUSES the limits update
/// is fail-OPEN by design: the stream works, and moving the gateway's audit path to
/// synchronous appends (its create-failure fallback) over a capacity bound would cost the
/// hot path more than an unbounded 21 MB stream does. The refusal is logged at `warn!`
/// with the drift named, once, at boot.
pub async fn ensure_stream(js: &jetstream::Context, wanted: Config) -> anyhow::Result<Stream> {
    let stream = js
        .get_or_create_stream(wanted.clone())
        .await
        .with_context(|| format!("get_or_create JetStream stream {}", wanted.name))?;
    let Some(drift) = limits_drift(&stream.cached_info().config, &wanted) else {
        return Ok(stream);
    };
    match js.update_stream(&wanted).await {
        Ok(info) => {
            tracing::info!(
                stream = %wanted.name,
                %drift,
                max_bytes = info.config.max_bytes,
                "JetStream stream limits drifted from source; UPDATED on the server"
            );
        }
        Err(err) => {
            tracing::warn!(
                stream = %wanted.name,
                %drift,
                error = %err,
                "JetStream stream limits drifted from source and the UPDATE was refused — \
                 the stream is running UNBOUNDED relative to source; fix on the node"
            );
        }
    }
    Ok(stream)
}

/// Name every LIMIT field on which the live config differs from the wanted one, or
/// `None` when the bounds already match.
///
/// Only limit fields are compared. `name`, `subjects`, `retention` and `storage` are
/// the stream's IDENTITY — a mismatch there is a different stream, not drift, and the
/// server refuses to update most of them anyway. `duplicate_window` is deliberately
/// excluded: a source literal that leaves it at `Default` (0) is answered by the server
/// with its own 2-minute default, so comparing it would report drift on every boot and
/// issue an update that changes nothing.
#[must_use]
pub fn limits_drift(live: &Config, wanted: &Config) -> Option<String> {
    // `Config::default()` leaves a limit at 0 and the server reports the same limit as -1;
    // both mean UNLIMITED. Compared raw, every boot reports `max_messages -1->0` and issues
    // an update that changes nothing — observed on the first prod boot of this code
    // (2026-09-05 12:08 UTC), which is why the live test now asserts idempotence.
    let unlimited = |v: i64| if v <= 0 { -1 } else { v };
    let mut drift = Vec::new();
    if unlimited(live.max_bytes) != unlimited(wanted.max_bytes) {
        drift.push(format!(
            "max_bytes {}->{}",
            live.max_bytes, wanted.max_bytes
        ));
    }
    if unlimited(live.max_messages) != unlimited(wanted.max_messages) {
        drift.push(format!(
            "max_messages {}->{}",
            live.max_messages, wanted.max_messages
        ));
    }
    if live.max_age != wanted.max_age {
        drift.push(format!("max_age {:?}->{:?}", live.max_age, wanted.max_age));
    }
    if live.discard != wanted.discard {
        drift.push(format!("discard {:?}->{:?}", live.discard, wanted.discard));
    }
    if drift.is_empty() {
        None
    } else {
        Some(drift.join(", "))
    }
}

/// Bind the durable pull consumer, creating it if absent, and reconcile
/// `max_ack_pending` / `ack_wait` / `max_deliver` when the existing one drifted.
///
/// Same class as [`ensure_stream`]: `get_or_create_consumer` returns the EXISTING
/// consumer's config untouched, so a change to the source literal never reaches a
/// durable consumer that already exists on the server.
///
/// # Errors
///
/// Fails CLOSED on create/bind failure (unchanged contract). A refused UPDATE is
/// fail-OPEN with a `warn!`, for the same reason as [`ensure_stream`].
pub async fn ensure_pull_consumer(
    stream: &Stream,
    wanted: pull::Config,
) -> anyhow::Result<Consumer<pull::Config>> {
    let name = wanted
        .durable_name
        .clone()
        .context("ensure_pull_consumer needs a durable_name")?;
    let consumer = stream
        .get_or_create_consumer(&name, wanted.clone())
        .await
        .with_context(|| format!("get_or_create JetStream consumer {name}"))?;
    let live = &consumer.cached_info().config;
    let Some(drift) = consumer_drift(
        live.max_ack_pending,
        live.ack_wait,
        live.max_deliver,
        &wanted,
    ) else {
        return Ok(consumer);
    };
    match stream.update_consumer(wanted).await {
        Ok(updated) => {
            tracing::info!(
                consumer = %name,
                %drift,
                "JetStream consumer config drifted from source; UPDATED on the server"
            );
            Ok(updated)
        }
        Err(err) => {
            tracing::warn!(
                consumer = %name,
                %drift,
                error = %err,
                "JetStream consumer config drifted from source and the UPDATE was refused; \
                 running with the server's existing config"
            );
            Ok(consumer)
        }
    }
}

/// Pure half of [`ensure_pull_consumer`]: names the drifted fields, or `None`.
#[must_use]
pub fn consumer_drift(
    live_max_ack_pending: i64,
    live_ack_wait: std::time::Duration,
    live_max_deliver: i64,
    wanted: &pull::Config,
) -> Option<String> {
    let mut drift = Vec::new();
    if live_max_ack_pending != wanted.max_ack_pending {
        drift.push(format!(
            "max_ack_pending {live_max_ack_pending}->{}",
            wanted.max_ack_pending
        ));
    }
    if live_ack_wait != wanted.ack_wait {
        drift.push(format!("ack_wait {live_ack_wait:?}->{:?}", wanted.ack_wait));
    }
    if live_max_deliver != wanted.max_deliver {
        drift.push(format!(
            "max_deliver {live_max_deliver}->{}",
            wanted.max_deliver
        ));
    }
    if drift.is_empty() {
        None
    } else {
        Some(drift.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_nats::jetstream::stream::DiscardPolicy;
    use std::time::Duration;

    fn wanted() -> Config {
        Config {
            name: "T".into(),
            subjects: vec!["t.>".into()],
            max_bytes: 1 << 30,
            discard: DiscardPolicy::New,
            max_age: Duration::from_secs(3600),
            ..Default::default()
        }
    }

    #[test]
    fn no_drift_when_limits_match() {
        assert_eq!(limits_drift(&wanted(), &wanted()), None);
    }

    #[test]
    fn unbounded_live_stream_is_drift_on_max_bytes_and_discard() {
        // The exact shape found on prod: created before any bound existed in source.
        let live = Config {
            max_bytes: -1,
            discard: DiscardPolicy::Old,
            ..wanted()
        };
        let d = limits_drift(&live, &wanted()).expect("drift");
        assert!(d.contains("max_bytes -1->1073741824"), "{d}");
        assert!(d.contains("discard Old->New"), "{d}");
        assert!(!d.contains("max_age"), "{d}");
    }

    #[test]
    fn unset_limit_and_server_unlimited_are_the_same_thing() {
        // Source leaves max_messages at Default (0); the server reports -1. Not drift —
        // this exact pair produced a spurious UPDATE on every prod boot.
        let live = Config {
            max_messages: -1,
            ..wanted()
        };
        assert_eq!(limits_drift(&live, &wanted()), None);
        // But a REAL bound against unlimited is drift, in both directions.
        let live = Config {
            max_messages: 500,
            ..wanted()
        };
        assert!(
            limits_drift(&live, &wanted())
                .unwrap()
                .contains("max_messages 500->0")
        );
    }

    #[test]
    fn duplicate_window_is_not_drift() {
        // The server answers a Default (0) duplicate_window with its own 2-minute
        // default. Comparing it would report drift on EVERY boot.
        let live = Config {
            duplicate_window: Duration::from_secs(120),
            ..wanted()
        };
        assert_eq!(limits_drift(&live, &wanted()), None);
    }

    #[test]
    fn consumer_drift_names_max_ack_pending_only_when_it_moved() {
        let w = pull::Config {
            durable_name: Some("c".into()),
            ack_wait: Duration::from_secs(30),
            max_deliver: 5,
            max_ack_pending: 4000,
            ..Default::default()
        };
        // Prod's durable consumer: the server default 1000 from before register #29.
        let d = consumer_drift(1000, Duration::from_secs(30), 5, &w).expect("drift");
        assert_eq!(d, "max_ack_pending 1000->4000");
        assert_eq!(consumer_drift(4000, Duration::from_secs(30), 5, &w), None);
    }

    /// LIVE proof of the class, against a real server. Run with a throwaway NATS:
    ///   docker run -d --rm --name nats-test -p 4222:4222 nats:2.10-alpine -js
    ///   NATS_TEST_URL=nats://127.0.0.1:4222 cargo test -p tracelane-shared \
    ///       jetstream_limits -- --ignored --nocapture
    /// The first assertion is the FALSIFICATION arm: it proves `get_or_create_stream`
    /// leaves the live bound untouched, which is the defect this module exists for.
    #[tokio::test]
    #[ignore]
    async fn ensure_stream_updates_a_drifted_live_stream() {
        let Ok(url) = std::env::var("NATS_TEST_URL") else {
            eprintln!("skip: NATS_TEST_URL unset");
            return;
        };
        let client = async_nats::connect(&url).await.expect("connect");
        let js = jetstream::new(client);
        let name = format!("TL_LIMITS_TEST_{}", std::process::id());
        let _ = js.delete_stream(&name).await;
        let unbounded = Config {
            name: name.clone(),
            subjects: vec![format!("{name}.>")],
            ..Default::default()
        };
        js.create_stream(unbounded.clone())
            .await
            .expect("create unbounded");

        let bounded = Config {
            max_bytes: 1 << 20,
            discard: DiscardPolicy::New,
            ..unbounded
        };
        // FALSIFICATION ARM. If this ever fails, get_or_create_stream started applying
        // config and this module is redundant — delete it rather than keep it.
        let via_get_or_create = js
            .get_or_create_stream(bounded.clone())
            .await
            .expect("bind");
        assert_eq!(
            via_get_or_create.cached_info().config.max_bytes,
            -1,
            "get_or_create_stream applied the bound — the defect this module fixes is gone"
        );

        ensure_stream(&js, bounded.clone()).await.expect("ensure");
        let live = js.get_stream(&name).await.expect("re-read");
        assert_eq!(live.cached_info().config.max_bytes, 1 << 20);
        assert_eq!(live.cached_info().config.discard, DiscardPolicy::New);
        // Idempotence: a second look at the SAME source must see no drift, or every
        // boot would issue an update (the -1 vs 0 "unlimited" spelling).
        assert_eq!(limits_drift(&live.cached_info().config, &bounded), None);

        // Consumer half of the class, same server.
        let base = pull::Config {
            durable_name: Some("c".into()),
            max_ack_pending: 1000,
            ..Default::default()
        };
        live.create_consumer(base.clone())
            .await
            .expect("create consumer");
        let moved = pull::Config {
            max_ack_pending: 4000,
            ..base
        };
        let via_get_or_create = live
            .get_or_create_consumer("c", moved.clone())
            .await
            .expect("bind consumer");
        assert_eq!(via_get_or_create.cached_info().config.max_ack_pending, 1000);
        let reconciled = ensure_pull_consumer(&live, moved)
            .await
            .expect("ensure consumer");
        assert_eq!(reconciled.cached_info().config.max_ack_pending, 4000);

        js.delete_stream(&name).await.expect("cleanup");
    }
}
