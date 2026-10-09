//! `OG-11`: the latency strategy's in-process EWMA of time-to-first-byte per
//! `(tenant, provider, model)`.
//!
//! Process-local and since-start (one gateway per control plane, B-386; spec §6: no
//! cross-process EWMA, nothing persisted) — after a restart every target is cold and the
//! latency strategy orders by priority until `min_samples` arrive. Bounded at
//! `routing.stats_max_entries`: past it a NEW pair is not tracked (it stays cold), an
//! existing one keeps updating.
//!
//! **Per tenant (M1, security review 2026-10-05).** It was keyed `(provider, model)` on
//! the theory that latency is upstream health, not tenant data — but a tenant's latency
//! reveals that tenant's traffic (its volume, its prompt sizes, when it is active), and
//! `POST /v1/routing/simulate` returned it to every other tenant; another tenant's samples
//! also reordered YOUR latency strategy (a steering lever). Each tenant is now ordered by,
//! and shown, only its own observations; a tenant with none is cold (priority order).

use std::time::{Duration, Instant};

use dashmap::DashMap;

type Key = (uuid::Uuid, String, String);

/// One tracked pair: the EWMA, its sample count, and when it was last observed.
#[derive(Clone, Copy)]
struct Stat {
    ewma_ms: f64,
    samples: u32,
    seen: Instant,
}

/// `(tenant, provider_id, model)` → its [`Stat`].
fn table() -> &'static DashMap<Key, Stat> {
    static T: std::sync::OnceLock<DashMap<Key, Stat>> = std::sync::OnceLock::new();
    T.get_or_init(DashMap::new)
}

/// `routing.stats_idle_evict_secs`: an entry not observed for this long is gone (MED
/// round 2) — it no longer holds a slot of the bound, and its stale EWMA no longer orders.
fn idle_ttl() -> Duration {
    Duration::from_secs(super::limits().stats_idle_evict_secs)
}

/// Is `model` on `provider_id` a target of one of this tenant's LATENCY virtual models?
/// Only those are ever ordered by latency, so only those are recorded (MED round 2): the
/// tenant's document bounds its entries (`max_virtual_models` x `max_targets_per_model`).
fn is_latency_target(routing: &super::RoutingState, provider_id: &str, model: &str) -> bool {
    routing.doc().is_some_and(|d| {
        d.virtual_models.values().any(|vm| {
            vm.strategy == super::Strategy::Latency
                && vm
                    .targets
                    .iter()
                    .any(|t| t.model == model && super::provider_of(&t.model) == Some(provider_id))
        })
    })
}

/// Record one observed time-to-first-byte (the dispatch reached a response head) — only
/// for a target of the tenant's own latency virtual models.
pub(crate) fn record(
    tenant: &uuid::Uuid,
    routing: &super::RoutingState,
    provider_id: &str,
    model: &str,
    ttfb: Duration,
) {
    if !is_latency_target(routing, provider_id, model) {
        return;
    }
    let l = super::limits();
    let ms = ttfb.as_secs_f64() * 1_000.0;
    let key = (*tenant, provider_id.to_owned(), model.to_owned());
    let t = table();
    let now = Instant::now();
    let update = |e: &mut Stat| {
        *e = Stat {
            ewma_ms: l.ewma_alpha.mul_add(ms - e.ewma_ms, e.ewma_ms),
            samples: e.samples.saturating_add(1),
            seen: now,
        };
    };
    if let Some(mut e) = t.get_mut(&key) {
        update(&mut e);
        return;
    }
    static INSERT: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    let _insert = INSERT.lock();
    if let Some(mut e) = t.get_mut(&key) {
        update(&mut e);
        return;
    }
    if t.len() >= l.stats_max_entries {
        let ttl = idle_ttl();
        t.retain(|_, e| now.saturating_duration_since(e.seen) < ttl);
        if t.len() >= l.stats_max_entries {
            return;
        }
    }
    t.insert(
        key,
        Stat {
            ewma_ms: ms,
            samples: 1,
            seen: now,
        },
    );
}

/// The smoothed TTFB and its sample count, if `tenant` has ever observed this pair.
/// `None` tenant (no caller to attribute to) → `None`: never another tenant's numbers.
#[must_use]
pub(crate) fn get(
    tenant: Option<&uuid::Uuid>,
    provider_id: &str,
    model: &str,
) -> Option<(f64, u32)> {
    let tenant = tenant?;
    let key = (*tenant, provider_id.to_owned(), model.to_owned());
    let stat = table().get(&key).map(|e| *e)?;
    if Instant::now().saturating_duration_since(stat.seen) >= idle_ttl() {
        table().remove(&key);
        return None;
    }
    Some((stat.ewma_ms, stat.samples))
}

#[cfg(test)]
fn age_for_test(tenant: &uuid::Uuid, provider_id: &str, model: &str, by: Duration) {
    if let Some(mut e) = table().get_mut(&(*tenant, provider_id.to_owned(), model.to_owned()))
        && let Some(seen) = e.seen.checked_sub(by)
    {
        e.seen = seen;
    }
}

#[cfg(test)]
pub(crate) fn reset_for_test(tenant: &uuid::Uuid, provider_id: &str, model: &str) {
    table().remove(&(*tenant, provider_id.to_owned(), model.to_owned()));
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: uuid::Uuid = uuid::Uuid::from_u128(0x0611_0001);

    /// A routing document whose ONE latency virtual model targets `models`.
    fn latency_doc(models: &[&str]) -> super::super::RoutingState {
        let targets: Vec<_> = models
            .iter()
            .map(|m| serde_json::json!({"model": m}))
            .collect();
        super::super::RoutingState::Valid(std::sync::Arc::new(
            serde_json::from_value(serde_json::json!({
                "virtual_models": {"lat": {"strategy": "latency", "targets": targets}}
            }))
            .unwrap(),
        ))
    }

    /// `OG-11` proof 6 (latency half): the strategy converges to the faster target once
    /// both have `min_samples`; with fewer, order is priority.
    #[test]
    fn og11_proof6_latency_converges_to_the_faster_target_after_min_samples() {
        use super::super::*;
        // Routable by prefix, used by no other test (the stats table is
        // process-wide); reset first anyway.
        let (a, b) = ("gpt-og11-latency-a", "claude-og11-latency-b");
        reset_for_test(&OWNER, "openai", a);
        reset_for_test(&OWNER, "anthropic", b);
        let targets = vec![
            Target {
                model: a.into(),
                weight: None,
            },
            Target {
                model: b.into(),
                weight: None,
            },
        ];
        // An RNG that never explores (explore when r % 10_000 < 500).
        let mut no_explore = || 9_999u64;
        let est = Estimate {
            owner: Some(OWNER),
            ..Estimate::default()
        };
        let (cold, _) = order(Strategy::Latency, &targets, est, &mut no_explore);
        assert_eq!(cold, vec![0, 1], "no samples: priority order");
        let doc = latency_doc(&[a, b]);
        for _ in 0..limits().min_samples {
            record(&OWNER, &doc, "openai", a, Duration::from_millis(900));
            record(&OWNER, &doc, "anthropic", b, Duration::from_millis(120));
        }
        let (warm, _) = order(Strategy::Latency, &targets, est, &mut no_explore);
        assert_eq!(warm, vec![1, 0], "converged to the faster target");
        let (ms, n) = get(Some(&OWNER), "anthropic", b).expect("tracked");
        assert!((ms - 120.0).abs() < 1.0 && n >= limits().min_samples);
    }

    /// M1 (security review, 2026-10-05): the EWMA was process-wide per (provider, model)
    /// and `POST /v1/routing/simulate` returned it — a cross-tenant side channel (another
    /// tenant's traffic and latency) and a steering lever (another tenant's samples
    /// reorder YOUR latency strategy). Each tenant now sees and is ordered by only its own.
    #[test]
    fn m1_latency_stats_are_per_tenant_and_simulate_shows_only_the_callers() {
        use super::super::*;
        let (a, b) = (
            uuid::Uuid::from_u128(0x0611_00a1),
            uuid::Uuid::from_u128(0x0611_00b2),
        );
        let (fast, slow) = ("gpt-m1-stats-fast", "claude-m1-stats-slow");
        let doc = latency_doc(&[fast, slow]);
        for _ in 0..limits().min_samples {
            record(&a, &doc, "openai", fast, Duration::from_millis(900));
            record(&a, &doc, "anthropic", slow, Duration::from_millis(80));
        }
        assert!(get(Some(&a), "anthropic", slow).is_some(), "A sees its own");
        assert!(
            get(Some(&b), "anthropic", slow).is_none(),
            "B must not read A's latency observations"
        );
        assert!(get(None, "anthropic", slow).is_none(), "no owner, no stats");
        let state = RoutingState::Valid(std::sync::Arc::new(
            serde_json::from_value(serde_json::json!({
                "virtual_models": {"m1": {"strategy": "latency", "targets": [
                    {"model": fast}, {"model": slow}]}}
            }))
            .unwrap(),
        ));
        let scope = RoutingScope {
            wire: Wire::Chat,
            virtual_models: VirtualSupport::AnyProvider,
            key_pool: PoolSupport::Pool,
            fallthrough: true,
            timeouts: true,
        };
        let for_b = Estimate {
            owner: Some(b),
            ..Estimate::default()
        };
        let mut no_explore = || 9_999u64;
        let p = plan(&scope, "m1", &state, for_b, &mut no_explore)
            .unwrap()
            .unwrap();
        assert_eq!(
            p.candidates[0].model, fast,
            "A's samples must not reorder B's latency routing (B is cold: priority order)"
        );
        let shown = super::super::routes::plan_json("m1", &scope, Some(&p), &[]);
        assert!(
            shown["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["ewma_ttfb_ms"].is_null()),
            "simulate must not show B another tenant's latency: {shown}"
        );
    }

    /// MED round 2 (security re-review, 2026-10-05): the table never evicted and every
    /// successful call of every tenant x model was recorded, so ordinary hosted traffic
    /// filled the 50k bound and froze the latency strategy cold for everyone after. Only
    /// targets of the tenant's own LATENCY virtual models are recorded (bounded by the
    /// routing document), and an entry idle past `stats_idle_evict_secs` is gone.
    #[test]
    fn r2_only_latency_targets_are_recorded_and_idle_entries_evict() {
        let t = uuid::Uuid::from_u128(0x0611_00c3);
        let ms = Duration::from_millis(50);
        let none = super::super::RoutingState::None;
        record(&t, &none, "openai", "gpt-r2-no-doc", ms);
        assert!(
            get(Some(&t), "openai", "gpt-r2-no-doc").is_none(),
            "no routing document: nothing to order, nothing recorded"
        );
        let doc = latency_doc(&["gpt-r2-target"]);
        record(&t, &doc, "openai", "gpt-r2-not-a-target", ms);
        assert!(
            get(Some(&t), "openai", "gpt-r2-not-a-target").is_none(),
            "a model no latency virtual model targets is not recorded"
        );
        record(&t, &doc, "openai", "gpt-r2-target", ms);
        assert!(get(Some(&t), "openai", "gpt-r2-target").is_some());
        age_for_test(
            &t,
            "openai",
            "gpt-r2-target",
            idle_ttl() + Duration::from_secs(1),
        );
        assert!(
            get(Some(&t), "openai", "gpt-r2-target").is_none(),
            "an idle entry is evicted"
        );
    }
}
