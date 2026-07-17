//!
//! Measures the per-request *gateway overhead* that the <25ms-p99 budget and
//! the ADR-033 "no >10% regression" gate care about — the deterministic
//! admission-control work done on every request, *excluding* the upstream
//! provider call (which dominates wall-clock but is not gateway overhead):
//!
//!   - the per-`(provider, region)` circuit-breaker `allow()` check (ADR-036)
//!   - the per-tenant monthly quota check (ADR-020)
//!   - the breaker `record()` of the outcome
//!
//! These are the components added/touched by the v2.0 hardening that sit on
//! the hot path. The bench gives a stable ns baseline so a regression here is
//! caught before it erodes the gateway-overhead SLO.
//!
//! Run: `cargo bench -p gateway --bench gateway_throughput`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gateway::circuit_breaker::CircuitBreaker;
use gateway::rate_limiter::{QuotaConfig, QuotaTracker};
use tracelane_shared::TenantId;
use uuid::Uuid;

/// Warmed admission state for one tenant + one upstream (steady-state path,
/// not first-insert allocation).
fn warmed() -> (CircuitBreaker, QuotaTracker, TenantId, QuotaConfig) {
    let cb = CircuitBreaker::default();
    let quota = QuotaTracker::new();
    let tid = TenantId::from_jwt_claim(Uuid::new_v4());
    let cfg = QuotaConfig {
        trace_quota_monthly: 150_000,
        hard_cap_tenths: 50,
    };
    // Warm both maps.
    let _ = cb.allow("openai", "default");
    cb.record("openai", "default", true);
    quota.check(&tid, cfg);
    (cb, quota, tid, cfg)
}

/// The full admission overhead: breaker gate → quota check → record outcome.
/// This is what runs on every request before dispatch.
fn bench_admission_overhead(c: &mut Criterion) {
    let (cb, quota, tid, cfg) = warmed();
    c.bench_function("gateway_admission_overhead", |b| {
        b.iter(|| {
            let allowed = black_box(cb.allow(black_box("openai"), black_box("default")));
            let _ = black_box(quota.check(black_box(&tid), black_box(cfg)));
            cb.record(
                black_box("openai"),
                black_box("default"),
                black_box(allowed),
            );
        });
    });
}

/// The breaker gate alone — the v2.0 hot-path addition (ADR-036).
fn bench_breaker_allow(c: &mut Criterion) {
    let (cb, _q, _t, _c) = warmed();
    c.bench_function("circuit_breaker_allow", |b| {
        b.iter(|| {
            let _ = black_box(cb.allow(black_box("openai"), black_box("default")));
        });
    });
}

criterion_group!(benches, bench_admission_overhead, bench_breaker_allow);
criterion_main!(benches);
