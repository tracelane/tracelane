//! Gateway hot-path admission-overhead benchmark (ADR-033 /).
//!
//! Measures the per-request *gateway overhead* that the <25ms-p99 budget and
//! the ADR-033 "no >10% regression" gate care about — the deterministic
//! admission-control work done on every request, *excluding* the upstream
//! provider call (which dominates wall-clock but is not gateway overhead):
//!
//!   - the per-`(provider, region)` circuit-breaker `allow()` check (ADR-036)
//!   - the per-tenant rate-limit check (`RateLimiter::check`, GWY-43/BILL-01)
//!   - the breaker `record()` of the outcome
//!
//! These are the components added/touched by the v2.0 hardening that sit on
//! the hot path. The bench gives a stable ns baseline so a regression here is
//! caught before it erodes the gateway-overhead SLO.
//!
//! **BILL-01 / ADR-076 (2026-09-13):** the per-tenant MONTHLY QUOTA component
//! this bench used to measure (`rate_limiter::QuotaTracker` /
//! `QuotaConfig`, ADR-020) is DELETED outright — "ingest is never blocked by
//! billing state" on any tier, so there is no more hot-path quota check to
//! benchmark. `RateLimiter::check` (a per-tenant token-bucket-style rpm gate,
//! unrelated to billing) replaces it here as the admission-path component
//! that runs a per-tenant `DashMap` probe on every request.
//!
//! Run: `cargo bench -p gateway --bench gateway_throughput`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gateway::circuit_breaker::CircuitBreaker;
use gateway::rate_limiter::RateLimiter;
use tracelane_shared::TenantId;
use uuid::Uuid;

/// Warmed admission state for one tenant + one upstream (steady-state path,
/// not first-insert allocation).
fn warmed() -> (CircuitBreaker, RateLimiter, TenantId) {
    let cb = CircuitBreaker::default();
    let limiter = RateLimiter::new();
    let tid = TenantId::from_jwt_claim(Uuid::new_v4());
    // Warm both maps.
    let _ = cb.allow("openai", "default");
    cb.record("openai", "default", true);
    let _ = limiter.check(&tid, Some(600));
    (cb, limiter, tid)
}

/// The full admission overhead: breaker gate → rate-limit check → record outcome.
/// This is what runs on every request before dispatch.
fn bench_admission_overhead(c: &mut Criterion) {
    let (cb, limiter, tid) = warmed();
    c.bench_function("gateway_admission_overhead", |b| {
        b.iter(|| {
            let allowed = black_box(cb.allow(black_box("openai"), black_box("default")));
            let _ = black_box(limiter.check(black_box(&tid), black_box(Some(600))));
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
    let (cb, _limiter, _tid) = warmed();
    c.bench_function("circuit_breaker_allow", |b| {
        b.iter(|| {
            let _ = black_box(cb.allow(black_box("openai"), black_box("default")));
        });
    });
}

criterion_group!(benches, bench_admission_overhead, bench_breaker_allow);
criterion_main!(benches);
