//! Hot-path microbench for `RateLimiter` (budget: <500ns p99).
//!
//! The rate-limit layer is wrapped around every gateway request, so its
//! per-call cost is multiplied by every RPS of throughput. Budget:
//! a single `DashMap` probe + token-bucket arithmetic, i.e. <500ns p99.
//!
//! **BILL-01 / ADR-076 (2026-09-13):** this bench used to measure
//! `rate_limiter::QuotaTracker` / `QuotaConfig` — the per-tenant MONTHLY
//! TRACE-COUNT hard cap (ADR-020), with an "overage band" once a tenant
//! exceeded `quota × hard_cap_tenths`. That whole concept is DELETED: ADR-076
//! §0.4 states "ingest is never blocked by billing state" on any tier, so
//! there is no more overage band to benchmark. `RateLimiter::check` — a
//! per-tenant requests-per-minute token bucket, unrelated to billing — is
//! the hot-path component that replaced it here; `bench_rate_limit_throttled`
//! replaces `bench_quota_check_after_overage`, comparing the ALLOW branch
//! against the THROTTLE branch instead of steady-state against overage.
//!
//! Run with `cargo bench -p gateway --bench rate_limiter`. The bench prints
//! mean/median/p99 in ns; CI (or the founder locally) compares against the
//! 500ns assertion in the eval suite — see
//! the rate-limit conformance eval for the merge gate.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gateway::rate_limiter::RateLimiter;
use tracelane_shared::TenantId;
use uuid::Uuid;

fn limiter_with_one_tenant() -> (RateLimiter, TenantId) {
    let limiter = RateLimiter::new();
    let tid = TenantId::from_jwt_claim(Uuid::new_v4());
    // Warm the DashMap entry so the bench measures the steady-state hot
    // path, not first-insert allocation.
    let _ = limiter.check(&tid, Some(600));
    (limiter, tid)
}

fn bench_rate_limit_hot_path(c: &mut Criterion) {
    let (limiter, tid) = limiter_with_one_tenant();
    c.bench_function("rate_limit_check_hot_path", |b| {
        b.iter(|| {
            let _ = black_box(limiter.check(black_box(&tid), black_box(Some(600))));
        });
    });
}

fn bench_rate_limit_throttled(c: &mut Criterion) {
    // Drain the bucket, then bench. Confirms the THROTTLE arm (which also
    // computes `retry_after_secs`) is no slower than the steady-state ALLOW
    // path.
    let limiter = RateLimiter::new();
    let tid = TenantId::from_jwt_claim(Uuid::new_v4());
    for _ in 0..5 {
        let _ = limiter.check(&tid, Some(1));
    }
    c.bench_function("rate_limit_check_throttled", |b| {
        b.iter(|| {
            let _ = black_box(limiter.check(black_box(&tid), black_box(Some(1))));
        });
    });
}

criterion_group!(
    benches,
    bench_rate_limit_hot_path,
    bench_rate_limit_throttled
);
criterion_main!(benches);
