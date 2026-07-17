//! Hot-path microbench for QuotaTracker (budget: <500ns p99).
//!
//! The hard-cap layer is wrapped around every gateway request, so its
//! per-call cost is multiplied by every RPS of throughput. Budget:
//! a single atomic load + integer compare, i.e. <500ns p99.
//!
//! Run with `cargo bench -p gateway --bench rate_limiter`. The bench prints
//! mean/median/p99 in ns; CI (or the founder locally) compares against the
//! 500ns assertion in the eval suite — see
//! `evals/pain-points/PP-RATELIMIT-OVERAGE.eval.ts` for the merge gate.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gateway::rate_limiter::{QuotaConfig, QuotaTracker};
use tracelane_shared::TenantId;
use uuid::Uuid;

fn tracker_with_one_tenant() -> (QuotaTracker, TenantId, QuotaConfig) {
    let q = QuotaTracker::new();
    let tid = TenantId::from_jwt_claim(Uuid::new_v4());
    // Builder-tier-equivalent config — 150K quota, 5× cap.
    let cfg = QuotaConfig {
        trace_quota_monthly: 150_000,
        hard_cap_tenths: 50,
    };
    // Warm the DashMap entry so the bench measures the steady-state hot
    // path, not first-insert allocation.
    q.check(&tid, cfg);
    (q, tid, cfg)
}

fn bench_quota_check_hot_path(c: &mut Criterion) {
    let (q, tid, cfg) = tracker_with_one_tenant();
    c.bench_function("quota_check_hot_path", |b| {
        b.iter(|| {
            let _ = black_box(q.check(black_box(&tid), black_box(cfg)));
        });
    });
}

fn bench_quota_check_after_overage(c: &mut Criterion) {
    // Drive counter into the overage band, then bench. Branch prediction
    // hits the AllowWithOverage arm — confirms the overage path is no
    // slower than the steady-state Allow path.
    let q = QuotaTracker::new();
    let tid = TenantId::from_jwt_claim(Uuid::new_v4());
    let cfg = QuotaConfig {
        trace_quota_monthly: 10,
        hard_cap_tenths: 50,
    };
    for _ in 0..15 {
        q.check(&tid, cfg);
    }
    c.bench_function("quota_check_overage_band", |b| {
        b.iter(|| {
            let _ = black_box(q.check(black_box(&tid), black_box(cfg)));
        });
    });
}

criterion_group!(
    benches,
    bench_quota_check_hot_path,
    bench_quota_check_after_overage
);
criterion_main!(benches);
