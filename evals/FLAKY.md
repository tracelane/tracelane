# Flaky Eval Tracker

> Tracked by `incident-responder` subagent. Updated whenever an eval fails intermittently on main.
> An eval is "flaky" if it passes and fails on the same commit without code changes.
> Flaky evals MUST be fixed or quarantined within 5 business days of first report.

---

## Active flaky evals

| Test | Description | Diagnosis | First seen | Status |
|------|-------------|-----------|-----------|--------|
| _(none)_ | | | | |

---

## Quarantine protocol

When an eval is confirmed flaky (≥2 intermittent failures on same commit):

1. Add it to this table with diagnosis and quarantine date
2. Add `.skip` to the eval `it()` block and annotate: `// FLAKY: quarantined YYYY-MM-DD`
3. Create a Linear issue tagged `flaky-eval` with reproduction steps
4. Do not remove the eval — fix the underlying race or timing issue

## Resolution protocol

1. Fix the root cause (race condition, timing dependency, mock order, etc.)
2. Run the eval 20× in a row locally to confirm stability
3. Remove the `.skip` annotation
4. Remove from this table
5. Close the Linear issue

---

## Resolved (closed)

| Eval ID | Description | Root Cause | Resolved |
|---------|-------------|------------|---------|
| `crates/gateway/tests/failover_chaos.rs::wiremock_500_then_200_succeeds_within_200ms` | FT-01 retry-budget timing test; load-sensitive false red (~1.9s observed under full-suite contention; 0.22s idle). Surfaced again 2026-06-01 turning a full `cargo test -p gateway` run red. | **wiremock cold-start inside the timed region.** The first POST paid TCP connect + worker spin-up, which CPU contention inflated to ~1.9s. | 2026-06-01 — warm the connection with a throwaway GET BEFORE starting the timer (excludes cold-start; the GET hits no POST mock so it doesn't consume the `up_to_n_times(1)` budget), then tightened the budget to 500ms. Catches a hung/looping retry while immune to cold-start. |
| `crates/gateway/tests/failover_chaos.rs::wiremock_persistent_500_exhausts_retry` | FT-01 retry-exhaustion test failed intermittently with `SSRF: IP 127.0.0.1 is in a blocked range` (failed under full-workspace load + 1 of 3 isolated binary runs; passed run as sole test). Audit finding P0-4. | **Env-var cross-test race.** The per-test `LoopbackBypassGuard` did `set_var` on `install()` and `remove_var` on `Drop`. `#[tokio::test]`s in a file run on multiple threads, so one test's Drop unset `TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS` while a sibling was mid-`validate_url`, and the SSRF guard then (correctly) rejected loopback. Violated `.claude/rules/testing.md` (never set/remove a process-global env var from parallel tests). | 2026-05-29 — replaced the set/remove guard with a `OnceLock` one-time set (never removed); the binary is process-isolated and every test in it needs loopback, so the single write happens-before all reads. No quarantine needed — fixed at root. |
