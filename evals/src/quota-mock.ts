/**
 * TS mirror of `crates/gateway/src/rate_limiter.rs::QuotaTracker::check`.
 *
 * The Rust hot path is the merge-gate source of truth (criterion bench at
 * `crates/gateway/benches/rate_limiter.rs` enforces <500ns p99). This mock
 * exists so pain-point evals can structurally assert against the decision
 * contract without spawning a full gateway. Kept literally aligned with
 * the Rust logic — any divergence is a bug.
 */

export interface QuotaConfig {
	/** Monthly included quota (e.g. 150_000 for Builder). */
	trace_quota_monthly: number;
	/**
	 * Hard cap multiplier × 10 (so 5.0× is stored as 50). Mirrors the Rust
	 * `hard_cap_tenths: u32` field, which keeps the hot path integer-only.
	 */
	hard_cap_tenths: number;
}

export enum QuotaDecision {
	Allow = "Allow",
	AllowWithOverage = "AllowWithOverage",
	HardCapExceeded = "HardCapExceeded",
}

/** Absolute hard-cap value above which requests must 429. */
export function hardCapAbsolute(cfg: QuotaConfig): number {
	return Math.floor((cfg.trace_quota_monthly * cfg.hard_cap_tenths) / 10);
}

/**
 * Apply the QuotaTracker decision rule given a configuration and the
 * post-increment usage value. Equivalent to `QuotaTracker::check` in Rust.
 */
export function simulateQuotaCheck(
	cfg: QuotaConfig,
	usedAfterIncrement: number,
): QuotaDecision {
	if (cfg.trace_quota_monthly === 0) {
		return QuotaDecision.Allow;
	}
	const limit = hardCapAbsolute(cfg);
	if (usedAfterIncrement > limit) {
		return QuotaDecision.HardCapExceeded;
	}
	if (usedAfterIncrement > cfg.trace_quota_monthly) {
		return QuotaDecision.AllowWithOverage;
	}
	return QuotaDecision.Allow;
}
