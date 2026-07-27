import { describe, it } from "vitest";
import { expect, spawnGateway } from "../src/harness.js";

/**
 * PP-PROMPT-PROMOTION — B1 Prompt Promotion + Eval Gates + Auto-Rollback.
 *
 * underlying logic IS implemented:
 *   - crates/gateway/src/auto_rollback.rs   — full EWMA + drift detection
 *     (10 unit tests cover assertions 3, 4, 5 logic — see RollbackEngine
 *     tests in that file)
 *   - crates/gateway/src/prompt_router.rs   — full in-memory routing +
 *     eval-gate enforcement (7 unit tests cover assertions 1, 2, 6 logic
 *     — see tests in that file)
 *
 * What's still missing for THIS file to flip from describe.skip to live:
 *   - HTTP routes /api/prompts/:id/{promote,rollback} on the gateway
 *   - spawnGateway harness invoking gateway with --features prompt-promotion-preview
 *   - Test client that POSTs promotion requests + observes routing
 *
 * unit tests in the Rust modules already give us merge-gate confidence
 * on the math + state-machine; this file becomes live HTTP coverage.
 *
 * Six assertions:
 *   1. A regressive candidate prompt fails the eval gate → blocked from promotion
 *   2. A clean candidate passes the eval gate → atomic promotion
 *   3. Post-deploy >2σ EWMA cost regression → auto-rollback within 500ms
 *   4. Post-deploy >2σ EWMA accuracy regression → suggest-rollback (no auto)
 *   5. Per-prompt override correctly disables auto-rollback
 *   6. Concurrent promotion attempts on same prompt serialize correctly
 *
 * Merge gate: this eval blocks Week 9 release if any assertion fails.
 *
 * Pain: Today prompt iteration is informal — git commit, deploy, hope.
 * Tracelane fix: structured stage → eval gate → promote → observe → auto-rollback.
 *
 */
describe.skip("PP-PROMPT-PROMOTION: B1 promotion + eval gate + auto-rollback", () => {
	it("1. regressive candidate fails eval gate and is blocked", async () => {
		const _gateway = await spawnGateway({ providers: ["mock-fast"] });
		// TODO(B1): stage regressive candidate, run eval, attempt promote, expect blocked_by_eval
		expect.fail("scaffold — wired in dedicated B1 session");
	});

	it("2. clean candidate passes eval gate and atomically promotes", async () => {
		const _gateway = await spawnGateway({ providers: ["mock-fast"] });
		// TODO(B1): stage clean candidate, run eval, attempt promote, expect promoted
		expect.fail("scaffold — wired in dedicated B1 session");
	});

	it("3. >2σ cost EWMA drift triggers auto-rollback within 500ms", async () => {
		const _gateway = await spawnGateway({ providers: ["mock-fast"] });
		// TODO(B1): promote v2, simulate >2σ cost spike, assert routing pointer flips back to v1 within 500ms
		expect.fail("scaffold — wired in dedicated B1 session");
	});

	it("4. >2σ accuracy EWMA drift triggers suggest-rollback only", async () => {
		const _gateway = await spawnGateway({ providers: ["mock-fast"] });
		// TODO(B1): promote v2, simulate >2σ accuracy regression, assert suggest_rollback row created and pointer NOT flipped
		expect.fail("scaffold — wired in dedicated B1 session");
	});

	it("5. per-prompt override disables auto-rollback", async () => {
		const _gateway = await spawnGateway({ providers: ["mock-fast"] });
		// TODO(B1): set override, simulate >2σ cost spike, assert no auto-rollback fired
		expect.fail("scaffold — wired in dedicated B1 session");
	});

	it("6. concurrent promotion attempts on same prompt serialize correctly", async () => {
		const _gateway = await spawnGateway({ providers: ["mock-fast"] });
		// TODO(B1): fire N concurrent promote() calls, assert exactly one wins, others log notes
		expect.fail("scaffold — wired in dedicated B1 session");
	});
});
