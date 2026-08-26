/**
 * Every rail's declared `action` must match what the RUST ENGINE actually returns.
 *
 * This file exists because /guardrails advertised "Blocks" for tool-definition pinning
 * (R3_pinning) with a red danger badge, while `r3_tool_safety.rs:322` returns
 * `RailOutcome::warn(TOOL_DEF_DRIFT)` and the request PROCEEDS to the provider. The only
 * blocking path needs `DriftPosture::Suspend`, opt-in via
 * `TRACELANE_GUARDRAIL_SUSPEND_DRIFTED_TOOLS=1` and off by default.
 *
 * That is not only inaccurate, it is the framing the ADR-055 amendment forbids: agent-tool
 * safety is a DETECTION capability of the recorder, never an enforcement /
 * block-before-execution lead, "because a false-positive block breaks a legitimate run —
 * worse than the failure it prevents".
 *
 * The expectations below are transcribed from the Rust sources named in each comment. If a
 * rail's posture changes in the engine, this test must be updated IN THE SAME CHANGE — that
 * coupling is the whole point, since nothing else connects the badge to the binary.
 */
import { describe, expect, it } from "vitest";
import { RAIL_ROSTER } from "./guardrail-rails";

const byId = new Map(RAIL_ROSTER.map((r) => [r.id, r]));

describe("rail action matches the engine's DEFAULT posture", () => {
	it("R3_pinning WARNS — the drift path is observe-first (r3_tool_safety.rs:322)", () => {
		const r = byId.get("R3_pinning");
		expect(r).toBeDefined();
		expect(r?.action).toBe("warn");
	});

	it("R3_pinning's copy does not promise blocking it does not do", () => {
		const blurb = (byId.get("R3_pinning")?.blurb ?? "").toLowerCase();
		// "Blocks a request when a tool's definition changed…" was the false claim.
		expect(blurb).not.toMatch(/^blocks\b/);
		expect(blurb).not.toMatch(/blocks a request/);
		// And it must say what actually happens.
		expect(blurb).toMatch(/proceeds|records/);
	});

	it("no rail claims to block on a posture that is opt-in and off by default", () => {
		// A rail may legitimately block (R3_schema, R4_trifecta do, unconditionally).
		// What is banned is claiming `block` when the default path returns warn.
		const suspicious = RAIL_ROSTER.filter(
			(r) =>
				r.action === "block" &&
				/opt-in|off by default|suspend/i.test(r.blurb ?? ""),
		);
		expect(suspicious.map((r) => r.id)).toEqual([]);
	});
});
