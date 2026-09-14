import type { Span } from "@/components/trace-viewer/types";
import { describe, expect, it } from "vitest";
import {
	MAIN_LANE_KEY,
	computeLanes,
	laneStats,
	lanesWithErrors,
} from "./lanes";

/** Minimal span factory — mirrors `lib/trace-tree.test.ts`'s convention. */
function span(p: Partial<Span> & { span_id: string }): Span {
	return {
		span_id: p.span_id,
		parent_span_id: p.parent_span_id ?? null,
		name: p.name ?? p.span_id,
		start_time: p.start_time ?? "2026-06-19T00:00:00.000Z",
		end_time: p.end_time ?? "2026-06-19T00:00:01.000Z",
		start_time_us: p.start_time_us,
		duration_us: p.duration_us ?? 1000,
		status_code: p.status_code ?? 1,
		status_message: p.status_message ?? "",
		attributes: p.attributes ?? "{}",
		aft_ids: p.aft_ids ?? [],
		intervention: p.intervention ?? 0,
	};
}

const J = (o: unknown) => JSON.stringify(o);

describe("computeLanes — the Claude Code fixture (proof #4, single-span/single-agent traces)", () => {
	// A real Claude Code session: `gen_ai_agent_name` is a SESSION-WIDE resource
	// attribute, so every span carries the same value and no span carries an
	// agent id. This must collapse to ONE lane, not one per span.
	const spans = [
		span({
			span_id: "root",
			start_time_us: 1000,
			attributes: J({ gen_ai_agent_name: "claude-code" }),
		}),
		span({
			span_id: "tool-1",
			parent_span_id: "root",
			start_time_us: 1100,
			attributes: J({ gen_ai_agent_name: "claude-code" }),
		}),
		span({
			span_id: "tool-2",
			parent_span_id: "root",
			start_time_us: 1200,
			attributes: J({ gen_ai_agent_name: "claude-code" }),
		}),
	];

	it("groups every span into a single lane keyed and labelled by the shared agent name", () => {
		const lanes = computeLanes(spans);
		expect(lanes).toHaveLength(1);
		const [lane] = lanes;
		if (!lane) throw new Error("unreachable — length just asserted");
		expect(lane.key).toBe("claude-code");
		expect(lane.label).toBe("claude-code");
		expect(lane.spans.map((s) => s.span_id).sort()).toEqual([
			"root",
			"tool-1",
			"tool-2",
		]);
	});

	it("a single-span trace with no agent attribute at all falls back to Main", () => {
		const lanes = computeLanes([span({ span_id: "only" })]);
		expect(lanes).toHaveLength(1);
		const [lane] = lanes;
		if (!lane) throw new Error("unreachable — length just asserted");
		expect(lane.key).toBe(MAIN_LANE_KEY);
		expect(lane.label).toBe("Main");
	});
});

describe("computeLanes — a seeded 3-agent fixture with a parent_agent_id hand-off", () => {
	// root (no agent attrs, falls to Main) spawns `planner`, which hands off to
	// two workers via `gen_ai.agent.parent_id`. `worker-1-child` carries NO
	// agent attribute of its own and must INHERIT worker-1's lane, never main's
	// or planner's — exercising "inheritance flows down the tree, from the
	// nearest ancestor, never from a sibling."
	const spans = [
		span({ span_id: "root", start_time_us: 1_000 }),
		span({
			span_id: "planner",
			parent_span_id: "root",
			start_time_us: 2_000,
			attributes: J({
				"gen_ai.agent.id": "planner-0",
				gen_ai_agent_name: "planner",
			}),
		}),
		span({
			span_id: "worker-1",
			parent_span_id: "planner",
			start_time_us: 3_000,
			attributes: J({
				"gen_ai.agent.id": "worker-1",
				gen_ai_agent_name: "researcher",
				"gen_ai.agent.parent_id": "planner-0",
			}),
		}),
		span({
			span_id: "worker-1-child",
			parent_span_id: "worker-1",
			start_time_us: 3_100,
			// No agent attribute of its own — must inherit "worker-1".
		}),
		span({
			span_id: "worker-2",
			parent_span_id: "planner",
			start_time_us: 4_000,
			status_code: 2,
			attributes: J({
				"gen_ai.agent.id": "worker-2",
				"gen_ai.agent.parent_id": "planner-0",
			}),
		}),
	];
	const lanes = computeLanes(spans);

	it("produces one lane per agent identity, not one per span", () => {
		expect(lanes.map((l) => l.key)).toEqual([
			MAIN_LANE_KEY,
			"planner-0",
			"worker-1",
			"worker-2",
		]);
	});

	it("orders lanes by first-seen start time", () => {
		// root(1000) < planner(2000) < worker-1(3000) < worker-2(4000).
		expect(lanes.map((l) => l.key)).toEqual([
			MAIN_LANE_KEY,
			"planner-0",
			"worker-1",
			"worker-2",
		]);
		for (let i = 1; i < lanes.length; i++) {
			const cur = lanes[i];
			const prev = lanes[i - 1];
			if (!cur || !prev) throw new Error("unreachable — index in range");
			expect(cur.firstStartUs).toBeGreaterThan(prev.firstStartUs);
		}
	});

	it("inherits a childless-of-attributes span into its nearest ancestor's lane", () => {
		const worker1 = lanes.find((l) => l.key === "worker-1");
		expect(worker1?.spans.map((s) => s.span_id).sort()).toEqual([
			"worker-1",
			"worker-1-child",
		]);
	});

	it("labels a lane with a known name + the short id, when both are known", () => {
		const worker1 = lanes.find((l) => l.key === "worker-1");
		expect(worker1?.label).toBe("researcher (worker-1)");
	});

	it("labels a lane with the short id alone when no name is known", () => {
		const worker2 = lanes.find((l) => l.key === "worker-2");
		expect(worker2?.label).toBe("worker-2");
	});

	it("records the hand-off from the parent agent's lane, when that lane exists", () => {
		const worker1 = lanes.find((l) => l.key === "worker-1");
		const worker2 = lanes.find((l) => l.key === "worker-2");
		const planner = lanes.find((l) => l.key === "planner-0");
		expect(worker1?.handoffFromKey).toBe("planner-0");
		expect(worker2?.handoffFromKey).toBe("planner-0");
		expect(planner?.handoffFromKey).toBeUndefined();
	});

	it("laneStats sums span/error counts and the active window per lane", () => {
		const worker2 = lanes.find((l) => l.key === "worker-2");
		expect(worker2).toBeDefined();
		if (!worker2) throw new Error("unreachable");
		const stats = laneStats(worker2);
		expect(stats.spanCount).toBe(1);
		expect(stats.errorCount).toBe(1);
		expect(stats.durationUs).toBe(1000); // the fixture's default duration_us
	});

	it("lanesWithErrors keeps only lanes containing at least one error span", () => {
		const errored = lanesWithErrors(lanes);
		expect(errored.map((l) => l.key)).toEqual(["worker-2"]);
	});
});

describe("computeLanes — no hand-off recorded when the named parent has no lane", () => {
	it("leaves handoffFromKey undefined rather than pointing at a lane that doesn't exist", () => {
		const spans = [
			span({
				span_id: "orphan-handoff",
				attributes: J({
					"gen_ai.agent.id": "solo",
					"gen_ai.agent.parent_id": "someone-not-in-this-trace",
				}),
			}),
		];
		const lanes = computeLanes(spans);
		expect(lanes).toHaveLength(1);
		const [lane] = lanes;
		if (!lane) throw new Error("unreachable — length just asserted");
		expect(lane.handoffFromKey).toBeUndefined();
	});
});
