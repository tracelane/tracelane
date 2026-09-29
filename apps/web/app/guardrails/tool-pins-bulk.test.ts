import { describe, expect, it } from "vitest";
import { bulkApprovalTargets } from "./ToolPins";

const row = (
	tool_name: string,
	def_hash: string,
	last_seen: string,
	approved = false,
) => ({
	tool_name,
	def_hash,
	first_seen: last_seen,
	last_seen,
	seen_count: 1,
	approved,
});

describe("bulk tool approval", () => {
	const rows = [
		row("Bash", "aaa", "2026-09-06T00:00:00Z"),
		row("get_weather", "old", "2026-09-07T00:00:00Z"),
		row("get_weather", "new", "2026-09-20T00:00:00Z"),
		row("list_traces", "ok1", "2026-09-07T00:00:00Z", true),
		row("list_traces", "drift", "2026-09-21T00:00:00Z"),
	];

	it("select-all takes every unapproved tool once, at its latest definition", () => {
		const t = bulkApprovalTargets(rows, null);
		expect(t.map((r) => `${r.tool_name}:${r.def_hash}`)).toEqual([
			"Bash:aaa",
			"get_weather:new",
		]);
	});

	it("never bulk-approves a changed definition — drift is reviewed one at a time", () => {
		const t = bulkApprovalTargets(
			rows,
			new Set(["list_traces:drift", "Bash:aaa"]),
		);
		expect(t.map((r) => r.tool_name)).toEqual(["Bash"]);
	});

	it("two selected definitions of one tool approve only the latest (one pin per tool)", () => {
		const t = bulkApprovalTargets(
			rows,
			new Set(["get_weather:old", "get_weather:new"]),
		);
		expect(t.map((r) => r.def_hash)).toEqual(["new"]);
	});
});
