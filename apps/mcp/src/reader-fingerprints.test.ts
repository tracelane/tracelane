import { expect, it, vi } from "vitest";
import { ClickHouseReader } from "./reader.js";
const raw = {
	span_id: "span",
	attributes: JSON.stringify({
		gen_ai_tool_call_arg_fp: "private-otlp",
		tracelane_response_tool_arg_fps: ["private-gateway"],
		"gen_ai.tool.name": "search",
	}),
};
vi.mock("./auth.js", () => ({
	getTenantId: () => "tenant",
	getActiveBearer: () => "test-bearer",
	validateGatewayUrl: (v: string) => v,
}));
vi.mock("./db.js", () => ({
	getDb: () => ({ query: async () => ({ json: async () => [raw] }) }),
}));
it("strips fingerprints from direct ClickHouse span list and single-span reads", async () => {
	const reader = new ClickHouseReader();
	for (const v of [
		await reader.getTraceSpans("trace"),
		await reader.getSpan({ traceId: "trace", spanId: "span" }),
	]) {
		expect(JSON.stringify(v)).not.toContain("private-");
		expect(JSON.stringify(v)).toContain("search");
	}
});
