/**
 * Tests for the MCP OTel-semconv invocation recorder.
 *
 * It emits a structured `mcp.tool.call` record and must NEVER throw —
 * telemetry must not break a tool call (e.g. when stderr is closed).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	MCP_METHOD_NAME,
	MCP_TOOL_NAME,
	recordMcpInvocation,
} from "./semconv.js";

describe("recordMcpInvocation", () => {
	afterEach(() => vi.restoreAllMocks());

	it("writes a structured mcp.tool.call record to stderr", () => {
		const writes: string[] = [];
		vi.spyOn(process.stderr, "write").mockImplementation((s: unknown) => {
			writes.push(String(s));
			return true;
		});

		recordMcpInvocation({
			[MCP_METHOD_NAME]: "tools/call",
			[MCP_TOOL_NAME]: "get_trace",
			"tracelane.tenant_id": "t-1",
			duration_ms: 12,
		});

		expect(writes).toHaveLength(1);
		const rec = JSON.parse(writes[0] ?? "{}");
		expect(rec.event_name).toBe("mcp.tool.call");
		expect(rec[MCP_TOOL_NAME]).toBe("get_trace");
		expect(rec["tracelane.tenant_id"]).toBe("t-1");
		expect(rec.duration_ms).toBe(12);
	});

	it("never throws when stderr write fails (telemetry is best-effort)", () => {
		vi.spyOn(process.stderr, "write").mockImplementation(() => {
			throw new Error("stderr closed");
		});
		expect(() =>
			recordMcpInvocation({
				[MCP_METHOD_NAME]: "tools/call",
				[MCP_TOOL_NAME]: "get_trace",
			}),
		).not.toThrow();
	});
});
