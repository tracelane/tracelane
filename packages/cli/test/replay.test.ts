/**
 *
 * Verifies the gateway repoint: the command hits `GET /v1/traces/{id}/spans`
 * with a Bearer token, treats 404 as "no steps", and maps gateway spans to the
 * `TraceStep[]` shape the renderer consumes. Uses an injected fetch — no live
 * server.
 */

import { describe, expect, it } from "vitest";
import {
	fetchSpans,
	type GatewaySpan,
	mapSpansToSteps,
} from "../src/commands/replay.js";

function jsonResponse(body: unknown, status = 200): Response {
	return {
		ok: status >= 200 && status < 300,
		status,
		json: async () => body,
	} as Response;
}

describe("tlane replay — fetchSpans", () => {
	it("GETs the gateway /v1/traces/{id}/spans URL with a Bearer header", async () => {
		let seenUrl = "";
		let seenAuth: string | undefined;
		const fakeFetch = (async (url: string, init?: RequestInit) => {
			seenUrl = url;
			seenAuth = (init?.headers as Record<string, string>)?.Authorization;
			return jsonResponse([]);
		}) as unknown as typeof fetch;

		await fetchSpans(
			"trace 1/weird",
			"https://gateway.tracelane.dev/",
			"tlane_secret",
			fakeFetch,
		);

		expect(seenUrl).toBe(
			"https://gateway.tracelane.dev/v1/traces/trace%201%2Fweird/spans",
		);
		expect(seenAuth).toBe("Bearer tlane_secret");
	});

	it("returns [] on a 404 (missing OR not-this-tenant — never leaks)", async () => {
		const fakeFetch = (async () =>
			jsonResponse({ error: "trace not found" }, 404)) as unknown as typeof fetch;
		const spans = await fetchSpans("abcdefgh", "https://gw", "t", fakeFetch);
		expect(spans).toEqual([]);
	});

	it("throws on a non-2xx that isn't 404", async () => {
		const fakeFetch = (async () =>
			jsonResponse({ error: "boom" }, 502)) as unknown as typeof fetch;
		await expect(
			fetchSpans("abcdefgh", "https://gw", "t", fakeFetch),
		).rejects.toThrow(/HTTP 502/);
	});

	it("omits the Authorization header when no token is given", async () => {
		let seenAuth: string | undefined = "set";
		const fakeFetch = (async (_url: string, init?: RequestInit) => {
			seenAuth = (init?.headers as Record<string, string>)?.Authorization;
			return jsonResponse([]);
		}) as unknown as typeof fetch;
		await fetchSpans("abcdefgh", "https://gw", "", fakeFetch);
		expect(seenAuth).toBeUndefined();
	});
});

describe("tlane replay — mapSpansToSteps", () => {
	const spans: GatewaySpan[] = [
		{
			span_id: "span-a",
			name: "llm.chat",
			start_time_us: 1_778_000_000_000_000,
			duration_us: 1500,
			attributes: JSON.stringify({
				"llm.model_name": "claude-sonnet-4-6",
				"llm.output_messages": [
					{ "message.role": "assistant", "message.content": "hello world" },
				],
				"some.array": [1, 2, 3],
			}),
		},
		{
			span_id: "span-b",
			name: "tool.call",
			start_time_us: 1_778_000_000_001_000,
			duration_us: 200,
			attributes: "{ not valid json",
		},
	];

	it("maps span fields and extracts the first LLM output message", () => {
		const steps = mapSpansToSteps(spans);
		expect(steps).toHaveLength(2);
		expect(steps[0]).toMatchObject({
			index: 0,
			spanId: "span-a",
			name: "llm.chat",
			startTimeUs: 1_778_000_000_000_000,
			durationUs: 1500,
			llmMessage: { role: "assistant", content: "hello world" },
		});
		// Scalar attributes are kept; non-scalar (array) is dropped.
		expect(steps[0].attributes?.["llm.model_name"]).toBe("claude-sonnet-4-6");
		expect(steps[0].attributes?.["some.array"]).toBeUndefined();
	});

	it("tolerates malformed attribute JSON (no llmMessage, empty attrs)", () => {
		const steps = mapSpansToSteps(spans);
		expect(steps[1].index).toBe(1);
		expect(steps[1].spanId).toBe("span-b");
		expect(steps[1].llmMessage).toBeUndefined();
		expect(steps[1].attributes).toEqual({});
	});
});
