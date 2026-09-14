/**
 * Tests for POST /api/tara — the agent loop (OBS-40 §7 proof 2, TESTS list).
 *
 * The gateway is mocked at `global.fetch`: every request/response is the
 * SSE `chat.completion.chunk` shape the real gateway streaming path emits
 * (`crates/gateway/src/server.rs:provider_stream_to_sse`) — see the route's
 * own module doc for why a non-streaming mock would not exercise the real
 * code path at all. `runTaraTool` is mocked so this file tests the LOOP's
 * bookkeeping (call count, cap, error pass-through), not the tool registry
 * (covered in `lib/tara/tools.test.ts`).
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: "jwt-test",
		tenantId: "org_test",
	})),
}));
vi.mock("@/lib/gateway", () => ({
	gatewayBaseUrl: () => "http://gateway.test",
}));
vi.mock("@/lib/tara/prompt", () => ({
	buildTaraSystemPrompt: () => "you are tara",
}));

// See `lib/tara/tools.test.ts` for why this must go through `vi.hoisted`.
const { runTaraToolSpy } = vi.hoisted(() => ({
	runTaraToolSpy: vi.fn(async (_name: string, _args: unknown) => ({
		ok: true as const,
		result: { trace_id: "deadbeef01" },
	})),
}));
vi.mock("@/lib/tara/tools", () => ({
	runTaraTool: (name: string, args: unknown) => runTaraToolSpy(name, args),
	toolWireDefinitions: () => [
		{
			type: "function",
			function: { name: "list_traces", description: "d", parameters: {} },
		},
	],
	extractTraceIdCitations: () => [],
}));

import { POST } from "./route";

function sseResponse(chunks: unknown[], status = 200): Response {
	const body = `${chunks.map((c) => `data: ${JSON.stringify(c)}\n\n`).join("")}data: [DONE]\n\n`;
	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			controller.enqueue(new TextEncoder().encode(body));
			controller.close();
		},
	});
	return new Response(stream, {
		status,
		headers: { "content-type": "text/event-stream" },
	});
}

function toolCallChunk(index: number, id: string) {
	return {
		choices: [
			{
				delta: {
					tool_calls: [
						{ index, id, function: { name: "list_traces", arguments: "{}" } },
					],
				},
				finish_reason: null,
			},
		],
	};
}

function finalTextChunk(text: string) {
	return {
		choices: [{ delta: { content: text }, finish_reason: null }],
	};
}

function stopChunk() {
	return {
		choices: [{ delta: {}, finish_reason: "stop" }],
		usage: { prompt_tokens: 10, completion_tokens: 5 },
	};
}

function jsonRequest(body: unknown) {
	return { json: async () => body } as unknown as Parameters<typeof POST>[0];
}

beforeEach(() => {
	runTaraToolSpy.mockClear();
});

describe("the loop stops at 4 tool calls", () => {
	it("dispatches at most 4 tool calls, then forces a tool-less final answer", async () => {
		let call = 0;
		const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => {
			call++;
			// Iterations 1-4 each request one tool call; the 5th (forced
			// tools-off) iteration answers with plain text.
			if (call <= 4) return sseResponse([toolCallChunk(0, `call_${call}`)]);
			return sseResponse([finalTextChunk("here is your answer"), stopChunk()]);
		});
		vi.stubGlobal("fetch", fetchMock);

		const res = await POST(
			jsonRequest({
				question: "why so expensive",
				model: "claude-haiku-4-5-20251001",
			}),
		);
		expect(res.status).toBe(200);
		const body = await res.json();

		expect(runTaraToolSpy).toHaveBeenCalledTimes(4);
		expect(fetchMock).toHaveBeenCalledTimes(5);
		expect(body.tool_calls).toHaveLength(4);
		expect(body.refused_tool_calls).toBe(0);
		expect(body.answer).toBe("here is your answer");
		expect(body.trace_id_of_this_conversation).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
		);

		// The 5th (forced-final) request must not have offered tools at all.
		const fifthCall = fetchMock.mock.calls[4];
		const fifthCallBody = JSON.parse(String(fifthCall?.[1]?.body));
		expect(fifthCallBody.tools).toBeUndefined();

		vi.unstubAllGlobals();
	});

	it("refuses a 5th tool call within the SAME batch without executing it", async () => {
		const fetchMock = vi.fn(async (_: unknown, init?: RequestInit) => {
			const parsed = JSON.parse(String(init?.body));
			if (!parsed.tools)
				return sseResponse([finalTextChunk("done"), stopChunk()]);
			// One turn that tries to fire 5 tool calls at once.
			return sseResponse([
				toolCallChunk(0, "a"),
				toolCallChunk(1, "b"),
				toolCallChunk(2, "c"),
				toolCallChunk(3, "d"),
				toolCallChunk(4, "e"),
			]);
		});
		vi.stubGlobal("fetch", fetchMock);

		const res = await POST(
			jsonRequest({ question: "q", model: "claude-haiku-4-5-20251001" }),
		);
		const body = await res.json();

		expect(runTaraToolSpy).toHaveBeenCalledTimes(4);
		expect(body.refused_tool_calls).toBe(1);

		vi.unstubAllGlobals();
	});
});

describe("gateway 4xx pass-through", () => {
	async function withUpstream(
		status: number,
		jsonBody: Record<string, unknown>,
	) {
		const fetchMock = vi.fn(
			async () => new Response(JSON.stringify(jsonBody), { status }),
		);
		vi.stubGlobal("fetch", fetchMock);
		const res = await POST(
			jsonRequest({ question: "q", model: "claude-haiku-4-5-20251001" }),
		);
		const body = await res.json();
		vi.unstubAllGlobals();
		return { res, body };
	}

	it("401 passes through verbatim", async () => {
		const { res, body } = await withUpstream(401, {
			error: "invalid or expired token",
		});
		expect(res.status).toBe(401);
		expect(body.error).toBe("invalid or expired token");
	});

	it("403 passes through verbatim", async () => {
		const { res, body } = await withUpstream(403, {
			error: "role_forbidden",
			required_role: "owner",
		});
		expect(res.status).toBe(403);
		expect(body.error).toBe("role_forbidden");
		expect(body.required_role).toBe("owner");
	});

	it("402 (budget) passes the gateway message through AND flags reason: budget", async () => {
		const { res, body } = await withUpstream(402, {
			error: "monthly budget exceeded",
			budget_usd: 50,
			spent_usd: 51.2,
		});
		expect(res.status).toBe(402);
		expect(body.error).toBe("monthly budget exceeded");
		expect(body.reason).toBe("budget");
		expect(body.budget_usd).toBe(50);
	});

	it("429 (quota) passes the gateway message through AND flags reason: quota", async () => {
		const { res, body } = await withUpstream(429, {
			error: "rate limit exceeded",
		});
		expect(res.status).toBe(429);
		expect(body.error).toBe("rate limit exceeded");
		expect(body.reason).toBe("quota");
	});
});

describe("request validation", () => {
	it("422s an empty question before ever calling fetch", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		const res = await POST(
			jsonRequest({ question: "", model: "claude-haiku-4-5-20251001" }),
		);
		expect(res.status).toBe(422);
		expect(fetchMock).not.toHaveBeenCalled();
		vi.unstubAllGlobals();
	});

	it("400s an invalid JSON body", async () => {
		const req = {
			json: async () => {
				throw new Error("bad json");
			},
		} as unknown as Parameters<typeof POST>[0];
		const res = await POST(req);
		expect(res.status).toBe(400);
	});
});
