/**
 * Tests for POST /api/playground (`specs/OBS-16-playground.md` §7 proofs 2-3).
 *
 * Focus: every guard fires BEFORE the gateway is ever called (oversized body,
 * missing fields), `max_tokens` is clamped rather than trusted, the generated
 * `traceparent` is a well-formed W3C header whose trace id becomes the
 * returned `trace_id` verbatim, and a non-2xx gateway response (unroutable
 * model, a guardrail 403 w/ correlation_id) passes through so the client can
 * render the real message — never a generic failure (CLAUDE.md §1,
 * "error ≠ empty"). Auth + gateway fetch are mocked, off the network, same
 * shape as `app/api/settings/provider-keys/route.test.ts`.
 */

import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ token: "wos_access_token_xyz" }));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_TEST",
		userId: "user_1",
		email: "a@b.com",
		role: "owner",
	})),
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: "org_TEST",
	})),
}));

vi.mock("@/lib/gateway", () => ({
	gatewayBaseUrl: () => "https://gateway.example",
}));

import { POST } from "./route";

const fetchMock = vi.fn();

beforeEach(() => {
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
});

// `route.ts` only ever calls `req.text()`, so a minimal fake is enough — same
// shape as `provider-keys/route.test.ts`'s `{ json: async () => body }`.
function req(body: unknown): NextRequest {
	return { text: async () => JSON.stringify(body) } as unknown as NextRequest;
}

function reqRaw(raw: string): NextRequest {
	return { text: async () => raw } as unknown as NextRequest;
}

const TRACEPARENT_RE = /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;

describe("POST /api/playground — guards enforced BEFORE any gateway call", () => {
	it("rejects a body over 32 KB with 413 and never calls the gateway", async () => {
		const hugePrompt = "x".repeat(33 * 1024);
		const res = await POST(
			reqRaw(JSON.stringify({ model: "gpt-4o", prompt: hugePrompt })),
		);
		expect(res.status).toBe(413);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("payload_too_large");
	});

	it("rejects invalid JSON with 400 and never calls the gateway", async () => {
		const res = await POST(reqRaw("{not json"));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects a missing model with 400 and never calls the gateway", async () => {
		const res = await POST(req({ prompt: "hello" }));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects a missing/blank prompt with 400 and never calls the gateway", async () => {
		const res = await POST(req({ model: "gpt-4o", prompt: "   " }));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("clamps max_tokens to 2048 rather than trusting the client's value", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () =>
				JSON.stringify({
					id: "chatcmpl-1",
					model: "gpt-4o",
					choices: [
						{
							index: 0,
							message: { role: "assistant", content: "hi" },
							finish_reason: "stop",
						},
					],
					usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
				}),
		});
		await POST(req({ model: "gpt-4o", prompt: "hello", max_tokens: 99999 }));
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [, opts] = fetchMock.mock.calls[0] as [string, { body: string }];
		const sent = JSON.parse(opts.body) as { max_tokens: number };
		expect(sent.max_tokens).toBe(2048);
	});

	it("clamps a non-positive max_tokens up to at least 1, never 0 or negative", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () =>
				JSON.stringify({
					model: "gpt-4o",
					choices: [
						{ index: 0, message: { content: "hi" }, finish_reason: "stop" },
					],
					usage: {},
				}),
		});
		await POST(req({ model: "gpt-4o", prompt: "hello", max_tokens: -5 }));
		const [, opts] = fetchMock.mock.calls[0] as [string, { body: string }];
		const sent = JSON.parse(opts.body) as { max_tokens: number };
		expect(sent.max_tokens).toBeGreaterThanOrEqual(1);
	});
});

describe("POST /api/playground — the generated trace context", () => {
	it("sends a well-formed W3C traceparent and returns its trace id as trace_id", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () =>
				JSON.stringify({
					model: "gpt-4o",
					choices: [
						{ index: 0, message: { content: "hi" }, finish_reason: "stop" },
					],
					usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
				}),
		});
		const res = await POST(req({ model: "gpt-4o", prompt: "hello" }));
		expect(res.status).toBe(200);
		const data = (await res.json()) as { trace_id: string };

		const [, opts] = fetchMock.mock.calls[0] as [
			string,
			{ headers: Record<string, string> },
		];
		const traceparent = opts.headers.traceparent ?? "";
		expect(traceparent).toMatch(TRACEPARENT_RE);
		const parts = traceparent.split("-");
		expect(data.trace_id.replace(/-/g, "")).toBe(parts[1]);
	});

	it("forwards the Bearer token and a non-streaming body", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () =>
				JSON.stringify({
					model: "gpt-4o",
					choices: [
						{ index: 0, message: { content: "hi" }, finish_reason: "stop" },
					],
					usage: {},
				}),
		});
		await POST(req({ model: "gpt-4o", prompt: "hello", system: "be nice" }));
		const [url, opts] = fetchMock.mock.calls[0] as [
			string,
			{ headers: Record<string, string>; body: string; method: string },
		];
		expect(url).toBe("https://gateway.example/v1/chat/completions");
		expect(opts.method).toBe("POST");
		expect(opts.headers.authorization).toBe(`Bearer ${h.token}`);
		const sent = JSON.parse(opts.body) as {
			stream: boolean;
			system: string;
			messages: Array<{ role: string; content: string }>;
		};
		expect(sent.stream).toBe(false);
		expect(sent.system).toBe("be nice");
		expect(sent.messages).toEqual([{ role: "user", content: "hello" }]);
	});
});

describe("POST /api/playground — non-2xx gateway responses pass through verbatim", () => {
	it("passes a 400 unroutable_model through with its message intact", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 400,
			text: async () =>
				JSON.stringify({
					error: "unroutable_model",
					message: "no provider is configured to serve this model",
					model: "bogus-model",
				}),
		});
		const res = await POST(req({ model: "bogus-model", prompt: "hello" }));
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string; message: string };
		expect(body.error).toBe("unroutable_model");
		expect(body.message).toBe("no provider is configured to serve this model");
	});

	it("passes a guardrail 403 through with its correlation_id intact", async () => {
		fetchMock.mockResolvedValue({
			ok: false,
			status: 403,
			text: async () =>
				JSON.stringify({
					error: "request blocked by Tracelane inline guardrail",
					rail: "r2_secrets_pii",
					reason_code: "secret_detected",
					correlation_id: "01JV000000000000000000",
				}),
		});
		const res = await POST(req({ model: "gpt-4o", prompt: "hello" }));
		expect(res.status).toBe(403);
		const body = (await res.json()) as { correlation_id: string; rail: string };
		expect(body.correlation_id).toBe("01JV000000000000000000");
		expect(body.rail).toBe("r2_secrets_pii");
	});

	it("maps a transport failure to 503 gateway_unreachable", async () => {
		fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));
		const res = await POST(req({ model: "gpt-4o", prompt: "hello" }));
		expect(res.status).toBe(503);
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("gateway_unreachable");
	});
});

describe("POST /api/playground — success shape", () => {
	it("returns {trace_id, response: {content, model, usage, finish_reason}, latency_ms}", async () => {
		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			text: async () =>
				JSON.stringify({
					id: "chatcmpl-1",
					model: "claude-sonnet-4-6",
					choices: [
						{
							index: 0,
							message: { role: "assistant", content: "the answer" },
							finish_reason: "stop",
						},
					],
					usage: { prompt_tokens: 12, completion_tokens: 4, total_tokens: 16 },
				}),
		});
		const res = await POST(
			req({ model: "claude-sonnet-4-6", prompt: "hello" }),
		);
		expect(res.status).toBe(200);
		const data = (await res.json()) as {
			trace_id: string;
			response: {
				content: string;
				model: string;
				usage: { prompt_tokens: number; completion_tokens: number };
				finish_reason: string;
			};
			latency_ms: number;
		};
		expect(data.response.content).toBe("the answer");
		expect(data.response.model).toBe("claude-sonnet-4-6");
		expect(data.response.usage).toEqual({
			prompt_tokens: 12,
			completion_tokens: 4,
			total_tokens: 16,
		});
		expect(data.response.finish_reason).toBe("stop");
		expect(typeof data.latency_ms).toBe("number");
		expect(typeof data.trace_id).toBe("string");
	});
});
