/**
 * Tests for POST /api/playground — v1 body (still accepted, unchanged response
 * shape) plus the v2 column-fan-out contract
 * (`specs/EVL-03-playground-v2-and-open-in-playground.md` §7 proofs 2-4, 7).
 *
 * Focus: every guard fires BEFORE the gateway is ever called (oversized body,
 * missing fields, too many columns/messages, an unfilled variable, a viewer
 * session), `max_tokens` is clamped rather than trusted, each column gets its
 * OWN well-formed W3C `traceparent` whose trace id becomes that column's
 * `trace_id` verbatim, `x-tracelane-cache: bypass` is sent on every call, and
 * a non-2xx gateway response (unroutable model, a guardrail 403 w/
 * correlation_id) passes through per-column so the client can render the real
 * message — never a generic failure, and one column's failure never blanks
 * the others (CLAUDE.md §1, "error ≠ empty"). Auth + gateway fetch are mocked,
 * off the network, same shape as `app/api/settings/provider-keys/route.test.ts`.
 * Every mocked `fetch` response is a REAL `Response` with a `content-type`
 * header, not an ad-hoc object.
 */

import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	token: "wos_access_token_xyz",
	role: "owner" as string | null,
	limits: {
		max_columns: 4,
		max_messages: 50,
		max_body_bytes: 262144,
		max_tokens_cap: 2048,
		timeout_ms: 45000,
		cost_poll_seconds: 20,
		history_entries: 10,
	},
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_TEST",
		userId: "user_1",
		email: "a@b.com",
		role: h.role,
	})),
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: "org_TEST",
	})),
}));

vi.mock("@/lib/gateway", () => ({
	gatewayBaseUrl: () => "https://gateway.example",
}));

vi.mock("@/lib/playground-settings", () => ({
	getPlaygroundSettings: async () => ({ limits: h.limits, defaulted: false }),
}));

import { POST } from "./route";

const fetchMock = vi.fn();

beforeEach(() => {
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();
	h.role = "owner";
	h.limits = {
		max_columns: 4,
		max_messages: 50,
		max_body_bytes: 262144,
		max_tokens_cap: 2048,
		timeout_ms: 45000,
		cost_poll_seconds: 20,
		history_entries: 10,
	};
});

/** A real `Response`, content-type included — never an ad-hoc mock object. */
function gatewayResponse(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

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
	it("rejects a body over the seeded max_body_bytes with 413 and never calls the gateway", async () => {
		const hugePrompt = "x".repeat(h.limits.max_body_bytes + 1024);
		const res = await POST(
			reqRaw(JSON.stringify({ model: "gpt-4o", prompt: hugePrompt })),
		);
		expect(res.status).toBe(413);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("payload_too_large");
	});

	it("reads the cap from playground_limits, not a hardcoded 32 KB — a body under the seeded cap but over the old 32 KB literal is ACCEPTED", async () => {
		fetchMock.mockResolvedValue(
			gatewayResponse(200, {
				model: "gpt-4o",
				choices: [
					{ index: 0, message: { content: "hi" }, finish_reason: "stop" },
				],
				usage: {},
			}),
		);
		const fortyKb = "x".repeat(40 * 1024);
		const res = await POST(req({ model: "gpt-4o", prompt: fortyKb }));
		expect(res.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("a viewer session gets 403 role_forbidden with ZERO gateway calls", async () => {
		h.role = "viewer";
		const res = await POST(req({ model: "gpt-4o", prompt: "hello" }));
		expect(res.status).toBe(403);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = (await res.json()) as { error: string; message: string };
		expect(body.error).toBe("role_forbidden");
	});

	it.each([
		["an unknown slug", "analyst"],
		["a role-less session", null],
	])(
		"%s is refused too — the rule is an allowlist, not a viewer blocklist (security review 2026-09-27)",
		async (_label, role) => {
			h.role = role;
			const res = await POST(req({ model: "gpt-4o", prompt: "hello" }));
			expect(res.status).toBe(403);
			expect(fetchMock).not.toHaveBeenCalled();
		},
	);

	it("a member (non-viewer) session is NOT refused", async () => {
		h.role = "member";
		fetchMock.mockResolvedValue(
			gatewayResponse(200, {
				model: "gpt-4o",
				choices: [
					{ index: 0, message: { content: "hi" }, finish_reason: "stop" },
				],
				usage: {},
			}),
		);
		const res = await POST(req({ model: "gpt-4o", prompt: "hello" }));
		expect(res.status).toBe(200);
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
		// Re-running or comparing must sample the model, never replay the
		// previous click's exact-cache answer (spec §2 row "gateway calls").
		expect(opts.headers["x-tracelane-cache"]).toBe("bypass");
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

// ── v2 body — column fan-out ────────────────────────────────────────────────

function v2Body(overrides: Record<string, unknown> = {}) {
	return {
		columns: [{ model: "claude-haiku-4-5" }],
		messages: [{ role: "user", content: "hello" }],
		...overrides,
	};
}

function chatResponse(model: string, content = "hi") {
	return gatewayResponse(200, {
		model,
		choices: [
			{
				index: 0,
				message: { role: "assistant", content },
				finish_reason: "stop",
			},
		],
		usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
	});
}

describe("POST /api/playground — v2 guards enforced BEFORE any gateway call (proof #4)", () => {
	it("refuses more than max_columns columns with 400, zero gateway calls", async () => {
		const res = await POST(
			req(
				v2Body({
					columns: Array.from({ length: 5 }, (_, i) => ({ model: `m${i}` })),
				}),
			),
		);
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("too_many_columns");
	});

	it("refuses zero columns with 400", async () => {
		const res = await POST(req(v2Body({ columns: [] })));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("refuses more than max_messages messages with 400, zero gateway calls", async () => {
		const res = await POST(
			req(
				v2Body({
					messages: Array.from({ length: h.limits.max_messages + 1 }, () => ({
						role: "user",
						content: "x",
					})),
				}),
			),
		);
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("too_many_messages");
	});

	it("an unfilled {{variable}} refuses the WHOLE request with 400 unfilled_variable, and NOTHING is sent", async () => {
		const res = await POST(
			req(
				v2Body({
					system: "You are a support agent for {{product}}.",
					messages: [{ role: "user", content: "hi {{name}}" }],
					variables: { product: "Acme" },
				}),
			),
		);
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = (await res.json()) as { error: string; variable: string };
		expect(body.error).toBe("unfilled_variable");
		expect(body.variable).toBe("name");
	});

	it("a fully-filled variable set is NOT refused, and the RENDERED text is what is sent", async () => {
		fetchMock.mockResolvedValue(chatResponse("claude-haiku-4-5"));
		const res = await POST(
			req(
				v2Body({
					messages: [{ role: "user", content: "hi {{name}}" }],
					variables: { name: "Ava" },
				}),
			),
		);
		expect(res.status).toBe(200);
		const [, opts] = fetchMock.mock.calls[0] as [string, { body: string }];
		const sent = JSON.parse(opts.body) as {
			messages: Array<{ content: string }>;
		};
		expect(sent.messages[0]?.content).toBe("hi Ava");
	});

	it("a column missing a model → 400 model_required, zero gateway calls", async () => {
		const res = await POST(req(v2Body({ columns: [{}] })));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
		const body = (await res.json()) as { error: string };
		expect(body.error).toBe("model_required");
	});

	it("zero messages → 400, zero gateway calls", async () => {
		const res = await POST(req(v2Body({ messages: [] })));
		expect(res.status).toBe(400);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("clamps a column's max_tokens to the seeded cap rather than trusting it", async () => {
		fetchMock.mockResolvedValue(chatResponse("gpt-4o"));
		await POST(
			req(v2Body({ columns: [{ model: "gpt-4o", max_tokens: 99999 }] })),
		);
		const [, opts] = fetchMock.mock.calls[0] as [string, { body: string }];
		const sent = JSON.parse(opts.body) as { max_tokens: number };
		expect(sent.max_tokens).toBe(h.limits.max_tokens_cap);
	});
});

describe("POST /api/playground — v2 compare: N models, N traces (proof #3)", () => {
	it("fans out one gateway call PER COLUMN, in parallel, each its own traceparent/trace_id", async () => {
		fetchMock.mockImplementation(
			async (_url: string, opts: { body: string }) => {
				const sent = JSON.parse(opts.body) as { model: string };
				return chatResponse(sent.model);
			},
		);
		const res = await POST(
			req(
				v2Body({
					columns: [
						{ model: "claude-haiku-4-5" },
						{ model: "gpt-4o" },
						{ model: "vertex/gemini-2.5-pro" },
					],
				}),
			),
		);
		expect(res.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledTimes(3);
		const data = (await res.json()) as {
			columns: Array<{
				ok: boolean;
				trace_id: string;
				response?: { model: string };
			}>;
		};
		expect(data.columns).toHaveLength(3);
		expect(data.columns.every((c) => c.ok)).toBe(true);
		// Three DISTINCT trace ids — never one shared trace across columns (spec §6).
		const traceIds = new Set(data.columns.map((c) => c.trace_id));
		expect(traceIds.size).toBe(3);
		expect(data.columns.map((c) => c.response?.model)).toEqual([
			"claude-haiku-4-5",
			"gpt-4o",
			"vertex/gemini-2.5-pro",
		]);
		// Every call carries its OWN well-formed traceparent and the bypass header.
		for (const [, opts] of fetchMock.mock.calls as Array<
			[string, { headers: Record<string, string> }]
		>) {
			expect(opts.headers.traceparent).toMatch(TRACEPARENT_RE);
			expect(opts.headers["x-tracelane-cache"]).toBe("bypass");
		}
		const traceparents = new Set(
			(
				fetchMock.mock.calls as Array<
					[string, { headers: Record<string, string> }]
				>
			).map(([, opts]) => opts.headers.traceparent),
		);
		expect(traceparents.size).toBe(3);
	});

	it("passes tools and tool_choice through, and surfaces tool_calls in the response (§2, §10 A1)", async () => {
		fetchMock.mockResolvedValue(
			gatewayResponse(200, {
				model: "gpt-4o",
				choices: [
					{
						index: 0,
						message: {
							role: "assistant",
							content: "",
							tool_calls: [
								{
									id: "call_1",
									type: "function",
									function: {
										name: "get_weather",
										arguments: '{"city":"NYC"}',
									},
								},
							],
						},
						finish_reason: "tool_calls",
					},
				],
				usage: {},
			}),
		);
		const res = await POST(
			req(
				v2Body({
					tools: [
						{
							type: "function",
							function: { name: "get_weather", parameters: {} },
						},
					],
					tool_choice: "auto",
				}),
			),
		);
		const [, opts] = fetchMock.mock.calls[0] as [string, { body: string }];
		const sent = JSON.parse(opts.body) as {
			tools: unknown;
			tool_choice: unknown;
		};
		expect(sent.tools).toEqual([
			{ type: "function", function: { name: "get_weather", parameters: {} } },
		]);
		expect(sent.tool_choice).toBe("auto");

		const data = (await res.json()) as {
			columns: Array<{
				response?: { tool_calls: Array<{ function?: { name?: string } }> };
			}>;
		};
		expect(data.columns[0]?.response?.tool_calls[0]?.function?.name).toBe(
			"get_weather",
		);
	});
});

describe("POST /api/playground — v2 one column errors, the others don't (proof #7)", () => {
	it("one column 400 unroutable_model, the other columns still succeed — never a blanket failure", async () => {
		fetchMock.mockImplementation(
			async (_url: string, opts: { body: string }) => {
				const sent = JSON.parse(opts.body) as { model: string };
				if (sent.model === "__unroutable__") {
					return gatewayResponse(400, {
						error: "unroutable_model",
						message: "no provider is configured to serve this model",
						model: "__unroutable__",
					});
				}
				return chatResponse(sent.model);
			},
		);
		const res = await POST(
			req(
				v2Body({ columns: [{ model: "__unroutable__" }, { model: "gpt-4o" }] }),
			),
		);
		expect(res.status).toBe(200); // the ENVELOPE is 200; each column carries its own status
		const data = (await res.json()) as {
			columns: Array<{
				ok: boolean;
				status: number;
				error?: { error?: string };
				response?: { model: string };
			}>;
		};
		expect(data.columns[0]?.ok).toBe(false);
		expect(data.columns[0]?.status).toBe(400);
		expect(data.columns[0]?.error?.error).toBe("unroutable_model");
		expect(data.columns[1]?.ok).toBe(true);
		expect(data.columns[1]?.response?.model).toBe("gpt-4o");
	});

	it("a guardrail 403 on one column carries its correlation_id verbatim in that column's error", async () => {
		fetchMock.mockResolvedValue(
			gatewayResponse(403, {
				error: "request blocked by Tracelane inline guardrail",
				rail: "r2_secrets_pii",
				reason_code: "secret_detected",
				correlation_id: "01JV000000000000000000",
			}),
		);
		const res = await POST(req(v2Body()));
		const data = (await res.json()) as {
			columns: Array<{
				ok: boolean;
				status: number;
				error?: { correlation_id?: string };
			}>;
		};
		expect(data.columns[0]?.ok).toBe(false);
		expect(data.columns[0]?.status).toBe(403);
		expect(data.columns[0]?.error?.correlation_id).toBe(
			"01JV000000000000000000",
		);
	});

	it("a transport failure on one column maps to a 503 gateway_unreachable error for that column", async () => {
		fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));
		const res = await POST(req(v2Body()));
		expect(res.status).toBe(200);
		const data = (await res.json()) as {
			columns: Array<{
				ok: boolean;
				status: number;
				error?: { error?: string };
			}>;
		};
		expect(data.columns[0]?.ok).toBe(false);
		expect(data.columns[0]?.status).toBe(503);
		expect(data.columns[0]?.error?.error).toBe("gateway_unreachable");
	});
});

describe("POST /api/playground — v2 viewer refusal (closes B-585)", () => {
	it("a viewer gets 403 role_forbidden with ZERO gateway calls on the v2 body too", async () => {
		h.role = "viewer";
		const res = await POST(req(v2Body()));
		expect(res.status).toBe(403);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
