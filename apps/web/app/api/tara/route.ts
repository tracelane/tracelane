/**
 * POST /api/tara — OBS-40 "Ask Tara": the agent loop.
 *
 * Body: `{ question, model, history? }` → system prompt (persona Tara,
 * `lib/tara/prompt.ts`) + the closed tool set (`lib/tara/tools.ts`) →
 * `POST ${gateway}/v1/chat/completions` with the user's own WorkOS JWT
 * (`requireGatewayToken`, ADR-042 tenant resolution) and a FRESH
 * `traceparent` (GWY-46) so this question is itself a recorded, ledger-
 * visible trace on the tenant's own gateway. At most 4 tool calls, then a
 * final answer. Returns `{ answer, citations, trace_id_of_this_conversation,
 * usage, tool_calls, refused_tool_calls }`.
 *
 * ── WHY THIS CALLS THE GATEWAY WITH `stream: true`, ALWAYS ─────────────────
 *
 * The obvious shape for a single-round-trip route is a plain, non-streaming
 * chat completion. It does not work here, and the reason is a real gateway
 * defect this build surfaced rather than a style choice:
 *
 *   - Every provider adapter (`anthropic.rs`, `openai.rs`) speaks to the
 *     UPSTREAM provider over SSE regardless of what the caller asked for —
 *     Anthropic's adapter hardcodes `stream: true` unconditionally
 *     (`providers/anthropic.rs:400`, "ALWAYS TRUE, REGARDLESS OF WHAT THE
 *     CALLER ASKED FOR"), and a tool-use turn arrives as
 *     `ProviderEvent::ToolCallDelta` events, never as a `Done{response}`
 *     whose `message.content` is a text string.
 *   - When the CLIENT's own request has `stream` unset/false, the gateway
 *     buffers that upstream SSE into one JSON reply via
 *     `buffer_provider_stream` (`server.rs:5531`). Its event-match loop
 *     handles `StreamChunk`, `UsageUpdate`, `Done`, `Error` — and falls
 *     through `ToolCallDelta` (and `ThinkingDelta`) with a bare `Ok(_) => {}`
 *     (`server.rs:5631`). The final JSON payload it builds
 *     (`server.rs:5800-5814`) has NO `tool_calls` field at all. So a
 *     non-streaming `/v1/chat/completions` call that triggers a tool call
 *     silently loses it — the client gets `finish_reason: "stop"` and
 *     whatever plain text happened to accompany it (often none).
 *   - The STREAMING path (`provider_stream_to_sse`, `server.rs:5050`) DOES
 *     forward `ToolCallDelta` as proper OpenAI `chat.completion.chunk`
 *     `delta.tool_calls` frames (`server.rs:5232-5250`) — this is the only
 *     path that actually surfaces a tool call to an OpenAI-style caller.
 *
 * So this route asks the gateway to stream (`stream: true` in the outbound
 * body) and reconstructs the full answer / tool calls itself from the SSE,
 * even though the BROWSER never sees a stream — the panel gets one JSON
 * response per spec §6 ("Streaming the answer — v1 is one round trip").
 * That scope line is about the web↔browser leg; the web↔gateway leg has to
 * stream or tool calling silently does not work for ANY provider (the same
 * `Ok(_) => {}` fallthrough exists regardless of adapter).
 *
 * One further gateway quirk this loop works around: the streaming path's
 * final chunk always carries `finish_reason: "stop"`, even on a turn that
 * emitted tool-call deltas (`server.rs:5336` — there is no `"tool_calls"`
 * finish reason anywhere in this codebase). Whether this turn is a tool
 * call or a final answer is therefore decided by whether any tool-call
 * deltas were seen, not by `finish_reason`.
 *
 * A separate, narrower gap: `ChatRequest` (`crates/shared/src/model.rs`) has
 * no `tool_choice` field at all, so the `tool_choice: "auto"` this route
 * sends is silently dropped by serde on the way in and never reaches any
 * provider. Anthropic and OpenAI both default to "auto" tool choice when
 * `tools` is present without an explicit steer, which is the behaviour this
 * feature wants — so the field is sent for wire-format honesty (a caller
 * reading the request body sees the intent) but is currently a no-op.
 */

import { requireGatewayToken } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { buildTaraSystemPrompt } from "@/lib/tara/prompt";
import {
	extractTraceIdCitations,
	runTaraTool,
	toolWireDefinitions,
} from "@/lib/tara/tools";
import { type NextRequest, NextResponse } from "next/server";
import { z } from "zod";

export const dynamic = "force-dynamic";

const MAX_TOOL_CALLS = 4;
const MAX_ITERATIONS = MAX_TOOL_CALLS + 2; // tool turns + a forced final answer, plus slack
const ANSWER_MAX_TOKENS = 800;
const TOTAL_TIMEOUT_MS = 45_000;

const bodySchema = z.object({
	question: z.string().min(1, "question is required").max(4000),
	model: z.string().min(1, "model is required").max(128),
	history: z
		.array(
			z.object({
				role: z.enum(["user", "assistant"]),
				content: z.string().min(1).max(4000),
			}),
		)
		.max(6)
		.optional(),
});

type ChatToolCallDelta = {
	index?: number;
	id?: string;
	function?: { name?: string; arguments?: string };
};
type ChatChunk = {
	choices?: Array<{
		delta?: { content?: string; tool_calls?: ChatToolCallDelta[] };
		finish_reason?: string | null;
	}>;
	usage?: { prompt_tokens?: number; completion_tokens?: number };
	tracelane_guardrail?: { reason_code?: string };
};

type AccumulatedToolCall = { id?: string; name?: string; args: string };

interface StreamOutcome {
	text: string;
	toolCalls: Map<number, AccumulatedToolCall>;
	usage: { input_tokens: number; output_tokens: number } | null;
	guardrailBlocked: boolean;
}

/** Consume the gateway's `chat.completion.chunk` SSE body and reconstruct
 * the text + any tool-call deltas. See the module doc for why this exists
 * instead of a plain JSON parse. */
async function consumeGatewaySse(res: Response): Promise<StreamOutcome> {
	const parts: string[] = [];
	const toolCalls = new Map<number, AccumulatedToolCall>();
	let usage: StreamOutcome["usage"] = null;
	let guardrailBlocked = false;

	const reader = res.body?.getReader();
	if (!reader) return { text: "", toolCalls, usage, guardrailBlocked };
	const decoder = new TextDecoder();
	let buffer = "";

	const handleLine = (rawLine: string): boolean => {
		// Returns true when the caller should stop reading (saw [DONE]).
		const line = rawLine.replace(/\r$/, "");
		if (!line || line.startsWith(":")) return false;
		const match = line.match(/^data:\s?(.*)$/);
		if (!match) return false;
		const data = match[1] ?? "";
		if (data === "[DONE]") return true;
		let chunk: ChatChunk;
		try {
			chunk = JSON.parse(data) as ChatChunk;
		} catch {
			return false;
		}
		if (chunk.tracelane_guardrail) guardrailBlocked = true;
		const choice = chunk.choices?.[0];
		if (choice?.delta?.content) parts.push(choice.delta.content);
		if (Array.isArray(choice?.delta?.tool_calls)) {
			for (const tc of choice.delta.tool_calls) {
				const idx = typeof tc.index === "number" ? tc.index : 0;
				const existing = toolCalls.get(idx) ?? { args: "" };
				if (tc.id) existing.id = tc.id;
				if (tc.function?.name) existing.name = tc.function.name;
				if (typeof tc.function?.arguments === "string")
					existing.args += tc.function.arguments;
				toolCalls.set(idx, existing);
			}
		}
		if (chunk.usage && typeof chunk.usage.prompt_tokens === "number") {
			usage = {
				input_tokens: chunk.usage.prompt_tokens,
				output_tokens: chunk.usage.completion_tokens ?? 0,
			};
		}
		return false;
	};

	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		buffer += decoder.decode(value, { stream: true });
		let nl = buffer.indexOf("\n");
		while (nl !== -1) {
			const line = buffer.slice(0, nl);
			buffer = buffer.slice(nl + 1);
			if (handleLine(line))
				return { text: parts.join(""), toolCalls, usage, guardrailBlocked };
			nl = buffer.indexOf("\n");
		}
	}
	return { text: parts.join(""), toolCalls, usage, guardrailBlocked };
}

/** A fresh W3C `traceparent` (version 00, non-zero ids) and the trace's UUID
 * form, so this conversation is captured under its own trace
 * (`trace_context.rs::parse_traceparent`) rather than an undocumented
 * `x-trace-id`. */
function freshTraceContext(): { traceparent: string; traceId: string } {
	const toHex = (n: number) => {
		const bytes = new Uint8Array(n);
		crypto.getRandomValues(bytes);
		return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
	};
	let traceHex = toHex(16);
	let spanHex = toHex(8);
	// Astronomically unlikely, but the gateway treats an all-zero id as
	// ABSENT (parse_traceparent), which would silently drop this trace's own
	// context — regenerate rather than ship a header that parses as nothing.
	while (/^0+$/.test(traceHex)) traceHex = toHex(16);
	while (/^0+$/.test(spanHex)) spanHex = toHex(8);
	const traceId = `${traceHex.slice(0, 8)}-${traceHex.slice(8, 12)}-${traceHex.slice(12, 16)}-${traceHex.slice(16, 20)}-${traceHex.slice(20, 32)}`;
	return { traceparent: `00-${traceHex}-${spanHex}-01`, traceId };
}

/**
 * The gateway's INTERNAL wire shape for a message (`crates/shared/src/model.rs`
 * `Message`/`ToolCall`), NOT the OpenAI wire shape — and the two differ in a
 * way that matters here.
 *
 * `POST /v1/chat/completions` deserializes the body straight into
 * `ChatRequest` (`serde_json::from_value::<ChatRequest>`, `server.rs:2224`)
 * with NO OpenAI-compatibility shim for message-level tool calls. `Tool`
 * (the tool DEFINITIONS in `tools:`) has a custom `Deserialize` that accepts
 * both `{name,input_schema}` and OpenAI's `{type,function:{name,parameters}}`
 * (B-258) — but `ToolCall` (an actual invocation, inside message HISTORY)
 * has no such shim: it derives a plain `{id,name,input}` and nothing else.
 * Sending an assistant tool_calls entry in OpenAI's own
 * `{id,type:"function",function:{name,arguments:"<json string>"}}` shape —
 * the shape the model itself just streamed back to us — fails
 * `serde_json::from_value` and 400s the WHOLE follow-up request with
 * `malformed request: …`. So this loop must translate the streamed
 * OpenAI-shaped tool-call deltas into the native `{id,name,input}` shape
 * before replaying them back to the gateway as conversation history.
 */
type ChatMessage =
	| { role: "system" | "user" | "assistant"; content: string }
	| {
			role: "assistant";
			content: string;
			tool_calls: Array<{ id: string; name: string; input: unknown }>;
	  }
	| { role: "tool"; tool_call_id: string; content: string };

export async function POST(req: NextRequest): Promise<NextResponse> {
	const { token } = await requireGatewayToken();

	let rawBody: unknown;
	try {
		rawBody = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	const parsedBody = bodySchema.safeParse(rawBody);
	if (!parsedBody.success) {
		return NextResponse.json(
			{
				error: "invalid_request",
				issues: parsedBody.error.issues.map(
					(i) => `${i.path.join(".") || "(root)"}: ${i.message}`,
				),
			},
			{ status: 422 },
		);
	}
	const { question, model, history } = parsedBody.data;

	const { traceparent, traceId } = freshTraceContext();
	const base = gatewayBaseUrl();
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), TOTAL_TIMEOUT_MS);

	const messages: ChatMessage[] = [
		{ role: "system", content: buildTaraSystemPrompt() },
		...(history ?? []).map(
			(h) => ({ role: h.role, content: h.content }) as ChatMessage,
		),
		{ role: "user", content: question },
	];

	const citations = new Map<string, { trace_id: string; label: string }>();
	const toolProgress: Array<{ name: string; ok: boolean }> = [];
	let toolCallsUsed = 0;
	let refusedToolCalls = 0;
	let totalInputTokens = 0;
	let totalOutputTokens = 0;
	let answer = "";
	let guardrailBlockedAny = false;

	try {
		for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
			const toolsAllowed = toolCallsUsed < MAX_TOOL_CALLS;
			const upstreamBody: Record<string, unknown> = {
				model,
				messages,
				max_tokens: ANSWER_MAX_TOKENS,
				stream: true,
			};
			if (toolsAllowed) {
				upstreamBody.tools = toolWireDefinitions();
				upstreamBody.tool_choice = "auto";
			}

			let res: Response;
			try {
				res = await fetch(`${base}/v1/chat/completions`, {
					method: "POST",
					headers: {
						authorization: `Bearer ${token}`,
						"content-type": "application/json",
						traceparent,
					},
					body: JSON.stringify(upstreamBody),
					signal: controller.signal,
				});
			} catch (err) {
				if (err instanceof Error && err.name === "AbortError") {
					return NextResponse.json(
						{
							error: "timeout",
							message:
								"Tara took too long to answer (45s) — try a narrower question.",
						},
						{ status: 504 },
					);
				}
				return NextResponse.json(
					{
						error: "gateway_unreachable",
						message: err instanceof Error ? err.message : "fetch failed",
					},
					{ status: 503 },
				);
			}

			if (!res.ok) {
				const upstreamJson = await res
					.json()
					.catch(() => null as Record<string, unknown> | null);
				const reason =
					res.status === 402
						? "budget"
						: res.status === 429
							? "quota"
							: undefined;
				return NextResponse.json(
					{
						...(upstreamJson ?? {}),
						error:
							(upstreamJson?.error as string | undefined) ??
							`gateway responded ${res.status}`,
						...(reason ? { reason } : {}),
					},
					{ status: res.status },
				);
			}

			const outcome = await consumeGatewaySse(res);
			if (outcome.usage) {
				totalInputTokens += outcome.usage.input_tokens;
				totalOutputTokens += outcome.usage.output_tokens;
			}
			if (outcome.guardrailBlocked) guardrailBlockedAny = true;

			if (outcome.toolCalls.size === 0) {
				// No tool call this turn — the accumulated text is the final answer,
				// regardless of `finish_reason` (the gateway always sends "stop" —
				// see module doc).
				answer = outcome.text;
				break;
			}

			// Record the assistant's tool-call turn, in index order — in the
			// gateway's NATIVE {id,name,input} shape (see the ChatMessage doc
			// comment above for why the OpenAI shape 400s here).
			const orderedIndices = [...outcome.toolCalls.keys()].sort(
				(a, b) => a - b,
			);
			messages.push({
				role: "assistant",
				content: outcome.text || "",
				tool_calls: orderedIndices.map((idx, i) => {
					const tc = outcome.toolCalls.get(idx);
					let input: unknown = {};
					try {
						input = tc?.args ? JSON.parse(tc.args) : {};
					} catch {
						input = { raw: tc?.args ?? "" };
					}
					return {
						id: tc?.id ?? `call_${iteration}_${i}`,
						name: tc?.name ?? "",
						input,
					};
				}),
			});

			for (const idx of orderedIndices) {
				const tc = outcome.toolCalls.get(idx);
				const callId = tc?.id ?? `call_${iteration}_${idx}`;
				const name = tc?.name ?? "";

				if (toolCallsUsed >= MAX_TOOL_CALLS) {
					refusedToolCalls++;
					messages.push({
						role: "tool",
						tool_call_id: callId,
						content: JSON.stringify({
							error: "tool_call_budget_exceeded",
							message: `Tara answers with at most ${MAX_TOOL_CALLS} tool calls per question; this call was not run.`,
						}),
					});
					continue;
				}

				let args: unknown;
				try {
					args = tc?.args ? JSON.parse(tc.args) : {};
				} catch {
					toolCallsUsed++;
					refusedToolCalls++;
					toolProgress.push({ name, ok: false });
					messages.push({
						role: "tool",
						tool_call_id: callId,
						content: JSON.stringify({
							error: "invalid_arguments",
							issues: ["arguments were not valid JSON"],
						}),
					});
					continue;
				}

				toolCallsUsed++;
				const result = await runTaraTool(name, args);
				toolProgress.push({ name, ok: result.ok });
				if (!result.ok) {
					if (result.error.error === "invalid_arguments") refusedToolCalls++;
					messages.push({
						role: "tool",
						tool_call_id: callId,
						content: JSON.stringify(result.error),
					});
					continue;
				}
				messages.push({
					role: "tool",
					tool_call_id: callId,
					content: JSON.stringify(result.result),
				});
				for (const c of extractTraceIdCitations(
					result.result,
					new Set(citations.keys()),
				)) {
					if (!citations.has(c.trace_id)) citations.set(c.trace_id, c);
				}
			}
			// Loop again — either with tools still available or, once the cap is
			// hit, forced onto a final, tool-less answer (`toolsAllowed` is
			// recomputed at the top of the next iteration from `toolCallsUsed`).
		}
	} finally {
		clearTimeout(timeout);
	}

	if (!answer) {
		answer = guardrailBlockedAny
			? "I could not find that in your traces — part of the answer was withheld by a guardrail."
			: "I could not find that in your traces.";
	}

	return NextResponse.json({
		answer,
		citations: [...citations.values()],
		trace_id_of_this_conversation: traceId,
		usage: { input_tokens: totalInputTokens, output_tokens: totalOutputTokens },
		tool_calls: toolProgress,
		refused_tool_calls: refusedToolCalls,
	});
}
