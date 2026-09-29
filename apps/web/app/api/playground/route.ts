/**
 * POST /api/playground — the `EVL-03` v2 contract: N model columns fanned out
 * in parallel against ONE set of messages/system/tools/variables
 * (`specs/EVL-03-playground-v2-and-open-in-playground.md` §2). The v1 body
 * (`{model, system, prompt, temperature, max_tokens}`) is STILL ACCEPTED and
 * still gets the v1 response shape — a stale tab, or the v1 UI Codex has not
 * yet replaced, keeps working unmodified.
 *
 * Mints the per-user WorkOS JWT via `requireGatewayToken()` (mirrors
 * `app/api/settings/provider-keys/route.ts` / `lib/gateway.ts`) and forwards
 * one non-streaming `POST /v1/chat/completions` PER COLUMN to the gateway.
 * The gateway resolves the tenant from the JWT, never from this body.
 *
 * TRACE ID PER COLUMN. Each column gets its OWN generated W3C `traceparent`
 * (strict level-1 form: `00-<32 hex trace id>-<16 hex parent id>-<flags>`,
 * `crates/gateway/src/trace_context.rs`), so each column lands as its own
 * trace — comparing N models is N parallel traces, never one shared trace
 * with orphan-parent spans (spec §6).
 *
 * `x-tracelane-cache: bypass` on EVERY gateway call (v1 and v2 alike):
 * re-running or comparing must sample the model, never replay the previous
 * click's exact-cache answer (`crates/gateway/src/semantic_cache.rs:109-125`).
 *
 * GUARDS ENFORCED HERE, NOT TRUSTED FROM THE CLIENT (spec §5/§9, proof #4):
 *   - a `viewer` session → 403 `role_forbidden`, BEFORE the body is even read
 *     — zero gateway calls (closes B-585: the gateway's admission pipeline
 *     checks the key SCOPE, not the ROLE, so a viewer session could otherwise
 *     spend the workspace's provider budget)
 *   - request body over `playground_limits.max_body_bytes` → 413, BEFORE any
 *     gateway call
 *   - 1..max_columns columns, 1..max_messages messages — otherwise 400,
 *     BEFORE any gateway call
 *   - an unfilled `{{variable}}` → 400 `unfilled_variable` naming it, BEFORE
 *     any gateway call — nothing is sent
 *   - `max_tokens` clamped to `[1, playground_limits.max_tokens_cap]`, never
 *     passed through raw
 *
 * Every limit above is `billing_policy.playground_limits`
 * (`lib/playground-settings.ts`), never a literal (CLAUDE.md §23).
 *
 * Non-2xx gateway responses (unroutable_model, guardrail 403 w/
 * correlation_id, budget 402, rate limit 429, ...) are passed through
 * VERBATIM in that column's `error` — one column's failure never blanks the
 * others (`Promise.allSettled`, spec §4 "Partial").
 */

import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { getPlaygroundSettings } from "@/lib/playground-settings";
import { render, variablesIn } from "@/lib/playground-template";
import { type NextRequest, NextResponse } from "next/server";

// v1-only defaults — NOT reference-table values (CLAUDE.md §23 covers caps,
// windows and rates; these are plain UI field defaults with no policy
// meaning, unchanged since the v1 route).
const V1_DEFAULT_MAX_TOKENS = 512;
const V1_DEFAULT_TEMPERATURE = 0.2;

function errorJson(
	status: number,
	error: string,
	message?: string,
	extra?: Record<string, unknown>,
) {
	return NextResponse.json(
		message ? { error, message, ...extra } : { error, ...extra },
		{
			status,
		},
	);
}

/** Clamp to `[1, cap]`; a missing/invalid value falls back to `fallback`. */
function clampMaxTokens(raw: unknown, cap: number, fallback: number): number {
	const n = typeof raw === "number" && Number.isFinite(raw) ? raw : fallback;
	return Math.max(1, Math.min(cap, Math.trunc(n)));
}

/** `[0, 2]` — the OpenAI-compatible range every adapter here accepts. */
function normalizeTemperature(raw: unknown): number {
	const n =
		typeof raw === "number" && Number.isFinite(raw)
			? raw
			: V1_DEFAULT_TEMPERATURE;
	return Math.max(0, Math.min(2, n));
}

/**
 * A random W3C `traceparent` (version 00, sampled) plus the trace id it
 * carries, pre-formatted as the UUID `/traces/<id>` expects.
 */
function generateTraceparent(): { header: string; traceId: string } {
	const traceId = crypto.randomUUID();
	const traceHex = traceId.replace(/-/g, "");
	const spanBytes = crypto.getRandomValues(new Uint8Array(8));
	const spanHex = Array.from(spanBytes, (b) =>
		b.toString(16).padStart(2, "0"),
	).join("");
	return { header: `00-${traceHex}-${spanHex}-01`, traceId };
}

interface GatewayToolCall {
	id?: string;
	type?: string;
	function?: { name?: string; arguments?: string };
}
interface GatewayChoice {
	message?: { content?: string; tool_calls?: GatewayToolCall[] };
	finish_reason?: string | null;
}
interface GatewayChatResponse {
	model?: string;
	choices?: GatewayChoice[];
	usage?: {
		prompt_tokens?: number;
		completion_tokens?: number;
		total_tokens?: number;
	};
}

// ── v1 body — unchanged response shape, so a stale tab keeps working ───────

interface PlaygroundV1RequestBody {
	model?: unknown;
	system?: unknown;
	prompt?: unknown;
	temperature?: unknown;
	max_tokens?: unknown;
}

async function handleV1(
	body: PlaygroundV1RequestBody,
	token: string,
	limits: { max_tokens_cap: number; timeout_ms: number },
): Promise<NextResponse> {
	const model = typeof body.model === "string" ? body.model.trim() : "";
	if (!model) return errorJson(400, "model_required", "a model is required");

	const prompt = typeof body.prompt === "string" ? body.prompt.trim() : "";
	if (!prompt) return errorJson(400, "prompt_required", "a prompt is required");

	const system =
		typeof body.system === "string" && body.system.trim()
			? body.system.trim()
			: undefined;

	const maxTokens = clampMaxTokens(
		body.max_tokens,
		limits.max_tokens_cap,
		V1_DEFAULT_MAX_TOKENS,
	);
	const temperature = normalizeTemperature(body.temperature);

	const { header: traceparent, traceId } = generateTraceparent();

	const gatewayBody = {
		model,
		messages: [{ role: "user", content: prompt }],
		...(system ? { system } : {}),
		max_tokens: maxTokens,
		temperature,
		stream: false,
	};

	const start = Date.now();
	let upstream: Response;
	try {
		upstream = await fetch(`${gatewayBaseUrl()}/v1/chat/completions`, {
			method: "POST",
			headers: {
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
				traceparent,
				"x-tracelane-cache": "bypass",
			},
			body: JSON.stringify(gatewayBody),
			cache: "no-store",
			signal: AbortSignal.timeout(limits.timeout_ms),
		});
	} catch (err) {
		return errorJson(
			503,
			"gateway_unreachable",
			err instanceof Error ? err.message : "the gateway did not respond",
		);
	}
	const latencyMs = Date.now() - start;
	const text = await upstream.text();

	if (!upstream.ok) {
		// Pass the gateway's status + body through VERBATIM (unroutable_model,
		// the guardrail 403 w/ correlation_id + rail, 402 budget, 429 quota, ...)
		// — the client renders the real message, never a generic failure.
		return new NextResponse(
			text || JSON.stringify({ error: "gateway_error" }),
			{
				status: upstream.status,
				headers: { "content-type": "application/json" },
			},
		);
	}

	let data: GatewayChatResponse;
	try {
		data = JSON.parse(text) as GatewayChatResponse;
	} catch {
		return errorJson(
			502,
			"invalid_gateway_response",
			"the gateway's response could not be parsed",
		);
	}

	const choice = data.choices?.[0];
	return NextResponse.json({
		trace_id: traceId,
		response: {
			content: choice?.message?.content ?? "",
			model: data.model ?? model,
			usage: data.usage ?? null,
			finish_reason: choice?.finish_reason ?? null,
		},
		latency_ms: latencyMs,
	});
}

// ── v2 body — column fan-out ────────────────────────────────────────────────

interface PlaygroundV2ColumnRequest {
	model?: unknown;
	temperature?: unknown;
	top_p?: unknown;
	max_tokens?: unknown;
	seed?: unknown;
}

interface PlaygroundV2MessageRequest {
	role?: unknown;
	content?: unknown;
}

interface PlaygroundV2RequestBody {
	columns?: unknown;
	system?: unknown;
	messages?: unknown;
	tools?: unknown;
	tool_choice?: unknown;
	variables?: unknown;
}

interface PlaygroundColumnResult {
	ok: boolean;
	status: number;
	trace_id: string;
	latency_ms: number;
	response?: {
		content: string;
		tool_calls: GatewayToolCall[];
		model: string;
		usage: GatewayChatResponse["usage"] | null;
		finish_reason: string | null;
	};
	// The gateway body verbatim — never re-shaped, so the client renders the
	// real message (spec §4 "Error").
	error?: unknown;
}

/** Structural validation of the v2 body. Returns an error response to send
 * as-is, or the validated, still-UNRENDERED shape to render + dispatch. */
function validateV2Body(
	body: PlaygroundV2RequestBody,
	limits: { max_columns: number; max_messages: number },
):
	| { error: NextResponse }
	| {
			columns: PlaygroundV2ColumnRequest[];
			system: string | undefined;
			messages: { role: string; content: string }[];
			tools: unknown;
			tool_choice: unknown;
			variables: Record<string, string>;
	  } {
	const columns = Array.isArray(body.columns)
		? (body.columns as PlaygroundV2ColumnRequest[])
		: [];
	if (columns.length === 0) {
		return {
			error: errorJson(400, "no_columns", "at least one column is required"),
		};
	}
	if (columns.length > limits.max_columns) {
		return {
			error: errorJson(
				400,
				"too_many_columns",
				`at most ${limits.max_columns} columns (got ${columns.length})`,
			),
		};
	}
	for (const [i, col] of columns.entries()) {
		if (typeof col.model !== "string" || !col.model.trim()) {
			return {
				error: errorJson(
					400,
					"model_required",
					`column ${i} is missing a model`,
				),
			};
		}
	}

	const rawMessages = Array.isArray(body.messages)
		? (body.messages as PlaygroundV2MessageRequest[])
		: [];
	if (rawMessages.length === 0) {
		return {
			error: errorJson(400, "no_messages", "at least one message is required"),
		};
	}
	if (rawMessages.length > limits.max_messages) {
		return {
			error: errorJson(
				400,
				"too_many_messages",
				`at most ${limits.max_messages} messages (got ${rawMessages.length})`,
			),
		};
	}
	const ROLES = new Set(["system", "user", "assistant", "tool"]);
	const messages: { role: string; content: string }[] = [];
	for (const [i, m] of rawMessages.entries()) {
		if (
			typeof m.role !== "string" ||
			!ROLES.has(m.role) ||
			typeof m.content !== "string"
		) {
			return {
				error: errorJson(
					400,
					"invalid_message",
					`message ${i} has an invalid role or content`,
				),
			};
		}
		messages.push({ role: m.role, content: m.content });
	}

	const system = typeof body.system === "string" ? body.system : undefined;

	const rawVariables = body.variables;
	const variables: Record<string, string> = {};
	if (
		rawVariables &&
		typeof rawVariables === "object" &&
		!Array.isArray(rawVariables)
	) {
		for (const [k, v] of Object.entries(
			rawVariables as Record<string, unknown>,
		)) {
			if (typeof v === "string") variables[k] = v;
		}
	}

	return {
		columns,
		system,
		messages,
		tools: body.tools,
		tool_choice: body.tool_choice,
		variables,
	};
}

async function handleV2(
	body: PlaygroundV2RequestBody,
	token: string,
	limits: {
		max_columns: number;
		max_messages: number;
		max_tokens_cap: number;
		timeout_ms: number;
	},
): Promise<NextResponse> {
	const validated = validateV2Body(body, limits);
	if ("error" in validated) return validated.error;
	const { columns, system, messages, tools, tool_choice, variables } =
		validated;

	// Render EVERY variable-bearing field with the SAME implementation the
	// save-as-version preview uses (§2 row 6) — one implementation, not two.
	// An unfilled variable refuses the WHOLE request before any gateway call;
	// nothing is sent (spec §5 proof #4).
	const missingNames = new Set<string>();
	const renderedSystem =
		system === undefined ? undefined : render(system, variables);
	if (renderedSystem)
		for (const m of renderedSystem.missing) missingNames.add(m);
	const renderedMessages = messages.map((m) => {
		const r = render(m.content, variables);
		for (const name of r.missing) missingNames.add(name);
		return { role: m.role, content: r.rendered };
	});
	if (missingNames.size > 0) {
		const [first] = missingNames;
		return errorJson(
			400,
			"unfilled_variable",
			`variable {{${first}}} has no value`,
			{ variable: first },
		);
	}

	const results = await Promise.allSettled(
		columns.map(async (col): Promise<PlaygroundColumnResult> => {
			const model = (col.model as string).trim();
			// Only a NUMBER present is clamped; absent stays absent — the gateway's
			// own default, never a substituted one (span.rs:397-399's rule).
			const maxTokens =
				typeof col.max_tokens === "number"
					? clampMaxTokens(
							col.max_tokens,
							limits.max_tokens_cap,
							limits.max_tokens_cap,
						)
					: undefined;
			const { header: traceparent, traceId } = generateTraceparent();

			const gatewayBody: Record<string, unknown> = {
				model,
				messages: renderedMessages,
				stream: false,
			};
			if (renderedSystem) gatewayBody.system = renderedSystem.rendered;
			if (typeof col.temperature === "number")
				gatewayBody.temperature = col.temperature;
			if (typeof col.top_p === "number") gatewayBody.top_p = col.top_p;
			if (maxTokens !== undefined) gatewayBody.max_tokens = maxTokens;
			if (typeof col.seed === "number") gatewayBody.seed = col.seed;
			if (tools !== undefined) gatewayBody.tools = tools;
			if (tool_choice !== undefined) gatewayBody.tool_choice = tool_choice;

			const start = Date.now();
			let upstream: Response;
			try {
				upstream = await fetch(`${gatewayBaseUrl()}/v1/chat/completions`, {
					method: "POST",
					headers: {
						authorization: `Bearer ${token}`,
						"content-type": "application/json",
						traceparent,
						"x-tracelane-cache": "bypass",
					},
					body: JSON.stringify(gatewayBody),
					cache: "no-store",
					signal: AbortSignal.timeout(limits.timeout_ms),
				});
			} catch (err) {
				return {
					ok: false,
					status: 503,
					trace_id: traceId,
					latency_ms: Date.now() - start,
					error: {
						error: "gateway_unreachable",
						message:
							err instanceof Error
								? err.message
								: "the gateway did not respond",
					},
				};
			}
			const latencyMs = Date.now() - start;
			const text = await upstream.text();

			if (!upstream.ok) {
				let errorBody: unknown = { error: "gateway_error" };
				try {
					errorBody = text ? JSON.parse(text) : errorBody;
				} catch {
					// Non-JSON error body — pass the raw text through instead.
					errorBody = { error: "gateway_error", message: text };
				}
				return {
					ok: false,
					status: upstream.status,
					trace_id: traceId,
					latency_ms: latencyMs,
					error: errorBody,
				};
			}

			let data: GatewayChatResponse;
			try {
				data = JSON.parse(text) as GatewayChatResponse;
			} catch {
				return {
					ok: false,
					status: 502,
					trace_id: traceId,
					latency_ms: latencyMs,
					error: { error: "invalid_gateway_response" },
				};
			}
			const choice = data.choices?.[0];
			return {
				ok: true,
				status: upstream.status,
				trace_id: traceId,
				latency_ms: latencyMs,
				response: {
					content: choice?.message?.content ?? "",
					tool_calls: choice?.message?.tool_calls ?? [],
					model: data.model ?? model,
					usage: data.usage ?? null,
					finish_reason: choice?.finish_reason ?? null,
				},
			};
		}),
	);

	// `Promise.allSettled` never rejects, but each mapped fn already catches
	// its own fetch failure — a `rejected` entry here would only mean a bug in
	// the mapper itself, so it still degrades to a per-column error rather than
	// blanking every other column (spec §4 "Partial").
	const columnResults: PlaygroundColumnResult[] = results.map((r) =>
		r.status === "fulfilled"
			? r.value
			: {
					ok: false,
					status: 500,
					trace_id: "",
					latency_ms: 0,
					error: { error: "internal_error", message: String(r.reason) },
				},
	);

	return NextResponse.json({ columns: columnResults });
}

/** Roles that may spend the workspace's provider budget from the playground. */
const PLAYGROUND_ROLES = new Set(["owner", "admin", "member"]);

export async function POST(req: NextRequest): Promise<NextResponse> {
	// Defense-in-depth: unreachable anonymously even if the JWT check below is
	// ever misconfigured (same shape as prompts/[name]/promote).
	const session = await requireSession();
	const { token } = await requireGatewayToken();

	// Closes B-585: the gateway's admission pipeline checks the key SCOPE, not
	// the ROLE (`crates/gateway/src/admission.rs:517`), so a viewer's session
	// can otherwise spend the workspace's provider budget. Checked BEFORE the
	// body is even read — zero gateway calls (spec §9 Q1, §4 "Permission-denied").
	// An ALLOWLIST, not a viewer blocklist (security review 2026-09-27): a new or
	// unknown WorkOS slug, or a role-less session, must not inherit spend rights —
	// the gateway's `Role::from_slug` denies unknown slugs the same way.
	if (!PLAYGROUND_ROLES.has(session.role ?? "")) {
		return errorJson(
			403,
			"role_forbidden",
			"Viewers can't run prompts — it spends the workspace's provider budget",
		);
	}

	const { limits } = await getPlaygroundSettings();

	// Read the raw body FIRST and measure it before parsing anything — the
	// 413 must fire before any gateway call, per spec §5.
	const raw = await req.text();
	if (new TextEncoder().encode(raw).length > limits.max_body_bytes) {
		return errorJson(
			413,
			"payload_too_large",
			`request body exceeds the ${limits.max_body_bytes}-byte playground limit`,
		);
	}

	let body: PlaygroundV1RequestBody & PlaygroundV2RequestBody;
	try {
		body = raw
			? (JSON.parse(raw) as PlaygroundV1RequestBody & PlaygroundV2RequestBody)
			: {};
	} catch {
		return errorJson(400, "invalid_json", "request body is not valid JSON");
	}

	if (Array.isArray(body.columns)) {
		return handleV2(body, token, {
			max_columns: limits.max_columns,
			max_messages: limits.max_messages,
			max_tokens_cap: limits.max_tokens_cap,
			timeout_ms: limits.timeout_ms,
		});
	}
	return handleV1(body, token, {
		max_tokens_cap: limits.max_tokens_cap,
		timeout_ms: limits.timeout_ms,
	});
}
