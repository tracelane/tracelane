/**
 * POST /api/playground — run one prompt through the gateway and hand back the
 * trace id the run landed under (`specs/OBS-16-playground.md` §2).
 *
 * Mints the per-user WorkOS JWT via `requireGatewayToken()` (mirrors
 * `app/api/settings/provider-keys/route.ts` / `lib/gateway.ts`) and forwards a
 * single non-streaming `POST /v1/chat/completions` to the gateway. The gateway
 * resolves the tenant from the JWT, never from this body.
 *
 * TRACE ID. A W3C `traceparent` is generated here (strict level-1 form:
 * `00-<32 hex trace id>-<16 hex parent id>-<flags>`,
 * `crates/gateway/src/trace_context.rs`) so we know the trace id BEFORE the
 * response arrives — the gateway joins it via `resolve_trace_identity` and its
 * span carries the SAME id `otlp_trace_id_to_uuid` would derive from those 16
 * bytes, which is exactly `crypto.randomUUID()`'s own byte layout. So the
 * `trace_id` we hand back to the client is the generated UUID verbatim, and
 * `/traces/<trace_id>` is where that span will show up.
 *
 * GUARDS ENFORCED HERE, NOT TRUSTED FROM THE CLIENT (spec §5, proof #2):
 *   - request body over 32 KB → 413, BEFORE any gateway call
 *   - `max_tokens` clamped to `[1, 2048]`, never passed through raw
 *   - 45s hard timeout on the upstream call
 *
 * Non-2xx gateway responses (unroutable_model, guardrail 403 w/
 * correlation_id, budget 402, rate limit 429, ...) are passed through
 * VERBATIM — status + body — so the client can render the real message
 * instead of a generic failure (spec §4, proof #3).
 */

import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

const MAX_BODY_BYTES = 32 * 1024;
const MAX_MAX_TOKENS = 2048;
const DEFAULT_MAX_TOKENS = 512;
const DEFAULT_TEMPERATURE = 0.2;
const GATEWAY_TIMEOUT_MS = 45_000;

interface PlaygroundRequestBody {
	model?: unknown;
	system?: unknown;
	prompt?: unknown;
	temperature?: unknown;
	max_tokens?: unknown;
}

function errorJson(status: number, error: string, message?: string) {
	return NextResponse.json(message ? { error, message } : { error }, {
		status,
	});
}

/** Clamp to `[1, 2048]`; a missing/invalid value falls back to the field default. */
function clampMaxTokens(raw: unknown): number {
	const n =
		typeof raw === "number" && Number.isFinite(raw) ? raw : DEFAULT_MAX_TOKENS;
	return Math.max(1, Math.min(MAX_MAX_TOKENS, Math.trunc(n)));
}

/** `[0, 2]` — the OpenAI-compatible range every adapter here accepts. */
function normalizeTemperature(raw: unknown): number {
	const n =
		typeof raw === "number" && Number.isFinite(raw) ? raw : DEFAULT_TEMPERATURE;
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

interface GatewayChoice {
	message?: { content?: string };
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

export async function POST(req: NextRequest): Promise<NextResponse> {
	// Defense-in-depth: unreachable anonymously even if the JWT check below is
	// ever misconfigured (same shape as prompts/[name]/promote).
	await requireSession();
	const { token } = await requireGatewayToken();

	// Read the raw body FIRST and measure it before parsing anything — the
	// 413 must fire before any gateway call, per spec §5.
	const raw = await req.text();
	if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) {
		return errorJson(
			413,
			"payload_too_large",
			"request body exceeds the 32 KB playground limit",
		);
	}

	let body: PlaygroundRequestBody;
	try {
		body = raw ? (JSON.parse(raw) as PlaygroundRequestBody) : {};
	} catch {
		return errorJson(400, "invalid_json", "request body is not valid JSON");
	}

	const model = typeof body.model === "string" ? body.model.trim() : "";
	if (!model) return errorJson(400, "model_required", "a model is required");

	const prompt = typeof body.prompt === "string" ? body.prompt.trim() : "";
	if (!prompt) return errorJson(400, "prompt_required", "a prompt is required");

	const system =
		typeof body.system === "string" && body.system.trim()
			? body.system.trim()
			: undefined;

	const maxTokens = clampMaxTokens(body.max_tokens);
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
			},
			body: JSON.stringify(gatewayBody),
			cache: "no-store",
			signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
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
