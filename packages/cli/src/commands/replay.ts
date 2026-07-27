/**
 * tlane replay — time-travel debugger CLI.
 *
 * Fetches a trace's spans from the Tracelane gateway and renders them in the
 * terminal as an ordered table. JSON output is also supported for piping into
 * other tools.
 *
 * (NOT the old dashboard `/api/traces/{id}/steps` route, which doesn't exist on
 * the gateway and required a browser session). Auth aligns with the modern
 * `tlane` family — `Authorization: Bearer <jwt|tlane_apikey>` — and the spans
 * are mapped to `TraceStep[]` client-side (same shape the dashboard's
 * TimeTravelDebugger consumes).
 *
 * Usage:
 *   tlane replay <traceId>
 *   tlane replay <traceId> --format json
 *   tlane replay <traceId> --endpoint https://gateway.tracelane.dev
 *
 * Environment:
 *   TRACELANE_GATEWAY_URL — gateway base URL (overridable with --endpoint;
 *                           TRACELANE_ENDPOINT still honored for back-compat)
 *   TRACELANE_TOKEN       — Bearer token: JWT or `tlane_` API key (overridable
 *                           with --token; TRACELANE_API_KEY honored too)
 */

import process from "node:process";
import type { Command } from "commander";

/** One step rendered by `tlane replay` — derived from a gateway span. */
export interface TraceStep {
	index: number;
	spanId: string;
	name: string;
	startTimeUs: number;
	durationUs: number;
	llmMessage?: { role: string; content: string };
	attributes?: Record<string, string | number | boolean>;
}

/** Span shape returned by the gateway `GET /v1/traces/{id}/spans` endpoint. */
export interface GatewaySpan {
	span_id: string;
	name: string;
	start_time_us: number;
	duration_us: number;
	attributes: string;
}

/**
 * Fetch spans for a trace from the gateway. Returns `[]` on a 404 (trace
 * missing OR not this tenant's — the gateway returns the same 404 for both),
 * throws on any other non-2xx. `fetchImpl` is injectable for tests.
 */
export async function fetchSpans(
	traceId: string,
	endpoint: string,
	token: string,
	fetchImpl: typeof fetch = fetch,
): Promise<GatewaySpan[]> {
	const base = endpoint.replace(/\/$/, "");
	const url = `${base}/v1/traces/${encodeURIComponent(traceId)}/spans`;
	const headers: Record<string, string> = { Accept: "application/json" };
	if (token) headers.Authorization = `Bearer ${token}`;

	const res = await fetchImpl(url, { headers });
	if (res.status === 404) return [];
	if (!res.ok) {
		throw new Error(`HTTP ${res.status} from ${url}`);
	}
	return res.json() as Promise<GatewaySpan[]>;
}

/**
 * Map gateway spans to `TraceStep[]`, extracting the first LLM output message
 * and the scalar attributes (mirrors the dashboard `/api/traces/[id]/steps`
 * transform so `replay` output is stable across the gateway repoint).
 */
export function mapSpansToSteps(spans: GatewaySpan[]): TraceStep[] {
	return spans.map((span, index) => {
		let attrs: Record<string, unknown> = {};
		try {
			attrs = JSON.parse(span.attributes) as Record<string, unknown>;
		} catch {
			// leave empty
		}

		const outputMessages = attrs["llm.output_messages"];
		let llmMessage: { role: string; content: string } | undefined;
		if (Array.isArray(outputMessages) && outputMessages.length > 0) {
			const msg = outputMessages[0] as Record<string, unknown>;
			if (msg && typeof msg["message.content"] === "string") {
				llmMessage = {
					role: String(msg["message.role"] ?? "assistant"),
					content: msg["message.content"],
				};
			}
		}

		const flatAttrs: Record<string, string | number | boolean> = {};
		for (const [k, v] of Object.entries(attrs)) {
			if (
				typeof v === "string" ||
				typeof v === "number" ||
				typeof v === "boolean"
			) {
				flatAttrs[k] = v;
			}
		}

		return {
			index,
			spanId: span.span_id,
			name: span.name,
			startTimeUs: span.start_time_us,
			durationUs: span.duration_us,
			...(llmMessage !== undefined && { llmMessage }),
			attributes: flatAttrs,
		};
	});
}

function renderTable(traceId: string, steps: TraceStep[]): void {
	console.log(`\nTrace: ${traceId}`);
	console.log(`Steps: ${steps.length}\n`);
	console.log(
		"  #    Span ID           Name                            Duration",
	);
	console.log(
		"  ──── ──────────────── ─────────────────────────────── ──────────",
	);

	for (const step of steps) {
		const idx = String(step.index + 1).padStart(4);
		const spanId = step.spanId.slice(0, 16).padEnd(16);
		const name = step.name.slice(0, 31).padEnd(31);
		const dur = `${(step.durationUs / 1000).toFixed(1)}ms`.padStart(10);
		console.log(`  ${idx} ${spanId} ${name} ${dur}`);

		if (step.llmMessage) {
			const preview = step.llmMessage.content.slice(0, 72).replace(/\n/g, " ");
			const ellipsis = step.llmMessage.content.length > 72 ? "…" : "";
			console.log(
				`       [${step.llmMessage.role.padEnd(9)}] ${preview}${ellipsis}`,
			);
		}
	}

	console.log();
}

export function registerReplayCommand(program: Command): void {
	program
		.command("replay <traceId>")
		.description("Replay a trace step-by-step (time-travel debugging)")
		.option("--format <fmt>", "Output format: table|json", "table")
		.option(
			"--endpoint <url>",
			"Tracelane gateway URL",
			process.env.TRACELANE_GATEWAY_URL ??
				process.env.TRACELANE_ENDPOINT ??
				"https://gateway.tracelane.dev",
		)
		.option(
			"--token <token>",
			"Bearer token: JWT or tlane_ API key (or set TRACELANE_TOKEN)",
			process.env.TRACELANE_TOKEN ?? "",
		)
		.option(
			"--api-key <key>",
			"Deprecated alias of --token (or set TRACELANE_API_KEY)",
			process.env.TRACELANE_API_KEY ?? "",
		)
		.action(
			async (
				traceId: string,
				opts: {
					format: string;
					endpoint: string;
					token: string;
					apiKey: string;
				},
			) => {
				const token = opts.token || opts.apiKey;
				let steps: TraceStep[];
				try {
					const spans = await fetchSpans(traceId, opts.endpoint, token);
					steps = mapSpansToSteps(spans);
				} catch (err) {
					console.error(`Error: ${String(err)}`);
					process.exit(1);
				}

				if (steps.length === 0) {
					console.error(`No steps found for trace ${traceId}`);
					process.exit(1);
				}

				if (opts.format === "json") {
					console.log(JSON.stringify(steps, null, 2));
					return;
				}

				renderTable(traceId, steps);
			},
		);
}
