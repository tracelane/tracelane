/**
 * tlane trace <id> — fetch a trace from the Tracelane API and render it.
 *
 * Performs a real HTTP GET against `<endpoint>/api/traces/<id>` (tenant auth
 * via the API key header) and renders the result as json, a table, or a
 * timeline. The fetch implementation is injectable so the renderer + request
 * shape are unit-tested without a live server.
 */

import process from "node:process";
import type { Command } from "commander";

export interface TraceSpan {
	span_id?: string;
	name?: string;
	start_time?: string | number;
	duration_us?: number;
	status_code?: number;
}

export interface TraceFetchOptions {
	endpoint: string;
	traceId: string;
	apiKey?: string;
	fetchImpl?: typeof fetch;
}

/** Fetch a trace as parsed JSON. Throws on a non-2xx response. */
export async function fetchTrace(opts: TraceFetchOptions): Promise<unknown> {
	const f = opts.fetchImpl ?? fetch;
	const base = opts.endpoint.replace(/\/$/, "");
	const url = `${base}/api/traces/${encodeURIComponent(opts.traceId)}`;
	const headers: Record<string, string> = {};
	if (opts.apiKey) headers["x-tracelane-api-key"] = opts.apiKey;
	const res = await f(url, { headers });
	if (!res.ok) {
		throw new Error(`trace fetch failed: HTTP ${res.status}`);
	}
	return res.json();
}

/** Render a fetched trace as `json`, `table`, or `timeline` (pure). */
export function renderTrace(trace: unknown, format: string): string {
	if (format === "json") return JSON.stringify(trace, null, 2);

	const obj = (trace ?? {}) as Record<string, unknown>;
	const spans = Array.isArray(obj.spans) ? (obj.spans as TraceSpan[]) : [];
	if (spans.length === 0) return "(no spans in trace)";

	if (format === "timeline") {
		const maxDur = Math.max(1, ...spans.map((s) => Number(s.duration_us ?? 0)));
		return spans
			.map((s) => {
				const dur = Number(s.duration_us ?? 0);
				const bars = Math.max(1, Math.round((dur / maxDur) * 30));
				return `${"█".repeat(bars).padEnd(30)} ${(s.name ?? "?").padEnd(28)} ${(dur / 1000).toFixed(1)}ms`;
			})
			.join("\n");
	}

	// table (default)
	const header = `${"SPAN".padEnd(20)} ${"NAME".padEnd(28)} ${"DUR(ms)".padStart(9)}  STATUS`;
	const rows = spans.map((s) => {
		const id = (s.span_id ?? "").slice(0, 18).padEnd(20);
		const name = (s.name ?? "?").slice(0, 26).padEnd(28);
		const dur = (Number(s.duration_us ?? 0) / 1000).toFixed(1).padStart(9);
		const status = Number(s.status_code ?? 0) === 0 ? "OK" : "ERROR";
		return `${id} ${name} ${dur}  ${status}`;
	});
	return [header, ...rows].join("\n");
}

export function registerTraceCommand(program: Command): void {
	program
		.command("trace <traceId>")
		.description("Fetch and display a trace")
		.option(
			"--endpoint <url>",
			"Tracelane API base URL",
			"https://app.tracelane.dev",
		)
		.option("--format <fmt>", "Output format: json|table|timeline", "table")
		.option("--api-key <key>", "Tracelane API key (or TRACELANE_API_KEY)")
		.action(async (traceId: string, opts) => {
			try {
				const trace = await fetchTrace({
					endpoint: opts.endpoint,
					traceId,
					apiKey: opts.apiKey ?? process.env.TRACELANE_API_KEY,
				});
				console.log(renderTrace(trace, opts.format));
			} catch (e) {
				console.error(String(e));
				process.exit(1);
			}
		});
}
