/**
 * PLT-22 — the trace-data seam between MCP tools and however traces are
 * actually read.
 *
 * Two implementations of `TraceReader`:
 *
 *   - **`GatewayReader`** (default, Cloud tenants): every read is an
 *     authenticated HTTP GET against `TRACELANE_GATEWAY_URL`'s existing
 *     tenant-scoped `/v1/*` routes (`crates/gateway/src/trace_reads.rs`).
 *     The gateway resolves `tenant_id` from the bearer's claims — this
 *     reader never sees or sends a tenant id itself. No new gateway route
 *     is introduced; a tool that cannot be served by an existing route
 *     narrows instead (see `getSpan`).
 *
 *   - **`ClickHouseReader`** (self-host, `CLICKHOUSE_URL` set): the exact
 *     SQL that lived inline in `tools/traces.ts` before PLT-22, moved here
 *     verbatim. `tenant_id` still comes only from `getTenantId()` (the
 *     auth-context seam in `auth.ts`), never from a tool argument.
 *
 * Mode selection (`createReader`): `CLICKHOUSE_URL` set -> ClickHouse;
 * unset -> gateway. No new env var — the presence of a ClickHouse URL IS
 * the self-host signal.
 *
 * Tools call the reader; no tool imports `getDb()` directly any more.
 */

import { getActiveBearer, getTenantId, validateGatewayUrl } from "./auth.js";
import { getDb } from "./db.js";

// ── Wire-shaped row types ────────────────────────────────────────────────
//
// Field names match the gateway's `TraceSummary` / `SpanRow` JSON exactly
// (`crates/gateway/src/trace_reads.rs:290-390` — no `#[serde(rename)]`
// anywhere in that file, so the Rust struct's field names ARE the wire
// contract) and match the ClickHouse column names the old SQL selected.
// One shape serves both readers.

export interface TraceSummaryLike {
	trace_id: string;
	root_name: string;
	start_time: string;
	duration_us: number;
	span_count: number;
	error_count: number;
	intervention: number;
	model: string;
	/** Gateway mode only (read-time cost rollup); absent in ClickHouse mode. */
	cost_usd?: number;
	/** Gateway mode only (read-time token rollup); absent in ClickHouse mode. */
	total_tokens?: number;
}

export interface SpanLike {
	span_id: string;
	parent_span_id: string | null;
	name: string;
	start_time: string;
	end_time: string;
	duration_us: number;
	status_code: number;
	status_message: string;
	/** Raw JSON string — parsed client-side by the tool, both modes. */
	attributes: string;
	aft_ids: string[];
	intervention: number;
}

/** ClickHouse-mode `search_traces` row — one per matched trace (unchanged shape). */
export interface SearchMatchRow {
	trace_id: string;
	matched_spans: number;
	first_match_time: string;
	first_match_span_id: string;
	first_match_name: string;
	max_status_code: number;
}

/** One row from the gateway's `GET /v1/guardrails/verdicts` (trace_reads.rs:1521). */
export interface GuardrailVerdictLike {
	correlation_id: string;
	side: string;
	decision: string;
	event_time: string;
	total_latency_micros: number;
	/** The per-rail verdict JSON array, as a string — parsed client-side. */
	rails: string;
	fail_open_rails: string[];
}

export interface ListTracesArgs {
	limit: number;
	modelFilter?: string;
	hasError?: boolean;
}

export interface SearchTracesArgs {
	query: string;
	modelFilter?: string;
	hasError?: boolean;
	limit: number;
}

/**
 * `search_traces` answers a genuinely different question per mode: the
 * ClickHouse SQL aggregates matching SPANS into one row per trace
 * (`matched_spans`, `first_match_*`); the gateway's `/v1/traces?q=` is the
 * same trace-LIST route content-filtered, so it returns trace summaries.
 * Tagging the result rather than forcing one shape keeps both honest.
 */
export type SearchTracesResult =
	| { source: "clickhouse_match"; matches: SearchMatchRow[] }
	| { source: "gateway_trace_list"; traces: TraceSummaryLike[] };

export interface GetSpanArgs {
	spanId: string;
	/**
	 * Required in gateway mode (no span-by-id gateway route — the span is
	 * picked out of `/v1/traces/{trace_id}/spans`). Optional in ClickHouse
	 * mode, where a bare `span_id` scan across the tenant's spans is a
	 * legitimate, pre-existing-shape query.
	 */
	traceId?: string;
}

/** Thrown by `GatewayReader` on a non-2xx gateway response. Tools catch this
 * and turn it into an MCP tool error (`isError: true`) carrying the status
 * and the gateway's own message verbatim — never an empty array. */
export class GatewayError extends Error {
	readonly status: number;
	constructor(status: number, message: string) {
		super(message);
		this.name = "GatewayError";
		this.status = status;
	}
}

/** Thrown for a caller mistake the reader itself can explain better than a
 * generic exception would (e.g. missing `trace_id` in gateway mode). Tools
 * catch this the same way as `GatewayError` (`isError: true`, no status). */
export class ToolInputError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ToolInputError";
	}
}

export interface TraceReader {
	readonly mode: "gateway" | "clickhouse";
	listTraces(args: ListTracesArgs): Promise<TraceSummaryLike[]>;
	getTraceSpans(traceId: string): Promise<SpanLike[]>;
	getSpan(args: GetSpanArgs): Promise<SpanLike | null>;
	searchTraces(args: SearchTracesArgs): Promise<SearchTracesResult>;
	/** Gateway-only capability: `GET /v1/guardrails/verdicts?correlation_id=`.
	 * `ClickHouseReader` throws `ToolInputError` — self-host has no reason to
	 * call it, since the ClickHouse-mode tool schema never exposes
	 * `correlation_id` in the first place. */
	explainGuardrailByCorrelationId(
		correlationId: string,
	): Promise<GuardrailVerdictLike[]>;
}

// ── GatewayReader ────────────────────────────────────────────────────────

/**
 * Reads through the gateway's existing tenant-scoped `/v1/*` routes.
 *
 * The bearer sent as `Authorization: Bearer <…>` depends on transport
 * (`bearer()`, via `getActiveBearer()` in `auth.ts`):
 *   - **HTTP transport:** the CALLER's own bearer, bound per request by
 *     `http.ts`'s `runWithTenant`. Two concurrent requests with different
 *     bearers each read as their own identity — never one shared key.
 *   - **Stdio:** no per-request context exists at all, so this falls back
 *     to the process's own `TRACELANE_API_KEY` — the same key
 *     `bootstrapStdioTenant` already validated at startup — read fresh from
 *     `process.env` on each call so a mid-process rotation is picked up.
 *   - **HTTP context present but no bearer bound:** fails CLOSED. Falling
 *     back to the env key here would be a cross-tenant read, not a caveat.
 */
export class GatewayReader implements TraceReader {
	readonly mode = "gateway" as const;
	private readonly baseUrl: string;

	constructor() {
		const raw = process.env.TRACELANE_GATEWAY_URL ?? "http://localhost:8080";
		const validation = validateGatewayUrl(raw);
		if (!validation.ok) {
			throw new Error(`TRACELANE_GATEWAY_URL is invalid: ${validation.reason}`);
		}
		this.baseUrl = validation.url.replace(/\/+$/, "");
	}

	/**
	 * The bearer to send with this call. PLT-22 cross-tenant-read fix:
	 * an active HTTP request context (`getActiveBearer`) — the CALLER's own
	 * validated bearer — always wins over the process's fixed
	 * `TRACELANE_API_KEY`. The env key is used ONLY when there is no
	 * request context at all (Stdio mode, a single-tenant subprocess).
	 *
	 * An HTTP context present with no bearer bound fails CLOSED here — it
	 * never falls back to the env key, because that fallback is exactly
	 * the cross-tenant read this method exists to prevent: an HTTP
	 * transport fronting more than one caller must never read gateway data
	 * as the identity of one fixed key on that caller's behalf.
	 */
	private bearer(): string {
		const active = getActiveBearer();
		if (active === undefined) {
			// Stdio: no per-request context at all.
			const key = process.env.TRACELANE_API_KEY;
			if (!key) {
				throw new Error(
					"TRACELANE_API_KEY is required in gateway mode (no CLICKHOUSE_URL is set, " +
						"so this server reads through the gateway).",
				);
			}
			return key;
		}
		if (active === null) {
			throw new ToolInputError(
				"no bearer token is bound to this HTTP request — refusing to read " +
					"gateway data as the server's own TRACELANE_API_KEY identity on " +
					"another caller's behalf.",
			);
		}
		return active;
	}

	/** GET `path?params`, returning the parsed JSON body. Throws
	 * `GatewayError` on any non-2xx response, carrying the gateway's own
	 * `{ "error": "…" }` message (`trace_reads.rs` `error_response`)
	 * verbatim so the tool layer never has to guess what went wrong. */
	private async getJson<T>(
		path: string,
		params?: Record<string, string | undefined>,
	): Promise<T> {
		const url = new URL(path, `${this.baseUrl}/`);
		if (params) {
			for (const [k, v] of Object.entries(params)) {
				if (v !== undefined && v !== "") url.searchParams.set(k, v);
			}
		}
		// Resolved BEFORE the network try/catch below, so a `ToolInputError` /
		// missing-env-var `Error` from bearer resolution propagates as itself —
		// never gets relabelled as a `GatewayError` "could not reach the
		// gateway", which is a different failure with a different fix.
		const bearer = this.bearer();
		let resp: Response;
		try {
			resp = await fetch(url, {
				method: "GET",
				headers: { authorization: `Bearer ${bearer}` },
				signal: AbortSignal.timeout(15_000),
			});
		} catch (err) {
			throw new GatewayError(
				0,
				`could not reach the gateway: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		if (!resp.ok) {
			let message = resp.statusText || `HTTP ${resp.status}`;
			try {
				const body = (await resp.json()) as { error?: string };
				if (body?.error) message = body.error;
			} catch {
				// Non-JSON error body — keep statusText.
			}
			throw new GatewayError(resp.status, message);
		}
		return (await resp.json()) as T;
	}

	async listTraces(args: ListTracesArgs): Promise<TraceSummaryLike[]> {
		const body = await this.getJson<{ traces: TraceSummaryLike[] }>(
			"v1/traces",
			{
				limit: String(args.limit),
				model: args.modelFilter,
				has_error:
					args.hasError === undefined ? undefined : String(args.hasError),
			},
		);
		return body.traces;
	}

	async getTraceSpans(traceId: string): Promise<SpanLike[]> {
		return this.getJson<SpanLike[]>(
			`v1/traces/${encodeURIComponent(traceId)}/spans`,
		);
	}

	async getSpan(args: GetSpanArgs): Promise<SpanLike | null> {
		if (!args.traceId) {
			throw new ToolInputError(
				"gateway mode has no span-by-id route — pass trace_id so the span " +
					"can be picked out of GET /v1/traces/{trace_id}/spans.",
			);
		}
		const spans = await this.getTraceSpans(args.traceId);
		return spans.find((s) => s.span_id === args.spanId) ?? null;
	}

	async searchTraces(args: SearchTracesArgs): Promise<SearchTracesResult> {
		const body = await this.getJson<{ traces: TraceSummaryLike[] }>(
			"v1/traces",
			{
				q: args.query,
				limit: String(args.limit),
				model: args.modelFilter,
				has_error:
					args.hasError === undefined ? undefined : String(args.hasError),
			},
		);
		return { source: "gateway_trace_list", traces: body.traces };
	}

	async explainGuardrailByCorrelationId(
		correlationId: string,
	): Promise<GuardrailVerdictLike[]> {
		const body = await this.getJson<{ verdicts: GuardrailVerdictLike[] }>(
			"v1/guardrails/verdicts",
			{ correlation_id: correlationId },
		);
		return body.verdicts;
	}
}

// ── ClickHouseReader ─────────────────────────────────────────────────────

/**
 * Self-host reader. Every query below is the same SQL that used to live
 * inline in `tools/traces.ts` — moved, not rewritten — plus one additive
 * capability `getSpan` never had: a `trace_id`-less lookup (session build
 * instruction, PLT-22 point 2). `tenant_id` still comes only from
 * `getTenantId()`, never from a tool argument.
 */
export class ClickHouseReader implements TraceReader {
	readonly mode = "clickhouse" as const;

	async listTraces(args: ListTracesArgs): Promise<TraceSummaryLike[]> {
		const tenantId = getTenantId();
		const db = getDb();

		let where = "WHERE tenant_id = {tenantId: String}";
		const params: Record<string, unknown> = {
			tenantId,
			limit: args.limit,
		};

		if (args.modelFilter) {
			where += " AND model = {model: String}";
			params.model = args.modelFilter;
		}
		if (args.hasError === true) {
			where += " AND error_count > 0";
		} else if (args.hasError === false) {
			where += " AND error_count = 0";
		}

		const result = await db.query({
			query: `
        SELECT
          trace_id,
          root_name,
          start_time,
          duration_us,
          span_count,
          error_count,
          intervention,
          model
        FROM tracelane.trace_summaries FINAL
        ${where}
        ORDER BY start_time DESC
        LIMIT {limit: UInt32}
      `,
			query_params: params,
			format: "JSONEachRow",
		});
		return result.json<TraceSummaryLike>();
	}

	async getTraceSpans(traceId: string): Promise<SpanLike[]> {
		const tenantId = getTenantId();
		const db = getDb();

		const result = await db.query({
			query: `
        SELECT
          span_id,
          parent_span_id,
          name,
          start_time,
          end_time,
          duration_us,
          status_code,
          status_message,
          attributes,
          aft_ids,
          intervention
        FROM tracelane.spans FINAL
        WHERE tenant_id = {tenantId: String}
          AND trace_id = {trace_id: String}
        ORDER BY start_time ASC
      `,
			query_params: { tenantId, trace_id: traceId },
			format: "JSONEachRow",
		});
		return result.json<SpanLike>();
	}

	async getSpan(args: GetSpanArgs): Promise<SpanLike | null> {
		const tenantId = getTenantId();
		const db = getDb();

		const where = args.traceId
			? "WHERE tenant_id = {tenantId: String} AND trace_id = {trace_id: String} AND span_id = {span_id: String}"
			: "WHERE tenant_id = {tenantId: String} AND span_id = {span_id: String}";
		const params: Record<string, unknown> = { tenantId, span_id: args.spanId };
		if (args.traceId) params.trace_id = args.traceId;

		const result = await db.query({
			query: `
        SELECT
          span_id,
          parent_span_id,
          name,
          start_time,
          end_time,
          duration_us,
          status_code,
          status_message,
          attributes,
          aft_ids,
          intervention
        FROM tracelane.spans FINAL
        ${where}
        LIMIT 1
      `,
			query_params: params,
			format: "JSONEachRow",
		});
		const rows = await result.json<SpanLike>();
		return rows[0] ?? null;
	}

	async searchTraces(args: SearchTracesArgs): Promise<SearchTracesResult> {
		const tenantId = getTenantId();
		const db = getDb();

		// Tenant isolation is structural and unconditional: the leading WHERE
		// clause is hard-coded, and tenantId comes from the auth context
		// (getTenantId), never from a tool argument. The search text is
		// parameter-bound — never concatenated into SQL.
		let where = "WHERE tenant_id = {tenantId: String}";
		const params: Record<string, unknown> = {
			tenantId,
			// `position(haystack, needle)` is case-sensitive in ClickHouse; we
			// lowercase both sides for a case-insensitive substring match.
			needle: args.query.toLowerCase(),
			limit: args.limit,
		};

		where +=
			" AND (position(lower(name), {needle: String}) > 0" +
			" OR position(lower(attributes), {needle: String}) > 0)";

		if (args.modelFilter) {
			where += " AND position(lower(attributes), {model: String}) > 0";
			params.model = args.modelFilter.toLowerCase();
		}
		if (args.hasError === true) {
			where += " AND status_code = 2";
		} else if (args.hasError === false) {
			where += " AND status_code != 2";
		}

		// Collapse matching spans to one row per trace so the caller gets
		// distinct traces. argMin picks the earliest-by-time span's fields as
		// the representative row for the matched trace.
		const result = await db.query({
			query: `
        SELECT
          trace_id,
          count() AS matched_spans,
          min(start_time) AS first_match_time,
          argMin(span_id, start_time) AS first_match_span_id,
          argMin(name, start_time) AS first_match_name,
          max(status_code) AS max_status_code
        FROM tracelane.spans FINAL
        ${where}
        GROUP BY trace_id
        ORDER BY first_match_time DESC
        LIMIT {limit: UInt32}
      `,
			query_params: params,
			format: "JSONEachRow",
		});
		const matches = await result.json<SearchMatchRow>();
		return { source: "clickhouse_match", matches };
	}

	async explainGuardrailByCorrelationId(): Promise<GuardrailVerdictLike[]> {
		throw new ToolInputError(
			"correlation_id lookup is a gateway-mode capability (GET " +
				"/v1/guardrails/verdicts) — ClickHouse mode explains a guardrail " +
				"flag from trace_id + span_id instead.",
		);
	}
}

// ── Mode selection ───────────────────────────────────────────────────────

/**
 * `CLICKHOUSE_URL` set -> self-host, read ClickHouse directly. Unset ->
 * Cloud tenant, read through the gateway. No new env var: the presence of
 * a ClickHouse URL IS the self-host signal (PLT-22 §2).
 */
export function createReader(): TraceReader {
	return process.env.CLICKHOUSE_URL
		? new ClickHouseReader()
		: new GatewayReader();
}
