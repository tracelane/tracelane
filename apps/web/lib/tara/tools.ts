/**
 * Tara's tool set — OBS-40 §2.
 *
 * A thin port of the MCP tool contracts (`apps/mcp/src/tools/traces.ts`,
 * `apps/mcp/src/reader.ts`) into a CLOSED set the chat loop in
 * `app/api/tara/route.ts` may call. **This file is the safety property, not
 * a convenience wrapper**: every tool is a zod-validated `GET` against a
 * gateway route that already exists (`crates/gateway/src/trace_reads.rs`),
 * scoped to the caller's tenant by the forwarded WorkOS JWT
 * (`requireGatewayToken`/`gatewayGet`, `lib/gateway.ts`). No tool schema has
 * a `tenant_id` field, none accepts free-form SQL or a free-form path, and
 * none writes anything — the model can only ask questions the gateway
 * already answers for the authenticated tenant.
 *
 * Field names match the gateway's REAL query params exactly (verified
 * against the `Deserialize` structs in `trace_reads.rs`), not the MCP
 * server's naming — where the two differ this file follows the gateway.
 *
 * Every argument object is validated with `schema.safeParse` BEFORE any
 * `fetch` happens (CLAUDE.md §21 — a tool call is a decision the loop acts
 * on, and it fails closed on a malformed one). A validation failure never
 * reaches `gatewayGet`; the loop turns it into a structured
 * `{ error: "invalid_arguments", issues }` tool result instead.
 *
 * ── THE WINDOWED TOOLS GO THROUGH `lib/metrics/`, NOT A HAND-BUILT URL ─────
 *
 * `list_sessions`, `cost_breakdown`, `slo_summary` and `guardrail_verdicts`
 * each read a WINDOWED gateway route, and `specs/metrics-renovation.md` §3c
 * is explicit that a windowed gateway URL is built in exactly one place:
 * `apps/web/lib/metrics/`. So these four call the existing
 * `fetchSessionsFor` / `fetchCostBreakdownFor` / `fetchSloSummary` /
 * `fetchGuardrailVerdictsFor` (`lib/metrics/fetch.ts`) instead of
 * constructing `/v1/sessions` etc. here — enforced by
 * `scripts/ci/check-metric-single-source.py`, which fails on a windowed URL
 * literal anywhere outside that directory. The model's `hours`/`days`
 * argument is converted to the shared `Win` (`sinceMs`/`untilMs`/`bucketMs`)
 * via `winForHours`/`winForDays` below, through `lib/metrics/time-range.ts`'s
 * own `parseTimeRange` — the ONE window parser — rather than a second
 * hand-rolled one. `list_traces`, `search_traces` and `get_trace` read
 * NON-windowed routes (no `since`/`until`/`hours` of their own — the
 * gateway's own `MIN_SEARCH_TERM`/id-length checks are the only bounds) and
 * are unaffected by §3c, so they keep a direct `gatewayGet` call.
 *
 * `fetchCostBreakdownFor` gained an optional third `scope` parameter in this
 * change (`lib/metrics/fetch.ts`) — it previously had no way to ask for
 * `production`/`eval` scope, which `cost_breakdown`'s schema needs.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";
import {
	fetchCostBreakdownFor,
	fetchGuardrailVerdictsFor,
	fetchSessionsFor,
	fetchSloSummary,
} from "@/lib/metrics/fetch";
import {
	MAX_SESSION_WINDOW_MS,
	type TimeRange,
	parseTimeRange,
} from "@/lib/metrics/time-range";
import { z } from "zod";

type Win = Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">;

/**
 * Convert a rolling `hours` argument into the shared `Win` shape, through
 * the ONE window parser (`parseTimeRange`) rather than re-deriving
 * `since`/bucket arithmetic here. `maxWidthMs` narrows the clamp for a
 * family with its own cap (sessions' 90 days vs. the general 720-hour cap).
 */
function winForHours(hours: number, maxWidthMs?: number): Win {
	const nowMs = Date.now();
	const since = new Date(nowMs - hours * 3_600_000).toISOString();
	return parseTimeRange({ since }, { defaultPreset: "24h", nowMs, maxWidthMs });
}

/**
 * The sessions route is capped in DAYS, not hours — converted through the
 * same parser, clamped to the session family's own (wider) cap.
 */
function winForDays(days: number): Win {
	return winForHours(days * 24, MAX_SESSION_WINDOW_MS);
}

/** Row caps kept LOW deliberately (spec §5) — these are context fed to a
 * model with an 800-token answer budget, not a dashboard page. */
const LIST_LIMIT = z.number().int().min(1).max(50).default(20);
const VERDICT_LIMIT = z.number().int().min(1).max(100).default(20);

/**
 * Trace ids are gateway-generated UUIDs (`trace_context.rs`) or, for older
 * ClickHouse rows, an opaque hex-ish token — either way, alnum + dash only.
 * This is the schema gate the spec's path-traversal proof exercises: a value
 * like `../../etc/passwd` fails the charset before it is ever interpolated
 * into a gateway URL path segment.
 */
const traceIdSchema = z
	.string()
	.min(8, "trace_id must be at least 8 characters")
	.max(64, "trace_id is too long")
	.regex(/^[a-zA-Z0-9-]+$/, "trace_id may only contain letters, digits and -");

const modelFilterSchema = z
	.string()
	.min(1)
	.max(128)
	.optional()
	.describe("Filter by model name substring, e.g. claude-sonnet-4-6");

/** `since`/`until` are intentionally NOT exposed — every tool here uses a
 * bounded rolling window (`hours`/`days`/`limit`) instead, which keeps the
 * closed set small and every result naturally bounded in size. */
const hoursSchema = z
	.number()
	.int()
	.min(1)
	.max(720)
	.default(24)
	.describe(
		"Rolling look-back window in hours (gateway caps at 720 = 30 days)",
	);

export interface ToolDefinition<Args> {
	/** OpenAI-style function name — must match `functionSchemas` below. */
	name: string;
	description: string;
	schema: z.ZodType<Args>;
	/** The OpenAI-wire JSON Schema for this tool's parameters. Hand-written
	 * rather than derived, so the wire shape sent to the model is exactly
	 * what `schema` will accept — no generator drift between the two. */
	parameters: Record<string, unknown>;
	/** Run a validated args object and return the raw result. The gateway
	 * resolves tenant_id from the JWT `gatewayGet` (or the shared
	 * `lib/metrics/fetch.ts` readers, which wrap it) forward — this function
	 * never sees or needs one. Resolves to `null` when the underlying read
	 * was reachable-but-failed via the shared metrics layer's `orNull`
	 * contract (`lib/metrics/fetch.ts`); `runTaraTool` turns that into a
	 * `gateway_error` result the same as a thrown `GatewayError`. */
	execute: (args: Args) => Promise<unknown>;
}

function qs(
	params: Record<string, string | number | boolean | undefined>,
): string {
	const sp = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) {
		if (v !== undefined && v !== "") sp.set(k, String(v));
	}
	const s = sp.toString();
	return s ? `?${s}` : "";
}

// ── list_traces — GET /v1/traces ────────────────────────────────────────────

const listTracesSchema = z.object({
	limit: LIST_LIMIT,
	model: modelFilterSchema,
	has_error: z
		.boolean()
		.optional()
		.describe("Filter to traces with at least one error span"),
});
type ListTracesArgs = z.infer<typeof listTracesSchema>;

// ── search_traces — GET /v1/traces?q= ───────────────────────────────────────

const searchTracesSchema = z.object({
	q: z
		.string()
		.min(4, "search term must be at least 4 characters (gateway minimum)")
		.max(256),
	limit: LIST_LIMIT,
	model: modelFilterSchema,
	has_error: z.boolean().optional(),
});
type SearchTracesArgs = z.infer<typeof searchTracesSchema>;

// ── get_trace — GET /v1/traces/{trace_id}/spans ─────────────────────────────

const getTraceSchema = z.object({ trace_id: traceIdSchema });
type GetTraceArgs = z.infer<typeof getTraceSchema>;

// ── list_sessions — GET /v1/sessions ────────────────────────────────────────

const listSessionsSchema = z.object({
	limit: LIST_LIMIT,
	days: z.number().int().min(1).max(90).default(30),
	status: z.enum(["error", "ok"]).optional(),
	model: modelFilterSchema,
	sort: z.enum(["turns", "cost", "tokens", "duration"]).optional(),
	order: z.enum(["asc", "desc"]).optional(),
});
type ListSessionsArgs = z.infer<typeof listSessionsSchema>;

// ── cost_breakdown — GET /v1/costs ──────────────────────────────────────────

const costBreakdownSchema = z.object({
	hours: hoursSchema,
	by: z.enum(["key", "model", "provider"]).default("model"),
	scope: z.enum(["all", "production", "eval"]).default("all"),
});
type CostBreakdownArgs = z.infer<typeof costBreakdownSchema>;

// ── slo_summary — GET /v1/slo/summary ───────────────────────────────────────

const sloSummarySchema = z.object({
	hours: hoursSchema,
	provider: z.string().min(1).max(64).optional(),
	model: modelFilterSchema,
});
type SloSummaryArgs = z.infer<typeof sloSummarySchema>;

// ── guardrail_verdicts — GET /v1/guardrails/verdicts ────────────────────────

const guardrailVerdictsSchema = z.object({
	hours: hoursSchema,
	limit: VERDICT_LIMIT,
	decision: z.enum(["allow", "block", "redact", "warn"]).optional(),
	/** ULID, 26 Crockford-base32 chars — matches the gateway's own validator
	 * (`parse_correlation_id_filter`, trace_reads.rs). */
	correlation_id: z
		.string()
		.regex(/^[0-9A-Za-z]{26}$/, "correlation_id must be a 26-character ULID")
		.optional(),
	/** `[A-Za-z0-9_]{1,40}` — the gateway's own `parse_rail_filter`. */
	rail: z
		.string()
		.regex(
			/^[A-Za-z0-9_]{1,40}$/,
			"rail must be alnum/underscore, max 40 chars",
		)
		.optional(),
});
type GuardrailVerdictsArgs = z.infer<typeof guardrailVerdictsSchema>;

// ── the closed registry ──────────────────────────────────────────────────

/** biome-ignore lint/suspicious/noExplicitAny: the registry is heterogeneous
 * over each tool's own arg type; every access goes through `getTool`, which
 * re-establishes the type via the generic. */
type AnyToolDefinition = ToolDefinition<any>;

export const TARA_TOOLS: readonly AnyToolDefinition[] = [
	{
		name: "list_traces",
		description:
			"List recent traces for the authenticated tenant, most recent first.",
		schema: listTracesSchema,
		parameters: {
			type: "object",
			properties: {
				limit: {
					type: "integer",
					minimum: 1,
					maximum: 50,
					description: "Maximum traces to return (1-50, default 20)",
				},
				model: {
					type: "string",
					description: "Filter by model name substring",
				},
				has_error: {
					type: "boolean",
					description: "Filter to traces with at least one error span",
				},
			},
		},
		execute: (a: ListTracesArgs) =>
			gatewayGet<unknown>(
				`/v1/traces${qs({ limit: a.limit, model: a.model, has_error: a.has_error })}`,
			),
	},
	{
		name: "search_traces",
		description:
			"Search traces by free-text substring across span names and attributes " +
			"(model names, prompts, tool names). Requires at least 4 characters.",
		schema: searchTracesSchema,
		parameters: {
			type: "object",
			properties: {
				q: {
					type: "string",
					minLength: 4,
					description: "Case-insensitive substring to search for (min 4 chars)",
				},
				limit: { type: "integer", minimum: 1, maximum: 50 },
				model: { type: "string", description: "Restrict to this model" },
				has_error: { type: "boolean" },
			},
			required: ["q"],
		},
		execute: (a: SearchTracesArgs) =>
			gatewayGet<unknown>(
				`/v1/traces${qs({ q: a.q, limit: a.limit, model: a.model, has_error: a.has_error })}`,
			),
	},
	{
		name: "get_trace",
		description: "Get all spans for one specific trace by its trace_id.",
		schema: getTraceSchema,
		parameters: {
			type: "object",
			properties: {
				trace_id: { type: "string", description: "The trace ID to fetch" },
			},
			required: ["trace_id"],
		},
		execute: (a: GetTraceArgs) =>
			gatewayGet<unknown>(`/v1/traces/${encodeURIComponent(a.trace_id)}/spans`),
	},
	{
		name: "list_sessions",
		description:
			"List recent conversation sessions (multi-turn threads) for the tenant, " +
			"with cost, token and turn-count rollups.",
		schema: listSessionsSchema,
		parameters: {
			type: "object",
			properties: {
				limit: { type: "integer", minimum: 1, maximum: 50 },
				days: {
					type: "integer",
					minimum: 1,
					maximum: 90,
					description: "Look-back window in days (default 30)",
				},
				status: { type: "string", enum: ["error", "ok"] },
				model: { type: "string" },
				sort: {
					type: "string",
					enum: ["turns", "cost", "tokens", "duration"],
					description: "Default sorts by most recent activity",
				},
				order: { type: "string", enum: ["asc", "desc"] },
			},
		},
		execute: (a: ListSessionsArgs) =>
			fetchSessionsFor(winForDays(a.days), {
				limit: a.limit,
				status: a.status,
				model: a.model,
				sort: a.sort,
				order: a.order,
			}),
	},
	{
		name: "cost_breakdown",
		description:
			"Spend attributed by API key, model or provider over a rolling window.",
		schema: costBreakdownSchema,
		parameters: {
			type: "object",
			properties: {
				hours: { type: "integer", minimum: 1, maximum: 720 },
				by: { type: "string", enum: ["key", "model", "provider"] },
				scope: { type: "string", enum: ["all", "production", "eval"] },
			},
		},
		execute: (a: CostBreakdownArgs) =>
			fetchCostBreakdownFor(winForHours(a.hours), a.by, a.scope),
	},
	{
		name: "slo_summary",
		description:
			"Latency (p50/p95/p99), error rate and volume summary over a rolling window, " +
			"optionally scoped to one provider or model.",
		schema: sloSummarySchema,
		parameters: {
			type: "object",
			properties: {
				hours: { type: "integer", minimum: 1, maximum: 720 },
				provider: { type: "string" },
				model: { type: "string" },
			},
		},
		execute: (a: SloSummaryArgs) =>
			fetchSloSummary(winForHours(a.hours), {
				provider: a.provider,
				model: a.model,
			}),
	},
	{
		name: "guardrail_verdicts",
		description:
			"Recent guardrail decisions (allow/block/redact/warn) for the tenant, " +
			"optionally filtered by decision, rail id or a correlation_id from a " +
			"403 block response body.",
		schema: guardrailVerdictsSchema,
		parameters: {
			type: "object",
			properties: {
				hours: { type: "integer", minimum: 1, maximum: 720 },
				limit: { type: "integer", minimum: 1, maximum: 100 },
				decision: {
					type: "string",
					enum: ["allow", "block", "redact", "warn"],
				},
				correlation_id: { type: "string", description: "26-character ULID" },
				rail: { type: "string", description: "e.g. R4_trifecta" },
			},
		},
		execute: (a: GuardrailVerdictsArgs) =>
			fetchGuardrailVerdictsFor(winForHours(a.hours), {
				decision: a.decision,
				correlationId: a.correlation_id,
				rail: a.rail,
				limit: a.limit,
			}),
	},
] as const;

/** Runtime assertion, not just a doc comment: the closed set never grows a
 * `tenant_id` field. A test asserts this over the registry (§7 proof 3) —
 * this is the production-path guard the test exercises. */
export function assertNoTenantIdField(): void {
	for (const tool of TARA_TOOLS) {
		const shape = (tool.schema as z.ZodObject<z.ZodRawShape>).shape;
		if (shape && Object.hasOwn(shape, "tenant_id")) {
			throw new Error(
				`tool ${tool.name} must never accept a tenant_id argument`,
			);
		}
	}
}

/** The tool definitions in OpenAI's `tools` wire shape, for the chat request
 * body (`ChatRequest.tools` accepts this shape verbatim — B-258). */
export function toolWireDefinitions(): Array<{
	type: "function";
	function: {
		name: string;
		description: string;
		parameters: Record<string, unknown>;
	};
}> {
	return TARA_TOOLS.map((t) => ({
		type: "function" as const,
		function: {
			name: t.name,
			description: t.description,
			parameters: t.parameters,
		},
	}));
}

export type ToolRunResult =
	| { ok: true; result: unknown }
	| { ok: false; error: { error: "invalid_arguments"; issues: string[] } }
	| { ok: false; error: { error: "unknown_tool"; name: string } }
	| {
			ok: false;
			error: { error: "gateway_error"; status: number; message: string };
	  };

/**
 * Validate `rawArgs` against the named tool's schema and, on success, run
 * it. On a validation failure the tool is NEVER dispatched — `fetch` is
 * unreachable from this branch (CLAUDE.md §21, spec proof #2).
 */
export async function runTaraTool(
	name: string,
	rawArgs: unknown,
): Promise<ToolRunResult> {
	const tool = TARA_TOOLS.find((t) => t.name === name);
	if (!tool) {
		return { ok: false, error: { error: "unknown_tool", name } };
	}
	const parsed = tool.schema.safeParse(rawArgs ?? {});
	if (!parsed.success) {
		return {
			ok: false,
			error: {
				error: "invalid_arguments",
				issues: parsed.error.issues.map(
					(i) => `${i.path.join(".") || "(root)"}: ${i.message}`,
				),
			},
		};
	}
	try {
		const result = await tool.execute(parsed.data);
		// The four `lib/metrics/fetch.ts` readers (list_sessions,
		// cost_breakdown, slo_summary, guardrail_verdicts) resolve `null`
		// rather than throwing on an unreachable gateway (`orNull`) — turn
		// that into the same shape a thrown `GatewayError` produces below,
		// so the loop's caller never has to know which of the two happened.
		if (result === null) {
			return {
				ok: false,
				error: {
					error: "gateway_error",
					status: 502,
					message: "the gateway was unreachable for this read",
				},
			};
		}
		return { ok: true, result };
	} catch (err) {
		if (err instanceof GatewayError) {
			return {
				ok: false,
				error: {
					error: "gateway_error",
					status: err.status,
					message: err.message,
				},
			};
		}
		throw err;
	}
}

export const TARA_TOOL_NAMES: readonly string[] = TARA_TOOLS.map((t) => t.name);

/**
 * Derive citation chips MECHANICALLY from a tool result, never from the
 * model's prose. Every gateway response shape that carries a trace id uses
 * the literal key `trace_id` (`TraceSummary`, `SpanLike`,
 * `SessionTracesResponse.traces[]`, `GuardrailVerdictLike` has none) — so a
 * shallow recursive scan for that key, deduped and capped, is a reliable
 * "what did we actually read" trail without asking the model to format one
 * (which it could get wrong or invent).
 */
export function extractTraceIdCitations(
	value: unknown,
	seen: Set<string> = new Set(),
	max = 6,
): Array<{ trace_id: string; label: string }> {
	const out: Array<{ trace_id: string; label: string }> = [];
	function walk(v: unknown): void {
		if (out.length >= max || v === null || v === undefined) return;
		if (Array.isArray(v)) {
			for (const item of v) {
				if (out.length >= max) return;
				walk(item);
			}
			return;
		}
		if (typeof v !== "object") return;
		const obj = v as Record<string, unknown>;
		const id = obj.trace_id;
		if (typeof id === "string" && id.length > 0 && !seen.has(id)) {
			seen.add(id);
			const model = typeof obj.model === "string" ? obj.model : undefined;
			out.push({
				trace_id: id,
				label: model ? `${id.slice(0, 8)}… (${model})` : `${id.slice(0, 8)}…`,
			});
		}
		for (const val of Object.values(obj)) {
			if (out.length >= max) return;
			walk(val);
		}
	}
	walk(value);
	return out;
}
