/**
 * MCP tools for reading trace data.
 *
 * All tools are READ-ONLY and read through a `TraceReader` (`../reader.js`)
 * — never `getDb()` directly (PLT-22). Two readers exist:
 *
 *   - `GatewayReader` (Cloud tenants, default): every call is an HTTP GET
 *     against the gateway's existing tenant-scoped `/v1/*` routes. The
 *     gateway resolves `tenant_id` from the bearer's claims server-side —
 *     no tenant id is ever sent or held by this file.
 *   - `ClickHouseReader` (self-host, `CLICKHOUSE_URL` set): parameter-bound
 *     SQL, `tenant_id` from `getTenantId()` (never a tool argument).
 *
 * A non-2xx gateway response becomes an MCP tool error (`isError: true`)
 * carrying the gateway's own status + message verbatim — never an empty
 * array (a cross-tenant or missing trace reads back as an error, not `[]`).
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
	GatewayError,
	type SpanLike,
	ToolInputError,
	type TraceReader,
} from "../reader.js";

type ToolContent = { type: "text"; text: string };
type ToolResult = { content: ToolContent[]; isError?: true };

function textResult(payload: unknown): ToolResult {
	return { content: [{ type: "text", text: JSON.stringify(payload) }] };
}

/**
 * Turn a thrown `GatewayError` / `ToolInputError` / anything else into an
 * MCP tool error. A gateway 401/403/404/etc. is surfaced with its real
 * status and the gateway's own message — never silently swallowed into an
 * empty result (the class of bug §4 of the spec exists to prevent).
 */
function toolErrorResult(err: unknown): ToolResult {
	if (err instanceof GatewayError) {
		return {
			content: [
				{
					type: "text",
					text: JSON.stringify({ error: err.message, status: err.status }),
				},
			],
			isError: true,
		};
	}
	if (err instanceof ToolInputError) {
		return {
			content: [{ type: "text", text: JSON.stringify({ error: err.message }) }],
			isError: true,
		};
	}
	const message = err instanceof Error ? err.message : String(err);
	return {
		content: [{ type: "text", text: JSON.stringify({ error: message }) }],
		isError: true,
	};
}

function safeParseJson(raw: string): unknown {
	try {
		return JSON.parse(raw);
	} catch {
		return { raw };
	}
}

/** AFT taxonomy short descriptions — expanded in V2 via DB join. Shared by
 * both the ClickHouse-mode and gateway-mode span-flag explanation path,
 * since `SpanRow` carries `aft_ids` / `intervention` in both modes
 * (`crates/gateway/src/trace_reads.rs:387-398`). */
const AFT_DESCRIPTIONS: Record<string, string> = {
	"AF-01": "Prompt injection — attempt to override system prompt",
	"AF-02": "Data exfiltration — attempt to extract sensitive data",
	"AF-03": "Tool misuse — calling a tool outside its declared intent",
	"AF-04":
		"Scope escalation — agent requesting permissions beyond declared scope",
	"AF-05": "Lethal trifecta — exfiltrate + execute + persist pattern",
	"AF-13":
		"Missing system prompt boundary — unguarded user content in system role",
};

function formatSpanAftFlag(
	traceId: string,
	spanId: string,
	span: SpanLike | null,
): ToolResult {
	if (!span) {
		return textResult({
			error: "Span not found",
			trace_id: traceId,
			span_id: spanId,
		});
	}
	const interventionLabel =
		span.intervention === 2
			? "block"
			: span.intervention === 1
				? "warn"
				: "none";
	const descriptions = span.aft_ids.map(
		(id) => AFT_DESCRIPTIONS[id] ?? `${id} — see AFT taxonomy docs`,
	);
	return textResult({
		trace_id: traceId,
		span_id: spanId,
		intervention: interventionLabel,
		aft_ids: span.aft_ids,
		aft_descriptions: descriptions,
		recommendation: span.aft_ids.includes("AF-13")
			? "Add a system prompt boundary to separate user content from system instructions."
			: "Review span attributes for the triggering AFT pattern and tighten the agent's tool permissions.",
	});
}

/** Explain a detection-layer (AFT) flag on one recorded span. Identical
 * lookup + formatting in both modes — the AFT signal lives on the span
 * itself, which both readers expose via `getSpan`. */
async function explainSpanAftFlag(
	reader: TraceReader,
	traceId: string,
	spanId: string,
): Promise<ToolResult> {
	const span = await reader.getSpan({ spanId, traceId });
	return formatSpanAftFlag(traceId, spanId, span);
}

export function registerTraceTools(server: McpServer, reader: TraceReader) {
	server.tool(
		"list_traces",
		"List recent traces for the authenticated tenant",
		{
			limit: z
				.number()
				.min(1)
				.max(100)
				.default(20)
				.describe("Maximum traces to return (1-100)"),
			model_filter: z
				.string()
				.optional()
				.describe("Filter by model name, e.g. claude-sonnet-4-6"),
			has_error: z
				.boolean()
				.optional()
				.describe("Filter to traces with at least one error span"),
		},
		async ({ limit, model_filter, has_error }) => {
			try {
				const traces = await reader.listTraces({
					limit,
					modelFilter: model_filter,
					hasError: has_error,
				});
				return textResult({ traces, count: traces.length });
			} catch (err) {
				return toolErrorResult(err);
			}
		},
	);

	server.tool(
		"get_trace",
		"Get all spans for a specific trace",
		{
			trace_id: z.string().describe("The trace ID to fetch"),
		},
		async ({ trace_id }) => {
			try {
				const spans = await reader.getTraceSpans(trace_id);
				return textResult({ trace_id, spans, span_count: spans.length });
			} catch (err) {
				return toolErrorResult(err);
			}
		},
	);

	const getSpanDescription =
		reader.mode === "gateway"
			? "Get details for a specific span including all LLM attributes. " +
				"trace_id is REQUIRED in Cloud (gateway) mode — there is no " +
				"span-by-id gateway route, so the span is located via GET " +
				"/v1/traces/{trace_id}/spans."
			: "Get details for a specific span including all LLM attributes. " +
				"trace_id narrows a self-host (ClickHouse) lookup but is optional.";

	server.tool(
		"get_span",
		getSpanDescription,
		{
			trace_id: z
				.string()
				.optional()
				.describe(
					reader.mode === "gateway"
						? "The trace ID (required — see tool description)."
						: "The trace ID (optional; narrows the lookup).",
				),
			span_id: z.string().describe("The span ID"),
		},
		async ({ trace_id, span_id }) => {
			try {
				const span = await reader.getSpan({
					spanId: span_id,
					traceId: trace_id,
				});
				if (!span) {
					return textResult({ error: "Span not found", trace_id, span_id });
				}
				let parsedAttributes: unknown = {};
				try {
					parsedAttributes = JSON.parse(span.attributes);
				} catch {
					parsedAttributes = { raw: span.attributes };
				}
				return textResult({ ...span, attributes: parsedAttributes });
			} catch (err) {
				return toolErrorResult(err);
			}
		},
	);

	server.tool(
		"search_traces",
		"Search traces by free-text substring across span names and the " +
			"attributes JSON blob, optionally narrowed by model name or error " +
			"status. Read-only; tenant-scoped. In gateway (Cloud) mode the " +
			"gateway rejects a search term shorter than 4 characters.",
		{
			query: z
				.string()
				.min(1)
				.max(256)
				.describe(
					"Case-insensitive substring matched against span name and the " +
						"attributes JSON (model names, prompts, tool names, etc.). " +
						"Gateway mode requires at least 4 characters.",
				),
			model_filter: z
				.string()
				.optional()
				.describe("Restrict to spans whose attributes mention this model"),
			has_error: z
				.boolean()
				.optional()
				.describe("Restrict to error spans (status_code = 2) when true"),
			limit: z
				.number()
				.min(1)
				.max(50)
				.default(10)
				.describe("Maximum distinct traces to return (1-50)"),
		},
		async ({ query, model_filter, has_error, limit }) => {
			try {
				const result = await reader.searchTraces({
					query,
					modelFilter: model_filter,
					hasError: has_error,
					limit,
				});
				if (result.source === "clickhouse_match") {
					return textResult({
						query,
						model_filter: model_filter ?? null,
						has_error: has_error ?? null,
						matches: result.matches,
						count: result.matches.length,
					});
				}
				// Gateway mode content-filters the trace LIST — a genuinely
				// different shape from the ClickHouse per-span match aggregation,
				// and honestly labelled as such rather than forced to match it.
				return textResult({
					query,
					model_filter: model_filter ?? null,
					has_error: has_error ?? null,
					traces: result.traces,
					count: result.traces.length,
					note:
						"gateway mode: results are trace summaries filtered by content " +
						"(GET /v1/traces?q=), not the per-span match detail " +
						"(matched_spans / first_match_*) that self-host ClickHouse mode returns.",
				});
			} catch (err) {
				return toolErrorResult(err);
			}
		},
	);

	server.tool(
		"replay_trace",
		"Fetch the full stored structure of a trace (ordered spans with their " +
			"LLM/tool attributes) for offline inspection and step-through " +
			"debugging. Read-only: this returns the recorded trace as-is and does " +
			"NOT re-execute any model or tool — live shadow re-execution requires " +
			"the gateway and is not part of the MCP server surface.",
		{
			trace_id: z.string().describe("The trace ID to fetch for inspection"),
			include_tool_calls: z
				.boolean()
				.default(true)
				.describe(
					"Include non-LLM (tool / browser / MCP) spans in the result. " +
						"When false, only LLM spans (those whose attributes carry a " +
						"gen_ai/llm model) are returned.",
				),
		},
		async ({ trace_id, include_tool_calls }) => {
			try {
				const spans = await reader.getTraceSpans(trace_id);

				const parsed = spans
					.map((s) => {
						let attributes: Record<string, unknown>;
						try {
							attributes = JSON.parse(s.attributes) as Record<string, unknown>;
						} catch {
							attributes = { raw: s.attributes };
						}
						const isLlmSpan =
							"gen_ai.request.model" in attributes ||
							"gen_ai.response.model" in attributes ||
							"llm.model_name" in attributes ||
							"llm.model" in attributes;
						return { ...s, attributes, is_llm_span: isLlmSpan };
					})
					.filter((s) => include_tool_calls || s.is_llm_span);

				if (parsed.length === 0) {
					return textResult({
						trace_id,
						error: "Trace not found or has no matching spans",
						span_count: 0,
						spans: [],
					});
				}

				return textResult({
					trace_id,
					mode: "inspection",
					replayed: false,
					note:
						"Stored trace returned for inspection. Live shadow " +
						"re-execution is a gateway capability, not available via MCP.",
					include_tool_calls,
					span_count: parsed.length,
					spans: parsed,
				});
			} catch (err) {
				return toolErrorResult(err);
			}
		},
	);

	if (reader.mode === "gateway") {
		server.tool(
			"explain_guardrail_block",
			"Explain a Tracelane guardrail signal. Two independent id kinds, " +
				"pick the one you have: `correlation_id` — the id in a guardrail " +
				"403 response body, for a request that was blocked pre-flight " +
				"(there is no trace/span for it, since the request never dispatched); " +
				"or `trace_id` + `span_id` together — to explain a detection-layer " +
				"(AFT) flag recorded on a span that DID execute.",
			{
				correlation_id: z
					.string()
					.optional()
					.describe(
						"The correlation id from a guardrail block's 403 response body.",
					),
				trace_id: z
					.string()
					.optional()
					.describe(
						"The trace ID containing an AFT-flagged span. Use with span_id.",
					),
				span_id: z
					.string()
					.optional()
					.describe(
						"The span ID carrying an AFT detection flag. Use with trace_id.",
					),
			},
			async ({ correlation_id, trace_id, span_id }) => {
				try {
					if (correlation_id) {
						const verdicts =
							await reader.explainGuardrailByCorrelationId(correlation_id);
						if (verdicts.length === 0) {
							return textResult({
								correlation_id,
								verdicts: [],
								hint:
									"no guardrail verdict found for that correlation_id in the " +
									"served window",
							});
						}
						return textResult({
							correlation_id,
							verdicts: verdicts.map((v) => ({
								...v,
								rails: safeParseJson(v.rails),
							})),
						});
					}
					if (trace_id && span_id) {
						return await explainSpanAftFlag(reader, trace_id, span_id);
					}
					throw new ToolInputError(
						"gateway mode needs either correlation_id (from a guardrail " +
							"block's 403 body) or both trace_id and span_id (to explain a " +
							"detection-layer flag on a recorded span).",
					);
				} catch (err) {
					return toolErrorResult(err);
				}
			},
		);
	} else {
		server.tool(
			"explain_guardrail_block",
			"Get a human-readable explanation of why a Tracelane guardrail fired on a span",
			{
				trace_id: z
					.string()
					.describe("The trace ID containing the blocked span"),
				span_id: z.string().describe("The span ID that was blocked or warned"),
			},
			async ({ trace_id, span_id }) => {
				try {
					return await explainSpanAftFlag(reader, trace_id, span_id);
				} catch (err) {
					return toolErrorResult(err);
				}
			},
		);
	}
}
