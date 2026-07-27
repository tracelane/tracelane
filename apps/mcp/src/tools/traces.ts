/**
 * MCP tools for reading trace data.
 *
 * All tools are READ-ONLY. Every ClickHouse query uses parameter binding
 * with tenant_id from TRACELANE_TENANT_ID env — never from tool arguments.
 * Query pattern: WHERE tenant_id = {tenantId: String} on every query.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getTenantId } from "../auth.js";
import { getDb } from "../db.js";

export function registerTraceTools(server: McpServer) {
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
			const tenantId = getTenantId();
			const db = getDb();

			let where = "WHERE tenant_id = {tenantId: String}";
			const params: Record<string, unknown> = { tenantId, limit };

			if (model_filter) {
				where += " AND model = {model: String}";
				params.model = model_filter;
			}
			if (has_error === true) {
				where += " AND error_count > 0";
			} else if (has_error === false) {
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

			const rows = await result.json<{
				trace_id: string;
				root_name: string;
				start_time: string;
				duration_us: number;
				span_count: number;
				error_count: number;
				intervention: number;
				model: string;
			}>();

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({ traces: rows, count: rows.length }),
					},
				],
			};
		},
	);

	server.tool(
		"get_trace",
		"Get all spans for a specific trace",
		{
			trace_id: z.string().describe("The trace ID to fetch"),
		},
		async ({ trace_id }) => {
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
				query_params: { tenantId, trace_id },
				format: "JSONEachRow",
			});

			const spans = await result.json<{
				span_id: string;
				parent_span_id: string | null;
				name: string;
				start_time: string;
				end_time: string;
				duration_us: number;
				status_code: number;
				status_message: string;
				attributes: string;
				aft_ids: string[];
				intervention: number;
			}>();

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({ trace_id, spans, span_count: spans.length }),
					},
				],
			};
		},
	);

	server.tool(
		"get_span",
		"Get details for a specific span including all LLM attributes",
		{
			trace_id: z.string().describe("The trace ID"),
			span_id: z.string().describe("The span ID"),
		},
		async ({ trace_id, span_id }) => {
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
            AND span_id = {span_id: String}
          LIMIT 1
        `,
				query_params: { tenantId, trace_id, span_id },
				format: "JSONEachRow",
			});

			const rows = await result.json<{
				span_id: string;
				parent_span_id: string | null;
				name: string;
				start_time: string;
				end_time: string;
				duration_us: number;
				status_code: number;
				status_message: string;
				attributes: string;
				aft_ids: string[];
				intervention: number;
			}>();

			const span = rows[0];
			if (!span) {
				return {
					content: [
						{
							type: "text" as const,
							text: JSON.stringify({
								error: "Span not found",
								trace_id,
								span_id,
							}),
						},
					],
				};
			}

			// Parse attributes JSON for easier consumption
			let parsedAttributes: unknown = {};
			try {
				parsedAttributes = JSON.parse(span.attributes);
			} catch {
				parsedAttributes = { raw: span.attributes };
			}

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({ ...span, attributes: parsedAttributes }),
					},
				],
			};
		},
	);

	server.tool(
		"search_traces",
		"Search traces by free-text substring across span names and the " +
			"attributes JSON blob, optionally narrowed by model name or error " +
			"status. Read-only; tenant-scoped.",
		{
			query: z
				.string()
				.min(1)
				.max(256)
				.describe(
					"Case-insensitive substring matched against span name and the " +
						"attributes JSON (model names, prompts, tool names, etc.)",
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
			const tenantId = getTenantId();
			const db = getDb();

			// Tenant isolation is structural and unconditional: the leading
			// WHERE clause is hard-coded, and tenantId comes from the auth
			// context (getTenantId), never from a tool argument. The search
			// text is parameter-bound — never concatenated into SQL.
			let where = "WHERE tenant_id = {tenantId: String}";
			const params: Record<string, unknown> = {
				tenantId,
				// `position(haystack, needle)` is case-sensitive in ClickHouse;
				// we lowercase both sides for a case-insensitive substring match.
				needle: query.toLowerCase(),
				limit,
			};

			where +=
				" AND (position(lower(name), {needle: String}) > 0" +
				" OR position(lower(attributes), {needle: String}) > 0)";

			if (model_filter) {
				where += " AND position(lower(attributes), {model: String}) > 0";
				params.model = model_filter.toLowerCase();
			}
			if (has_error === true) {
				where += " AND status_code = 2";
			} else if (has_error === false) {
				where += " AND status_code != 2";
			}

			// Collapse matching spans to one row per trace so the caller gets
			// distinct traces. argMax picks the earliest-by-time span's fields
			// as the representative row for the matched trace.
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

			const rows = await result.json<{
				trace_id: string;
				matched_spans: number;
				first_match_time: string;
				first_match_span_id: string;
				first_match_name: string;
				max_status_code: number;
			}>();

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({
							query,
							model_filter: model_filter ?? null,
							has_error: has_error ?? null,
							matches: rows,
							count: rows.length,
						}),
					},
				],
			};
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
			const tenantId = getTenantId();
			const db = getDb();

			// Tenant-isolated, parameter-bound read of the stored trace. No
			// model/tool re-execution — strictly a fetch of recorded spans.
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
				query_params: { tenantId, trace_id },
				format: "JSONEachRow",
			});

			const spans = await result.json<{
				span_id: string;
				parent_span_id: string | null;
				name: string;
				start_time: string;
				end_time: string;
				duration_us: number;
				status_code: number;
				status_message: string;
				attributes: string;
				aft_ids: string[];
				intervention: number;
			}>();

			// Parse each span's attributes JSON and, when the caller asked to
			// exclude tool calls, keep only spans that look like LLM spans
			// (attributes carry a gen_ai/llm model field).
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
				return {
					content: [
						{
							type: "text" as const,
							text: JSON.stringify({
								trace_id,
								error: "Trace not found or has no matching spans",
								span_count: 0,
								spans: [],
							}),
						},
					],
				};
			}

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({
							trace_id,
							mode: "inspection",
							replayed: false,
							note:
								"Stored trace returned for inspection. Live shadow " +
								"re-execution is a gateway capability, not available via MCP.",
							include_tool_calls,
							span_count: parsed.length,
							spans: parsed,
						}),
					},
				],
			};
		},
	);

	server.tool(
		"explain_guardrail_block",
		"Get a human-readable explanation of why a Tracelane guardrail fired on a span",
		{
			trace_id: z.string().describe("The trace ID containing the blocked span"),
			span_id: z.string().describe("The span ID that was blocked or warned"),
		},
		async ({ trace_id, span_id }) => {
			const tenantId = getTenantId();
			const db = getDb();

			const result = await db.query({
				query: `
          SELECT aft_ids, intervention, attributes
          FROM tracelane.spans FINAL
          WHERE tenant_id = {tenantId: String}
            AND trace_id = {trace_id: String}
            AND span_id = {span_id: String}
          LIMIT 1
        `,
				query_params: { tenantId, trace_id, span_id },
				format: "JSONEachRow",
			});

			const rows = await result.json<{
				aft_ids: string[];
				intervention: number;
				attributes: string;
			}>();

			const span = rows[0];
			if (!span) {
				return {
					content: [
						{
							type: "text" as const,
							text: JSON.stringify({
								error: "Span not found",
								trace_id,
								span_id,
							}),
						},
					],
				};
			}

			const interventionLabel =
				span.intervention === 2
					? "block"
					: span.intervention === 1
						? "warn"
						: "none";

			// AFT taxonomy short descriptions — expanded in V2 via DB join
			const aftDescriptions: Record<string, string> = {
				"AF-01": "Prompt injection — attempt to override system prompt",
				"AF-02": "Data exfiltration — attempt to extract sensitive data",
				"AF-03": "Tool misuse — calling a tool outside its declared intent",
				"AF-04":
					"Scope escalation — agent requesting permissions beyond declared scope",
				"AF-05": "Lethal trifecta — exfiltrate + execute + persist pattern",
				"AF-13":
					"Missing system prompt boundary — unguarded user content in system role",
			};

			const descriptions = span.aft_ids.map(
				(id) => aftDescriptions[id] ?? `${id} — see AFT taxonomy docs`,
			);

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({
							trace_id,
							span_id,
							intervention: interventionLabel,
							aft_ids: span.aft_ids,
							aft_descriptions: descriptions,
							recommendation: span.aft_ids.includes("AF-13")
								? "Add a system prompt boundary to separate user content from system instructions."
								: "Review span attributes for the triggering AFT pattern and tighten the agent's tool permissions.",
						}),
					},
				],
			};
		},
	);
}
