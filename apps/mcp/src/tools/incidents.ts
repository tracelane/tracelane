/**
 * EVL-40 slice 6 — incident MCP tools (`specs/EVL-40-incident-to-regression-pr-check.md` §2.5).
 *
 * GATEWAY MODE ONLY. Both tools read the gateway's tenant-scoped routes — the
 * incident packet (§2.1) and the regression export (§2.2) are assembled
 * server-side, so a self-host `ClickHouseReader` has nothing to call and these
 * tools are simply not registered there (`index.ts`).
 *
 * The descriptions carry the two honesty rules the spec requires an agent to
 * see before it acts: an explanation the packet cannot support is labelled
 * "uncertain", and an export is built from the RECORDED trace — it never
 * re-executes the request.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { GatewayReader } from "../reader.js";
import { textResult, toolErrorResult } from "./traces.js";

export function registerIncidentTools(
	server: McpServer,
	reader: GatewayReader,
) {
	server.tool(
		"get_incident",
		"Get the incident packet for one trace: what triggered it, what happened, what changed " +
			"against the nearest comparable good run, the linked spans, and candidate explanations. " +
			"Each explanation cites its evidence; one the evidence does not support is marked " +
			"'uncertain' — treat it as a lead, not a finding.",
		{
			trace_id: z.string().min(1).describe("The trace to explain"),
		},
		async ({ trace_id }) => {
			try {
				return textResult(await reader.getIncident(trace_id));
			} catch (err) {
				return toolErrorResult(err);
			}
		},
	);

	server.tool(
		"export_regression",
		"Export one trace as a regression fixture (format 'dataset' or 'promptfoo'). " +
			"mode 'recorded' replays the recorded output as the expected answer; mode 'mocked' also " +
			"pins the recorded tool results so the test is deterministic. The export is built from " +
			"the recorded trace and never re-executes the request. Fails with 422 " +
			"content_not_captured when content capture was off for the trace. The `limits` field " +
			"carries the gateway's x-tracelane-* headers stating what the fixture can and cannot assert.",
		{
			trace_id: z.string().min(1).describe("The trace to export"),
			format: z.enum(["dataset", "promptfoo"]).default("dataset"),
			mode: z.enum(["recorded", "mocked"]).default("recorded"),
		},
		async ({ trace_id, format, mode }) => {
			try {
				const out = await reader.exportRegression(trace_id, format, mode);
				return textResult({ fixture: out.fixture, format, limits: out.limits });
			} catch (err) {
				return toolErrorResult(err);
			}
		},
	);
}
