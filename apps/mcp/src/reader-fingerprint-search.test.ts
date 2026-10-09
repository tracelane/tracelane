import { spawnSync } from "node:child_process";
import { expect, it, vi } from "vitest";
import { ClickHouseReader } from "./reader.js";
const query = vi.hoisted(() =>
	vi.fn(
		async (_q: { query: string; query_params: Record<string, unknown> }) => ({
			json: async () => [],
		}),
	),
);
vi.mock("./auth.js", () => ({ getTenantId: () => "tenant" }));
vi.mock("./db.js", () => ({ getDb: () => ({ query }) }));

it("search and model filters remove only the two private fingerprint attributes, with tenant first", async () => {
	await new ClickHouseReader().searchTraces({
		query: 'gen_ai_tool_call_arg_fp":"a3',
		modelFilter: "other",
		limit: 10,
	});
	const sql = query.mock.calls.at(-1)?.[0].query ?? "";
	expect(sql).toContain("WHERE tenant_id = {tenantId: String}");
	expect(sql).not.toContain("lower(attributes)");
	expect(sql).toContain("gen_ai_tool_call_arg_fp");
	expect(sql).toContain("tracelane_response_tool_arg_fps");
	expect(sql).toContain("JSONExtractKeysAndValuesRaw(attributes)");
});

it.skipIf(process.env.CF2_CLICKHOUSE_LOCAL !== "1")(
	"real ClickHouse search hides fingerprints and retains other attributes",
	async () => {
		const source = `(SELECT 'tenant' AS tenant_id, 'trace' AS trace_id, 'span' AS span_id, 1 AS start_time, 'root' AS name, 0 AS status_code, '{"gen_ai_tool_call_arg_fp":"a3secret","tracelane_response_tool_arg_fps":["a3secret"],"other":"kept-value","nested":{"key":"nested-value"}}' AS attributes)`;
		for (const [needle, expected] of [
			['gen_ai_tool_call_arg_fp":"a3', 0],
			['tracelane_response_tool_arg_fps":["a3', 0],
			["a3secret", 0],
			["kept-value", 1],
			["nested-value", 1],
		] as const) {
			await new ClickHouseReader().searchTraces({ query: needle, limit: 10 });
			const request = query.mock.calls.at(-1)?.[0];
			if (!request) throw new Error("reader did not query ClickHouse");
			const sql = request.query.replace("tracelane.spans FINAL", source);
			const container = process.env.CF2_CLICKHOUSE_CONTAINER;
			const engine = container
				? ["exec", "-i", container, "clickhouse-local"]
				: [
						"run",
						"--rm",
						"--pull=never",
						"--network",
						"none",
						"--entrypoint",
						"clickhouse-local",
						"-i",
						"clickhouse/clickhouse-server:24.12-alpine",
					];
			const result = spawnSync(
				"docker",
				[
					...engine,
					"--param_tenantId=tenant",
					`--param_needle=${needle}`,
					"--param_limit=10",
				],
				{
					input: `${sql} FORMAT JSONEachRow`,
					encoding: "utf8",
					timeout: 300000,
				},
			);
			expect(result.status, result.stderr).toBe(0);
			expect(
				result.stdout.trim() ? result.stdout.trim().split("\n").length : 0,
				needle,
			).toBe(expected);
		}
	},
	1800000,
);
