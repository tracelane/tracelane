import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { webRateLimits } from "@/db/schema";
import { PGlite } from "@electric-sql/pglite";
import type { SQL } from "drizzle-orm";
import { PgDialect, getTableConfig } from "drizzle-orm/pg-core";
import { afterAll, beforeAll, beforeEach, expect, it, vi } from "vitest";

const shared = vi.hoisted(() => ({ execute: vi.fn() }));
vi.mock("@/db", () => ({ db: shared }));
const url = process.env.POSTGRES_TEST_URL;
if (
	url &&
	!["127.0.0.1", "localhost", "[::1]"].includes(new URL(url).hostname)
) {
	throw new Error("Rate-limit integration tests require localhost Postgres");
}
const engine = url ? null : new PGlite();
const schema = `rate_limit_test_${randomUUID().replaceAll("-", "")}`;
const dialect = new PgDialect();
const migration = readFileSync(
	new URL("../db/migrations/0093_web_rate_limits.sql", import.meta.url),
	"utf8",
);
function psql(statement: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const child = spawn(
			"psql",
			[url ?? "", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1"],
			{ stdio: ["pipe", "pipe", "pipe"] },
		);
		let output = "";
		child.stdout.on("data", (part) => {
			output += part;
		});
		// Discard server errors: tests must never echo connection strings/keys.
		child.stderr.resume();
		child.on("error", () => reject(new Error("local psql unavailable")));
		child.on("close", (code) =>
			code === 0
				? resolve(output.trim())
				: reject(new Error("local SQL failed")),
		);
		child.stdin.on("error", () => {});
		child.stdin.end(`SET search_path TO "${schema}";\n${statement}`);
	});
}
const literal = (value: unknown) => {
	if (typeof value === "number" && Number.isFinite(value)) return String(value);
	if (typeof value === "string") return `'${value.replaceAll("'", "''")}'`;
	throw new Error("unexpected test bind type");
};
async function query(
	statement: string,
	params: unknown[] = [],
): Promise<{ rows: Record<string, unknown>[] }> {
	if (engine) return engine.query(statement, params);
	if (statement.trimStart().startsWith("DELETE")) {
		if (params.length) throw new Error("unexpected cleanup binds");
		await psql(`${statement};`);
		return { rows: [] };
	}
	const wrapped = `WITH result AS (${statement}) SELECT coalesce(json_agg(result), '[]') FROM result`;
	const sql = params.length
		? `PREPARE test_statement AS ${wrapped}; EXECUTE test_statement(${params.map(literal).join(",")});`
		: `${wrapped};`;
	return { rows: JSON.parse(await psql(sql)) };
}
async function exec(statement: string) {
	if (engine) await engine.exec(statement);
	else await psql(statement);
}
beforeAll(async () => {
	if (url)
		await psql(`CREATE SCHEMA "${schema}"; SET search_path TO "${schema}";`);
	await exec(migration);
	await exec(migration); // additive/idempotent for repeat setup
});
afterAll(async () => {
	if (engine) await engine.close();
	else await psql(`DROP SCHEMA "${schema}" CASCADE;`);
});
beforeEach(async () => {
	vi.resetModules();
	await exec("TRUNCATE web_rate_limits");
	shared.execute.mockReset().mockImplementation(async (statement: SQL) => {
		const compiled = dialect.sqlToQuery(statement);
		return query(compiled.sql, compiled.params);
	});
	vi.spyOn(Math, "random").mockReturnValue(0.5);
});

it("under_limit_allowed", async () => {
	const { rateLimit } = await import("./rate-limit");
	expect(await rateLimit("under", 3, 300_000)).toBe(true);
	expect(await rateLimit("under", 3, 300_000)).toBe(true);
});
it("call_at_limit_allowed", async () => {
	const { rateLimit } = await import("./rate-limit");
	expect(await rateLimit("exact", 1, 300_000)).toBe(true);
});
it("cross_isolate_burst_limited", async () => {
	const first = await import("./rate-limit");
	vi.resetModules();
	const second = await import("./rate-limit");
	expect(await first.rateLimit("invite:t:fixture", 2, 300_000)).toBe(true);
	expect(await second.rateLimit("invite:t:fixture", 2, 300_000)).toBe(true);
	expect(await first.rateLimit("invite:t:fixture", 2, 300_000)).toBe(false);
});
it("concurrent_calls_do_not_exceed_limit", async () => {
	const first = await import("./rate-limit");
	vi.resetModules();
	const second = await import("./rate-limit");
	const results = await Promise.all(
		Array.from({ length: 30 }, (_, i) =>
			(i % 2 ? first : second).rateLimit("concurrent", 5, 3_600_000),
		),
	);
	expect(results.filter(Boolean)).toHaveLength(5);
	expect(
		(await query("SELECT count FROM web_rate_limits")).rows[0]?.count,
	).toBe(30);
});
it("keys_count_independently", async () => {
	const { rateLimit } = await import("./rate-limit");
	expect(await rateLimit("first", 1, 300_000)).toBe(true);
	expect(await rateLimit("first", 1, 300_000)).toBe(false);
	expect(await rateLimit("second", 1, 300_000)).toBe(true);
});
it("new_window_resets_count", async () => {
	const { rateLimit } = await import("./rate-limit");
	expect(await rateLimit("first", 1, 300_000)).toBe(true);
	await exec(
		"UPDATE web_rate_limits SET window_start = window_start - interval '2 hours'",
	);
	expect(await rateLimit("first", 1, 300_000)).toBe(true);
});
it("over_limit_refused", async () => {
	const { rateLimit } = await import("./rate-limit");
	await rateLimit("over", 1, 300_000);
	expect(await rateLimit("over", 1, 300_000)).toBe(false);
});
it("raw_key_never_stored", async () => {
	const { rateLimit } = await import("./rate-limit");
	const key = "invite:ip:192.0.2.44";
	await rateLimit(key, 1, 3_600_000);
	const rows = (
		await query(
			"SELECT encode(key_hash, 'hex') AS hash, octet_length(key_hash) AS bytes FROM web_rate_limits",
		)
	).rows;
	expect(rows).toEqual([
		{ hash: createHash("sha256").update(key).digest("hex"), bytes: 32 },
	]);
	for (const [statement] of shared.execute.mock.calls) {
		expect(dialect.sqlToQuery(statement).params).not.toContain(key);
	}
});
it("uses_database_clock", async () => {
	const { rateLimit } = await import("./rate-limit");
	await rateLimit("clock", 1, 3_600_000);
	// PGlite shares the JS host clock; real Postgres has an independent clock.
	if (url) vi.spyOn(Date, "now").mockReturnValue(0);
	expect(await rateLimit("clock", 1, 3_600_000)).toBe(false);
	expect(
		(
			await query(
				"SELECT window_start = to_timestamp(floor(extract(epoch FROM now()) / 3600) * 3600) AS aligned FROM web_rate_limits",
			)
		).rows,
	).toEqual([{ aligned: true }]);
});
it("limiter_returns_promise", async () => {
	const { rateLimit } = await import("./rate-limit");
	const result = rateLimit("promise", 1, 300_000);
	expect(result).toBeInstanceOf(Promise);
	expect(await result).toBe(true);
});
it("cleanup_removes_old_windows", async () => {
	const { rateLimit } = await import("./rate-limit");
	await rateLimit("old", 2, 300_000);
	await exec(
		"UPDATE web_rate_limits SET window_start = now() - interval '2 days'",
	);
	vi.spyOn(Math, "random").mockReturnValue(0);
	expect(await rateLimit("current", 2, 300_000)).toBe(true);
	expect(
		(await query("SELECT count(*)::int AS total FROM web_rate_limits")).rows,
	).toEqual([{ total: 1 }]);
});
it("store_error_fails_closed", async () => {
	const { rateLimit } = await import("./rate-limit");
	const errors = vi.spyOn(console, "error").mockImplementation(() => {});
	shared.execute.mockRejectedValueOnce(new Error("private database detail"));
	await expect(rateLimit("test", 1, 300_000)).rejects.toThrow(
		"rate_limit_unavailable",
	);
	expect(errors).toHaveBeenCalledWith("rate_limit_unavailable");
	expect(JSON.stringify(errors.mock.calls)).not.toContain("private database");
});
it("cleanup_failure_does_not_refuse_a_counted_request", async () => {
	// The request was already counted and decided; a failed housekeeping DELETE must not 503 it.
	const { rateLimit } = await import("./rate-limit");
	const errors = vi.spyOn(console, "error").mockImplementation(() => {});
	vi.spyOn(Math, "random").mockReturnValue(0);
	shared.execute
		.mockResolvedValueOnce({ rows: [{ count: 1 }] })
		.mockRejectedValueOnce(new Error("cleanup failed"));
	await expect(rateLimit("test", 1, 300_000)).resolves.toBe(true);
	expect(errors).toHaveBeenCalledWith("rate_limit_cleanup_failed");
});
it("drizzle_matches_migration", async () => {
	const config = getTableConfig(webRateLimits);
	expect(
		config.columns.map((c) => [c.name, c.getSQLType(), c.notNull]),
	).toEqual([
		["key_hash", "bytea", true],
		["window_start", "timestamp with time zone", true],
		["count", "integer", true],
	]);
	expect(config.primaryKeys[0]?.columns.map((c) => c.name)).toEqual([
		"key_hash",
		"window_start",
	]);
	expect(config.indexes[0]?.config.name).toBe(
		"web_rate_limits_window_start_idx",
	);
	const columns = (
		await query(
			"SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'web_rate_limits' ORDER BY ordinal_position",
		)
	).rows;
	expect(columns.map((c) => c.column_name)).toEqual([
		"key_hash",
		"window_start",
		"count",
	]);
});
it("migration_is_additive", async () => {
	const runner = readFileSync(
		new URL("../../../scripts/deploy/migrate.sh", import.meta.url),
		"utf8",
	);
	const declarations = runner.slice(0, runner.indexOf("post=0"));
	expect(declarations.length).toBeGreaterThan(0);
	const code = await new Promise<number | null>((resolve, reject) => {
		const child = spawn(
			"bash",
			[
				"-c",
				`${declarations}\npre_allowed "$1"`,
				"migration-check",
				fileURLToPath(
					new URL("../db/migrations/0093_web_rate_limits.sql", import.meta.url),
				),
			],
			{ stdio: "ignore" },
		);
		child.on("error", reject);
		child.on("close", resolve);
	});
	expect(code).toBe(0);
});
it("no_in_memory_map", async () => {
	const first = await import("./rate-limit");
	await first.rateLimit("survives-restart", 1, 300_000);
	expect((await query("SELECT count FROM web_rate_limits")).rows).toEqual([
		{ count: 1 },
	]);
	vi.resetModules();
	const restarted = await import("./rate-limit");
	expect(await restarted.rateLimit("survives-restart", 1, 300_000)).toBe(false);
});
