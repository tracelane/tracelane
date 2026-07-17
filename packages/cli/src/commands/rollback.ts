/**
 *
 * The Bender invariant: a recovery path that depends on an LLM / agent / MCP /
 * provider can be defeated exactly when you need it (provider outage, token
 * exhaustion — often the very failure you're recovering from). So this command
 * is a **pure ClickHouse routing-pointer swap**: it writes a `manual_override`
 * row to `tracelane.promotion_decisions` (the pointer the gateway's prompt
 * router reads to resolve the active version) over ClickHouse's HTTP API. It
 * runs with **every upstream down and a $0 token budget** — it talks only to
 * ClickHouse, never to the gateway, a provider, the MCP server, or any model.
 *
 * HARD RULE (enforced by `scripts/ci/no-llm-in-recovery.sh`): this file MUST
 * NOT import any provider SDK, MCP client, or SLM-judge module. It uses only
 * Node built-ins + commander + global `fetch`.
 *
 * Two rollback targets (ADR-037):
 *   - **prompt version** → this command (ClickHouse routing-pointer swap).
 *   - **deploy SHA / binary** → the blue-green LB origin flip in
 *     `infra/prod/` (Phase 6 / ADR-038); also deterministic and token-free.
 *
 * The R2 cold-tier partition pointer is governed by the ingest worker's
 * partition logic, not a user rollback; a prompt-version rollback does not move
 * R2 data, so no R2 mutation is needed here.
 */

import { randomUUID } from "node:crypto";
import process from "node:process";
import type { Command } from "commander";

interface ClickHouseConn {
	url: string;
	user: string;
	password: string;
}

function resolveClickHouse(opts: {
	clickhouse?: string;
	chUser?: string;
	chPassword?: string;
}): ClickHouseConn {
	return {
		url:
			opts.clickhouse ??
			process.env.TRACELANE_CLICKHOUSE_URL ??
			"http://localhost:8123",
		user: opts.chUser ?? process.env.TRACELANE_CLICKHOUSE_USER ?? "default",
		password:
			opts.chPassword ?? process.env.TRACELANE_CLICKHOUSE_PASSWORD ?? "",
	};
}

/**
 * Execute a ClickHouse statement over the HTTP interface. `rows`, when given,
 * is appended as the JSONEachRow body for an INSERT. Returns on 2xx; throws
 * otherwise. No retry against any model — ClickHouse is the only dependency.
 */
async function clickhouseExec(
	conn: ClickHouseConn,
	query: string,
	rows?: unknown[],
): Promise<void> {
	const u = new URL(conn.url);
	u.searchParams.set("query", query);
	const body =
		rows && rows.length > 0
			? rows.map((r) => JSON.stringify(r)).join("\n")
			: undefined;
	const res = await fetch(u.toString(), {
		method: "POST",
		headers: {
			"X-ClickHouse-User": conn.user,
			"X-ClickHouse-Key": conn.password,
			"content-type": "text/plain",
		},
		body,
	});
	if (!res.ok) {
		const text = await res.text();
		throw new Error(`ClickHouse ${res.status} ${res.statusText}: ${text}`);
	}
}

/** Micros-since-epoch ClickHouse DateTime64(3) literal as an ISO-ish string. */
function nowClickhouse(): string {
	// 'YYYY-MM-DD HH:MM:SS.mmm' in UTC — ClickHouse parses this for DateTime64.
	return new Date().toISOString().replace("T", " ").replace("Z", "");
}

export function registerRollbackCommand(program: Command): void {
	program
		.command("rollback")
		.description(
			"Deterministic token-free rollback of a prompt's active version (ADR-037). " +
				"Swaps the ClickHouse routing pointer directly — runs with every provider down.",
		)
		.requiredOption(
			"--to <versionId>",
			"Target prompt_version_id (UUID) to make active",
		)
		.requiredOption("--prompt-id <uuid>", "The prompt_id being rolled back")
		.requiredOption("--tenant <uuid>", "Tenant id (workspace) of the prompt")
		.option(
			"--from-version <uuid>",
			"The version being rolled back FROM (recorded for attribution)",
		)
		.option("--env <env>", "Environment to roll back", "production")
		.option(
			"--reason <text>",
			"Reason recorded in the decision row",
			"deterministic CLI rollback (ADR-037)",
		)
		.option(
			"--clickhouse <url>",
			"ClickHouse HTTP URL ($TRACELANE_CLICKHOUSE_URL)",
		)
		.option("--ch-user <user>", "ClickHouse user ($TRACELANE_CLICKHOUSE_USER)")
		.option(
			"--ch-password <pw>",
			"ClickHouse password ($TRACELANE_CLICKHOUSE_PASSWORD)",
		)
		.action(
			async (opts: {
				to: string;
				promptId: string;
				tenant: string;
				fromVersion?: string;
				env: string;
				reason: string;
				clickhouse?: string;
				chUser?: string;
				chPassword?: string;
			}) => {
				const conn = resolveClickHouse(opts);
				// The routing pointer: a `manual_override` promotion decision. The
				// gateway's prompt router resolves the active version from the latest
				// decided_at per (tenant_id, prompt_id) — so this row immediately
				// becomes the active pointer. ReplacingMergeTree + decided_at ordering
				// serializes it per workspace (ADR-038 §23.4).
				const row = {
					tenant_id: opts.tenant,
					promotion_id: randomUUID(),
					prompt_id: opts.promptId,
					from_version_id: opts.fromVersion ?? null,
					to_version_id: opts.to,
					from_env: opts.env,
					to_env: opts.env,
					eval_run_id: null,
					decision: "manual_override",
					decided_at: nowClickhouse(),
					decided_by_user_id: null,
					notes: opts.reason,
				};
				try {
					await clickhouseExec(
						conn,
						"INSERT INTO tracelane.promotion_decisions FORMAT JSONEachRow",
						[row],
					);
					process.stdout.write(
						`ROLLBACK ok — ${opts.env} now points prompt ${opts.promptId.slice(0, 8)} → version ${opts.to.slice(0, 8)} (deterministic, no providers contacted)\n`,
					);
				} catch (err) {
					process.stderr.write(
						`rollback failed: ${err instanceof Error ? err.message : String(err)}\n`,
					);
					process.exit(1);
				}
			},
		);
}
