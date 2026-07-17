/**
 *
 * Wired to the live gateway endpoints landed in commits c28bac9 +
 * 4555ffb:
 *   GET  /v1/prompts/:name?env=...           -> show
 *   GET  /v1/prompts/:name/history?limit=N   -> list (per prompt)
 *   POST /v1/prompts/:name/promote           -> promote
 *   POST /v1/prompts/:name/rollback          -> rollback
 *
 * Auth: TRACELANE_TOKEN env var or --token flag (Bearer JWT or
 * tlane_<key> API key). Gateway URL: TRACELANE_GATEWAY_URL or
 * --gateway flag (default http://localhost:8080).
 *
 * `diff` is local-only: pulls both versions via show + diffs the
 * content client-side. No server endpoint required.
 */

import { spawnSync } from "node:child_process";
import process from "node:process";
import type { Command } from "commander";

interface ResolvedVersion {
	prompt_version_id: string;
	prompt_id: string;
	version_number: number;
	content: string;
	model_pin: string | null;
	sha256_hex: string;
}

type HistoryEntry =
	| {
			kind: "promotion";
			promotion_id: string;
			from_env: string;
			to_env: string;
			from_version_id: string | null;
			to_version_id: string;
			decision: string;
			notes: string;
			at_micros: number;
	  }
	| {
			kind: "rollback";
			rollback_id: string;
			from_version_id: string;
			to_version_id: string;
			trigger_metric: string;
			trigger_value: number;
			sigma_drift: number;
			rollback_mode: string;
			at_micros: number;
	  };

interface PromotionDecision {
	promotion_id: string;
	from_version_id: string | null;
	to_version_id: string;
	from_env: string;
	to_env: string;
	eval_run_id: string | null;
	decision: string;
	notes: string;
}

interface ConnOpts {
	gateway: string;
	token: string;
}

function resolveConn(opts: { gateway?: string; token?: string }): ConnOpts {
	const gateway =
		opts.gateway ??
		process.env.TRACELANE_GATEWAY_URL ??
		"http://localhost:8080";
	const token = opts.token ?? process.env.TRACELANE_TOKEN ?? "";
	if (!token) {
		process.stderr.write(
			"tlane prompt: TRACELANE_TOKEN env var or --token flag required.\n",
		);
		process.exit(2);
	}
	return { gateway, token };
}

async function apiGet<T>(conn: ConnOpts, path: string): Promise<T> {
	const res = await fetch(`${conn.gateway}${path}`, {
		headers: { authorization: `Bearer ${conn.token}` },
	});
	if (!res.ok) {
		const body = await res.text();
		throw new Error(`GET ${path} -> ${res.status} ${res.statusText}: ${body}`);
	}
	return (await res.json()) as T;
}

async function apiPost<TIn, TOut>(
	conn: ConnOpts,
	path: string,
	body: TIn,
): Promise<TOut> {
	const res = await fetch(`${conn.gateway}${path}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${conn.token}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
	});
	if (!res.ok) {
		const respBody = await res.text();
		throw new Error(
			`POST ${path} -> ${res.status} ${res.statusText}: ${respBody}`,
		);
	}
	return (await res.json()) as TOut;
}

function fmtMicros(microsSinceEpoch: number): string {
	const ms = Math.floor(microsSinceEpoch / 1000);
	if (!Number.isFinite(ms) || ms <= 0) return "—";
	return new Date(ms).toISOString().replace("T", " ").replace(/\..+$/, "Z");
}

function shortId(uuid: string | null | undefined): string {
	if (!uuid) return "—";
	return uuid.slice(0, 8);
}

export function registerPromptCommand(program: Command): void {
	const prompt = program
		.command("prompt")
		.description(
			"B1 Prompt Promotion + Eval Gates + Auto-Rollback (per ADR-009)",
		);

	const commonOpts = (cmd: Command): Command =>
		cmd
			.option(
				"--gateway <url>",
				"Tracelane gateway URL (default: $TRACELANE_GATEWAY_URL or http://localhost:8080)",
			)
			.option("--token <bearer>", "Auth bearer (default: $TRACELANE_TOKEN)");

	commonOpts(prompt.command("list <name>"))
		.description(
			"List recent promotion + rollback events for a prompt (uses /history endpoint)",
		)
		.option("--limit <n>", "Max entries (1..500, default 50)", "50")
		.action(
			async (
				name: string,
				opts: { gateway?: string; token?: string; limit?: string },
			) => {
				const conn = resolveConn(opts);
				const limit = Number(opts.limit ?? "50");
				try {
					const entries = await apiGet<HistoryEntry[]>(
						conn,
						`/v1/prompts/${encodeURIComponent(name)}/history?limit=${limit}`,
					);
					if (entries.length === 0) {
						process.stdout.write(`(no events for ${name})\n`);
						return;
					}
					for (const e of entries) {
						const ts = fmtMicros(e.at_micros);
						if (e.kind === "promotion") {
							process.stdout.write(
								`${ts}  PROMOTE  ${e.from_env} -> ${e.to_env}  v=${shortId(e.to_version_id)}  ${e.decision}\n`,
							);
						} else {
							process.stdout.write(
								`${ts}  ROLLBACK ${e.rollback_mode.padEnd(15)}  ${e.trigger_metric} ${e.sigma_drift.toFixed(1)}σ  v=${shortId(e.to_version_id)}\n`,
							);
						}
					}
				} catch (err) {
					process.stderr.write(
						`error: ${err instanceof Error ? err.message : String(err)}\n`,
					);
					process.exit(1);
				}
			},
		);

	commonOpts(prompt.command("show <name>"))
		.description("Show resolved active version per environment")
		.option("--env <env>", "Single env (dev|staging|production|canary)")
		.action(
			async (
				name: string,
				opts: { gateway?: string; token?: string; env?: string },
			) => {
				const conn = resolveConn(opts);
				const envs = opts.env
					? [opts.env]
					: ["production", "staging", "canary"];
				for (const env of envs) {
					try {
						const v = await apiGet<ResolvedVersion>(
							conn,
							`/v1/prompts/${encodeURIComponent(name)}?env=${env}`,
						);
						process.stdout.write(
							`${env.padEnd(10)} v${v.version_number}  id=${shortId(v.prompt_version_id)}  sha=${v.sha256_hex.slice(0, 12)}…${v.model_pin ? `  model=${v.model_pin}` : ""}\n`,
						);
					} catch (err) {
						process.stdout.write(
							`${env.padEnd(10)} (error: ${err instanceof Error ? err.message : String(err)})\n`,
						);
					}
				}
			},
		);

	commonOpts(prompt.command("promote <name>"))
		.description("Promote a prompt version to a higher env (eval-gated)")
		.option("--from <env>", "Source environment", "staging")
		.option("--to <env>", "Target environment", "production")
		.option("--version-id <uuid>", "Target prompt_version_id (required)")
		.option("--eval-run <uuid>", "Eval run id to gate on")
		.action(
			async (
				name: string,
				opts: {
					gateway?: string;
					token?: string;
					from: string;
					to: string;
					versionId?: string;
					evalRun?: string;
				},
			) => {
				const conn = resolveConn(opts);
				if (!opts.versionId) {
					process.stderr.write("--version-id is required.\n");
					process.exit(2);
				}
				try {
					const decision = await apiPost<unknown, PromotionDecision>(
						conn,
						`/v1/prompts/${encodeURIComponent(name)}/promote`,
						{
							from_env: opts.from,
							to_env: opts.to,
							to_version_id: opts.versionId,
							eval_run_id: opts.evalRun ?? null,
						},
					);
					process.stdout.write(
						`${decision.decision.toUpperCase()}  ${decision.from_env} -> ${decision.to_env}  v=${shortId(decision.to_version_id)}\n`,
					);
					if (decision.notes)
						process.stdout.write(`  notes: ${decision.notes}\n`);
					if (
						decision.decision === "blocked_by_eval" ||
						decision.decision === "blocked_by_policy"
					) {
						process.exit(1);
					}
				} catch (err) {
					process.stderr.write(
						`error: ${err instanceof Error ? err.message : String(err)}\n`,
					);
					process.exit(1);
				}
			},
		);

	commonOpts(prompt.command("rollback <name>"))
		.description("Force-rollback a prompt to a specific previous version")
		.option("--env <env>", "Environment to roll back", "production")
		.option("--version-id <uuid>", "Target prompt_version_id (required)")
		.option(
			"--reason <text>",
			"Reason for rollback (recorded in audit)",
			"manual rollback via CLI",
		)
		.action(
			async (
				name: string,
				opts: {
					gateway?: string;
					token?: string;
					env: string;
					versionId?: string;
					reason: string;
				},
			) => {
				const conn = resolveConn(opts);
				if (!opts.versionId) {
					process.stderr.write("--version-id is required.\n");
					process.exit(2);
				}
				try {
					const decision = await apiPost<unknown, PromotionDecision>(
						conn,
						`/v1/prompts/${encodeURIComponent(name)}/rollback`,
						{
							env: opts.env,
							to_version_id: opts.versionId,
							reason: opts.reason,
						},
					);
					process.stdout.write(
						`ROLLBACK  ${decision.to_env}  v=${shortId(decision.to_version_id)}  ${decision.notes}\n`,
					);
				} catch (err) {
					process.stderr.write(
						`error: ${err instanceof Error ? err.message : String(err)}\n`,
					);
					process.exit(1);
				}
			},
		);

	commonOpts(prompt.command("diff <name>"))
		.description(
			"Diff two versions (local — pulls both via /v1/prompts and runs git diff)",
		)
		.requiredOption("--from-env <env>", "First env to fetch from")
		.requiredOption("--to-env <env>", "Second env to fetch from")
		.action(
			async (
				name: string,
				opts: {
					gateway?: string;
					token?: string;
					fromEnv: string;
					toEnv: string;
				},
			) => {
				const conn = resolveConn(opts);
				try {
					const [a, b] = await Promise.all([
						apiGet<ResolvedVersion>(
							conn,
							`/v1/prompts/${encodeURIComponent(name)}?env=${opts.fromEnv}`,
						),
						apiGet<ResolvedVersion>(
							conn,
							`/v1/prompts/${encodeURIComponent(name)}?env=${opts.toEnv}`,
						),
					]);
					if (a.sha256_hex === b.sha256_hex) {
						process.stdout.write(
							`(identical sha256 across ${opts.fromEnv} and ${opts.toEnv})\n`,
						);
						return;
					}
					// Use git diff for a familiar visual. Falls back to plain
					// content dump on systems without git.
					const tmp = await import("node:os");
					const fsp = await import("node:fs/promises");
					const path = await import("node:path");
					const dir = await fsp.mkdtemp(path.join(tmp.tmpdir(), "tlane-diff-"));
					const fa = path.join(dir, `${name}.${opts.fromEnv}`);
					const fb = path.join(dir, `${name}.${opts.toEnv}`);
					await fsp.writeFile(fa, a.content);
					await fsp.writeFile(fb, b.content);
					const result = spawnSync(
						"git",
						["--no-pager", "diff", "--no-index", "--color", fa, fb],
						{ stdio: "inherit" },
					);
					await fsp.rm(dir, { recursive: true, force: true });
					// `git diff --no-index` exits 1 when files differ — that's
					// what we expect, not an error.
					if (result.status !== null && result.status > 1) {
						process.exit(result.status);
					}
				} catch (err) {
					process.stderr.write(
						`error: ${err instanceof Error ? err.message : String(err)}\n`,
					);
					process.exit(1);
				}
			},
		);
}
