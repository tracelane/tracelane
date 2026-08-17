/**
 * MCP tools for reading eval results.
 *
 * The eval CORPUS (ids + suite + repo-relative path) comes from
 * `src/eval-manifest.json`, generated from `evals/` by
 * `scripts/gen-eval-manifest.mjs` and bundled into `dist/`. That matters
 * for distribution: `npx @tracelanedev/mcp` runs out of `node_modules`
 * where no `evals/` directory exists at any depth, so the previous
 * walk-up-from-`__dirname` lookup found nothing and the hand-maintained
 * id array (49 entries against 79 real evals) was the only answer the
 * published package could give.
 *
 * Eval SOURCE files are still read from a repo checkout when one is
 * present — the manifest tells us the count and the ids; the checkout
 * tells us the assertions. With no checkout the tools say so explicitly
 * rather than reporting "not found".
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import manifest from "../eval-manifest.json";

interface EvalEntry {
	id: string;
	/** Repo-relative path, e.g. `evals/pain-points/PP-G1.eval.ts`. */
	path: string;
	suite: string;
}

/** Flat id -> entry map. The ONLY set of ids these tools will act on. */
const EVALS: ReadonlyMap<string, EvalEntry> = new Map(
	Object.entries(manifest.suites).flatMap(([suite, entries]) =>
		(entries as { id: string; path: string }[]).map(
			(e) => [e.id, { ...e, suite }] as const,
		),
	),
);

const EVAL_IDS: readonly string[] = [...EVALS.keys()];

/**
 * Locate a repo checkout by walking up from the bundle looking for
 * `evals/pain-points`. Returns `null` when there is none — the normal
 * case for an `npx`-installed package.
 */
function findRepoRoot(): string | null {
	let dir = __dirname;
	for (let i = 0; i < 8; i++) {
		if (existsSync(join(dir, "evals", "pain-points"))) return dir;
		dir = join(dir, "..");
	}
	return null;
}

function readIndexMd(repoRoot: string | null): string | null {
	if (!repoRoot) return null;
	const indexPath = join(repoRoot, "evals", "pain-points", "INDEX.md");
	return existsSync(indexPath) ? readFileSync(indexPath, "utf8") : null;
}

function textResult(payload: unknown) {
	return {
		content: [{ type: "text" as const, text: JSON.stringify(payload) }],
	};
}

export function registerEvalTools(server: McpServer) {
	server.tool(
		"list_evals",
		"List all pain-point and fault-tolerance evals and their current status",
		{},
		async () => {
			const repoRoot = findRepoRoot();
			const indexContent = readIndexMd(repoRoot);

			return textResult({
				eval_count: manifest.total,
				eval_ids: EVAL_IDS,
				suites: Object.fromEntries(
					Object.entries(manifest.suites).map(([suite, entries]) => [
						suite,
						(entries as unknown[]).length,
					]),
				),
				// Honest about which surface answered: the count is always the
				// real corpus (bundled manifest); the excerpt needs a checkout.
				source: "bundled eval manifest (generated from evals/)",
				sources_available: repoRoot !== null,
				index_available: indexContent !== null,
				index_excerpt: indexContent
					? indexContent.slice(0, 2000)
					: "Eval sources are not part of the npm package — clone github.com/tracelane/tracelane to read assertions, or run `pnpm eval:index`.",
				hint: "Use get_eval_result with an eval ID for details",
			});
		},
	);

	server.tool(
		"get_eval_result",
		"Get the latest result for a specific eval",
		{
			eval_id: z.string().describe("Eval ID, e.g. PP-G3, PP-PR1, FT-01"),
		},
		async ({ eval_id }) => {
			// generated manifest and the PATH comes from the manifest entry —
			// never from the caller's string. An `eval_id` of
			// `../../../etc/passwd` cannot name a manifest entry, so traversal
			// is structurally impossible rather than regex-filtered. The old
			// regex also REJECTED 30+ real ids (`PP-AUDIT-TAMPER-DETECT`,
			// `FT-10-concurrent-promotion-rollback`), so it failed both ways.
			const entry = EVALS.get(eval_id);
			if (!entry) {
				return textResult({
					eval_id,
					error: `unknown eval id — not present in the ${manifest.total}-eval manifest`,
					known_eval_ids: EVAL_IDS,
				});
			}

			const repoRoot = findRepoRoot();
			if (!repoRoot) {
				return textResult({
					eval_id,
					suite: entry.suite,
					path: entry.path,
					error:
						"eval sources are not bundled in the npm package — clone github.com/tracelane/tracelane and run this server from the checkout to read assertions",
				});
			}

			const filePath = join(repoRoot, entry.path);
			if (!existsSync(filePath)) {
				return textResult({
					eval_id,
					suite: entry.suite,
					path: entry.path,
					error: `eval file listed in the manifest is missing from the checkout at ${filePath} — the manifest is stale (run \`pnpm --filter @tracelanedev/mcp gen:evals\`)`,
				});
			}

			const source = readFileSync(filePath, "utf8");
			const descMatch = source.match(/describe\(['"]([^'"]+)['"]/);
			const testMatches = [...source.matchAll(/it\(['"]([^'"]+)['"]/g)];

			return textResult({
				eval_id,
				file: filePath,
				suite: descMatch?.[1] ?? entry.suite,
				tests: testMatches.map((m) => m[1]),
				test_count: testMatches.length,
				hint: "Run `pnpm eval:run --suite=all` for live pass/fail status",
			});
		},
	);
}
