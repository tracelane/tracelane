/**
 * MCP tools for reading eval results.
 *
 * Reads from the local eval result cache produced by `pnpm eval:run`.
 * Falls back to the static INDEX.md listing if no cache is present.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

function findRepoRoot(): string {
	let dir = __dirname;
	for (let i = 0; i < 8; i++) {
		if (existsSync(join(dir, "evals", "pain-points"))) return dir;
		dir = join(dir, "..");
	}
	return __dirname;
}

function readIndexMd(): string | null {
	const repoRoot = findRepoRoot();
	const indexPath = join(repoRoot, "evals", "pain-points", "INDEX.md");
	if (existsSync(indexPath)) {
		return readFileSync(indexPath, "utf8");
	}
	return null;
}

const KNOWN_EVALS = [
	"PP-G1",
	"PP-G2",
	"PP-G3",
	"PP-G4",
	"PP-G5",
	"PP-O1",
	"PP-O2",
	"PP-O3",
	"PP-O4",
	"PP-O5",
	"PP-O6",
	"PP-O7",
	"PP-O8",
	"PP-O9",
	"PP-O10",
	"PP-O11",
	"PP-P1",
	"PP-P2",
	"PP-P3",
	"PP-P4",
	"PP-P5",
	"PP-P6",
	"PP-P7",
	"PP-P8",
	"PP-P9",
	"PP-P10",
	"PP-P11",
	"PP-P12",
	"PP-P13",
	"PP-PR1",
	"PP-PR2",
	"PP-PR3",
	"PP-PR4",
	"PP-PR5",
	"PP-PR6",
	"PP-PR7",
	"PP-PR8",
	"PP-PR9",
	"PP-PR10",
	"PP-PR11",
	"PP-PR12",
	"FT-01",
	"FT-02",
	"FT-03",
	"FT-04",
	"FT-05",
	"FT-06",
	"FT-07",
	"FT-08",
];

export function registerEvalTools(server: McpServer) {
	server.tool(
		"list_evals",
		"List all pain-point evals and their current status",
		{},
		async () => {
			const indexContent = readIndexMd();

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({
							eval_count: KNOWN_EVALS.length,
							eval_ids: KNOWN_EVALS,
							index_available: indexContent !== null,
							index_excerpt: indexContent
								? indexContent.slice(0, 2000)
								: "Run `pnpm eval:index` to generate INDEX.md",
							hint: "Use get_eval_result with an eval ID for details",
						}),
					},
				],
			};
		},
	);

	server.tool(
		"get_eval_result",
		"Get the latest result for a specific eval",
		{
			eval_id: z.string().describe("Eval ID, e.g. PP-G3, PP-PR1, FT-01"),
		},
		async ({ eval_id }) => {
			// eval-id shape (PP-*, FT-*, PR*). Without this, an
			// MCP client could traverse out of the evals/ directory
			// via `eval_id = "../../../etc/passwd"` (only files
			// ending in `.eval.ts` were readable, but defense in
			// depth costs nothing).
			if (!/^(PP-[A-Z0-9]+|FT-\d+|PR\d+)$/.test(eval_id)) {
				return {
					content: [
						{
							type: "text" as const,
							text: JSON.stringify({
								eval_id,
								error:
									"invalid eval_id shape — must match /^(PP-[A-Z0-9]+|FT-\\d+|PR\\d+)$/",
							}),
						},
					],
				};
			}

			const repoRoot = findRepoRoot();

			// Try to find the eval file
			const evalFile = join(
				repoRoot,
				"evals",
				"pain-points",
				`${eval_id}.eval.ts`,
			);
			const ftFile = join(
				repoRoot,
				"evals",
				"fault-tolerance",
				`${eval_id}.eval.ts`,
			);

			const filePath = existsSync(evalFile)
				? evalFile
				: existsSync(ftFile)
					? ftFile
					: null;

			if (!filePath) {
				return {
					content: [
						{
							type: "text" as const,
							text: JSON.stringify({
								eval_id,
								error: `Eval file not found. Known eval IDs: ${KNOWN_EVALS.join(", ")}`,
							}),
						},
					],
				};
			}

			// Read the eval source to extract description
			const source = readFileSync(filePath, "utf8");
			const descMatch = source.match(/describe\(['"]([^'"]+)['"]/);
			const testMatches = [...source.matchAll(/it\(['"]([^'"]+)['"]/g)];

			return {
				content: [
					{
						type: "text" as const,
						text: JSON.stringify({
							eval_id,
							file: filePath,
							suite: descMatch?.[1] ?? "unknown",
							tests: testMatches.map((m) => m[1]),
							test_count: testMatches.length,
							hint: "Run `pnpm eval:run --suite=all` for live pass/fail status",
						}),
					},
				],
			};
		},
	);
}
