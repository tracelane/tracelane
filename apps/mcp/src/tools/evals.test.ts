/**
 * Eval-tool regression tests (PLT-21).
 *
 * These pin the behaviours that changed when the hand-written 49-id array
 * was replaced by the generated manifest:
 *
 *   · `list_evals` reports the REAL corpus, not a number that drifted 30
 *     evals behind;
 *   · `get_eval_result` reaches every real eval while still refusing
 *     anything that is not one — the retired shape regex
 *     `/^(PP-[A-Z0-9]+|FT-\d+|PR\d+)$/` failed BOTH ways, rejecting 30+
 *     legitimate hyphenated ids on top of the traversal strings it was
 *     written for; and
 *   · a checkout is FOUND, so the assertions are actually readable.
 *
 * Accept/reject are asserted as pairs (`.claude/rules/testing.md`): an
 * accept-only suite would go green against a tool that accepts everything.
 *
 * ── EVERY CASE IS DERIVED FROM THE MANIFEST, AND THAT IS THE POINT ──────────
 * This file used to name `"pain-points"`, two `PP-` ids and the literal 49.
 * All three are properties of OUR tree, and the public export deliberately
 * withholds that suite — so the exported copy of this file failed `tsc`
 * (TS7053: `"pain-points"` cannot index a manifest that has only
 * fault-tolerance) and then failed four vitest cases behind it. The mirror's
 * own CI found it; nothing here did, because in this tree it is all true.
 *
 * A test that hard-codes what the tree happens to contain is a snapshot, not
 * an assertion. Corpus-size drift is `gen-eval-manifest.mjs --check`'s job and
 * it is BYTE-EXACT against `evals/`, which is strictly stronger than any
 * literal a human keeps up to date here.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { beforeAll, describe, expect, it } from "vitest";
import manifest from "../eval-manifest.json";
import { registerEvalTools } from "./evals.js";

interface EvalPayload {
	eval_count?: number;
	eval_ids?: string[];
	suites?: Record<string, number>;
	sources_available?: boolean;
	eval_id?: string;
	suite?: string;
	test_count?: number;
	tests?: string[];
	error?: string;
	known_eval_ids?: string[];
}

type Entry = { id: string; path: string };

const SUITES = Object.entries(manifest.suites) as [string, Entry[]][];
const ALL: Entry[] = SUITES.flatMap(([, entries]) => entries);

/** The retired shape regex. Any real id it REJECTS is a live regression case. */
const RETIRED_SHAPE = /^(PP-[A-Z0-9]+|FT-\d+|PR\d+)$/;

/**
 * One id from every suite present (so no suite goes unexercised), plus up to
 * two ids the retired regex would have refused — which is the regression that
 * actually shipped. Both halves come from the tree, so this stays honest in a
 * tree that withholds a suite.
 */
const ACCEPT_IDS: string[] = [
	...new Set([
		...SUITES.flatMap(([, e]) => (e[0] ? [e[0].id] : [])),
		...ALL.filter((e) => !RETIRED_SHAPE.test(e.id))
			.slice(0, 2)
			.map((e) => e.id),
	]),
];

let client: Client;

async function call(name: string, args: Record<string, unknown> = {}) {
	const res = (await client.callTool({ name, arguments: args })) as {
		content: { type: string; text: string }[];
	};
	const first = res.content[0];
	if (!first) throw new Error(`${name} returned no content`);
	return JSON.parse(first.text) as EvalPayload;
}

beforeAll(async () => {
	const server = new McpServer({ name: "test", version: "0.0.0" });
	registerEvalTools(server);
	const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
	client = new Client({ name: "evals-test", version: "0.0.0" });
	await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
});

describe("list_evals", () => {
	it("reports exactly the corpus the generated manifest holds", async () => {
		const payload = await call("list_evals");
		expect(payload.eval_count).toBe(manifest.total);
		expect(payload.eval_ids).toHaveLength(manifest.total);
		expect(payload.suites).toEqual(
			Object.fromEntries(SUITES.map(([suite, e]) => [suite, e.length])),
		);
		// A manifest with no suites at all would make every assertion above
		// vacuously true, so the corpus must be non-empty for this to mean
		// anything. The SIZE is gen-eval-manifest.mjs --check's job.
		expect(manifest.total).toBeGreaterThan(0);
	});

	it("finds the checkout it is running inside", async () => {
		// THE ASSERTION THAT WOULD HAVE CAUGHT THE SHIPPED DEFECT. `findRepoRoot`
		// probed `evals/pain-points` — a path the public export withholds — so in
		// a public clone this was false and `get_eval_result` told the user to
		// clone the repo they were already in. Nothing asserted it until now.
		const payload = await call("list_evals");
		expect(payload.sources_available).toBe(true);
	});
});

describe("get_eval_result — must accept", () => {
	it.each(ACCEPT_IDS.map((id) => [id]))(
		"resolves %s and returns its assertions",
		async (id) => {
			const payload = await call("get_eval_result", { eval_id: id });
			expect(payload.error).toBeUndefined();
			expect(payload.eval_id).toBe(id);
			// A real eval file always declares at least one `it(...)`; returning
			// zero would mean we resolved a file but read nothing useful.
			expect(payload.test_count).toBeGreaterThan(0);
			expect(payload.tests?.length).toBe(payload.test_count);
		},
	);
});

describe("get_eval_result — must reject", () => {
	it.each([
		["../../../etc/passwd"],
		["../../package.json"],
		// A real manifest PATH is not an id. Taken from the tree so the case
		// survives a withheld suite; hard-coding one was how this file broke.
		[ALL[0]?.path ?? "evals/nope/NOPE.eval.ts"],
		["PP-ZZZZ"],
		[""],
	])("refuses %j without touching the filesystem", async (id) => {
		const payload = await call("get_eval_result", { eval_id: id });
		expect(payload.error).toContain("unknown eval id");
		// The rejection names the corpus size, so the message itself cannot
		// go stale against the manifest.
		expect(payload.error).toContain(`${manifest.total}-eval manifest`);
		expect(payload.tests).toBeUndefined();
	});
});
