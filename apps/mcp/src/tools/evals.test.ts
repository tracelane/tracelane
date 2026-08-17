/**
 * Eval-tool regression tests (PLT-21).
 *
 * These pin the two behaviours that changed when the hand-written 49-id
 * array was replaced by the generated manifest:
 *
 *   · `list_evals` reports the REAL corpus (79 = 69 pain-point + 10
 *     fault-tolerance), not a number that drifted 30 evals behind; and
 *   · `get_eval_result` reaches every real eval while still refusing
 *     anything that is not one — the retired shape regex
 *     `/^(PP-[A-Z0-9]+|FT-\d+|PR\d+)$/` failed BOTH ways, rejecting 30+
 *     legitimate hyphenated ids on top of the traversal strings it was
 *     written for.
 *
 * Accept/reject are asserted as pairs (`.claude/rules/testing.md`): an
 * accept-only suite would go green against a tool that accepts everything.
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
	it("reports the real corpus, both suites, from the generated manifest", async () => {
		const payload = await call("list_evals");
		expect(payload.eval_count).toBe(manifest.total);
		expect(payload.eval_ids).toHaveLength(manifest.total);
		expect(payload.suites).toEqual({
			"pain-points": manifest.suites["pain-points"].length,
			"fault-tolerance": manifest.suites["fault-tolerance"].length,
		});
		// Not the stale hand-written count. Pinned as a literal so a future
		// silent shrink back toward 49 is a failure, not a quiet re-baseline.
		expect(payload.eval_count).toBeGreaterThan(49);
	});
});

describe("get_eval_result — must accept", () => {
	// Both of these are real files that the retired regex rejected.
	it.each([
		["PP-G1", "pain-points"],
		["PP-AUDIT-TAMPER-DETECT", "pain-points"],
		["FT-10-concurrent-promotion-rollback", "fault-tolerance"],
	])("resolves %s and returns its assertions", async (id) => {
		const payload = await call("get_eval_result", { eval_id: id });
		expect(payload.error).toBeUndefined();
		expect(payload.eval_id).toBe(id);
		// A real eval file always declares at least one `it(...)`; returning
		// zero would mean we resolved a file but read nothing useful.
		expect(payload.test_count).toBeGreaterThan(0);
		expect(payload.tests?.length).toBe(payload.test_count);
	});
});

describe("get_eval_result — must reject", () => {
	it.each([
		["../../../etc/passwd"],
		["../../package.json"],
		["evals/pain-points/PP-G1.eval.ts"],
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
