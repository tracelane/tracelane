/**
 * PLT-21 distribution proof — the END STATE, not a 200.
 *
 * The question this file answers is "can a user who runs
 * `npx @tracelanedev/mcp` get a working MCP server?", so it does what npx
 * does and nothing softer:
 *
 *   1. packs the package with `pnpm pack` — the exact tarball
 *      `.github/workflows/release.yml` hands to `npm publish`;
 *   2. unpacks it into a throwaway `node_modules/@tracelanedev/mcp`
 *      OUTSIDE the repo, with its runtime dependencies resolvable beside
 *      it — the layout an install leaves behind, and critically one with
 *      no repo checkout at any depth above it;
 *   3. EXECUTES the installed file with NO interpreter — the way npm's
 *      POSIX bin symlink does — so a missing hashbang or a non-executable
 *      mode fails here instead of in a customer's terminal;
 *   4. speaks real MCP over stdio with the official SDK client and asserts
 *      the tool surface AND a tool result come back.
 *
 * Steps 2–3 are the ones that were untested and wrong. `@tracelanedev/mcp`
 * 0.1.0 built `dist/index.js` with no hashbang and mode 0644, so the `npx`
 * one-liner the README advertises could not have run even once the package
 * reached the registry; and `list_evals` located the eval corpus by walking
 * up from `__dirname` for `evals/`, which exists in a checkout and never
 * inside `node_modules`.
 *
 * Dependencies are linked from the workspace rather than fetched, so this
 * runs offline and deterministically. Resolution of the declared semver
 * ranges is npm's job and is covered by the release workflow's own
 * `npm publish` + a manual `pnpm add <tarball>` install.
 */

import { execFileSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	realpathSync,
	rmSync,
	statSync,
	symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const PKG_ROOT = resolve(__dirname, "..");

/** Every tool the published server must expose. */
const EXPECTED_TOOLS = [
	"list_traces",
	"get_trace",
	"get_span",
	"search_traces",
	"explain_guardrail_block",
	"list_evals",
	"get_eval_result",
	"replay_trace",
];

let scratch: string;
/** `<scratch>/consumer` — the fake project that "installed" the package. */
let consumer: string;
/** The installed package root, i.e. `…/node_modules/@tracelanedev/mcp`. */
let installed: string;
/** The `bin` target inside the installed package. */
let binPath: string;

beforeAll(() => {
	execFileSync("pnpm", ["run", "build"], { cwd: PKG_ROOT, stdio: "pipe" });

	scratch = mkdtempSync(join(tmpdir(), "tracelane-mcp-dist-"));
	consumer = join(scratch, "consumer");
	const nodeModules = join(consumer, "node_modules");
	mkdirSync(join(nodeModules, "@tracelanedev"), { recursive: true });

	const packDir = join(scratch, "tgz");
	mkdirSync(packDir, { recursive: true });
	execFileSync("pnpm", ["pack", "--pack-destination", packDir], {
		cwd: PKG_ROOT,
		stdio: "pipe",
	});
	const tgz = readdirSync(packDir).find((f) => f.endsWith(".tgz"));
	if (!tgz) throw new Error("pnpm pack produced no tarball");

	// The tarball's single top-level dir is `package/`; strip it so the
	// contents land directly at node_modules/@tracelanedev/mcp — the exact
	// path an install produces.
	installed = join(nodeModules, "@tracelanedev", "mcp");
	mkdirSync(installed, { recursive: true });
	execFileSync("tar", [
		"-xzf",
		join(packDir, tgz),
		"-C",
		installed,
		"--strip-components=1",
	]);

	// Make the runtime deps resolvable from `<consumer>/node_modules`, which
	// is where Node's lookup lands when requiring from inside the installed
	// package. Linked, not downloaded, so the test is offline-deterministic.
	for (const entry of readdirSync(join(PKG_ROOT, "node_modules"))) {
		if (entry.startsWith(".") || entry === "@tracelanedev") continue;
		const target = join(PKG_ROOT, "node_modules", entry);
		symlinkSync(realpathSync(target), join(nodeModules, entry), "dir");
	}

	const manifest = JSON.parse(
		readFileSync(join(installed, "package.json"), "utf8"),
	) as { bin: Record<string, string> };
	const binRel = Object.values(manifest.bin)[0];
	if (!binRel) throw new Error("packed package.json declares no bin");
	binPath = resolve(installed, binRel);

	// npm chmods bin targets to 0o755 on install; reproduce that step so the
	// direct-exec assertion below tests the HASHBANG rather than the umask
	// of whoever ran `pnpm pack`.
	if (existsSync(binPath)) chmodSync(binPath, 0o755);
});

afterAll(() => {
	if (scratch) rmSync(scratch, { recursive: true, force: true });
});

describe("published tarball", () => {
	it("ships the bin target declared in package.json", () => {
		expect(existsSync(binPath)).toBe(true);
		expect(binPath.startsWith(installed)).toBe(true);
	});

	it("starts the bin target with a node hashbang", () => {
		// The negative this pins: WITHOUT this line npm's POSIX bin symlink
		// hands the file to the shell and `npx @tracelanedev/mcp` dies with
		// "Exec format error" / a syntax error. 0.1.0 would have failed here.
		const head = readFileSync(binPath, "utf8").slice(0, 32);
		expect(head.startsWith("#!/usr/bin/env node")).toBe(true);
	});

	it("carries the mcpName the MCP registry validates ownership against", () => {
		const packed = JSON.parse(
			readFileSync(join(installed, "package.json"), "utf8"),
		) as { mcpName?: string; version: string };
		const server = JSON.parse(
			readFileSync(join(PKG_ROOT, "server.json"), "utf8"),
		) as { name: string; version: string };
		// The registry fetches this exact field off the npm version metadata
		// and rejects the submission when it is absent or does not match
		// (registry internal/validators/registries/npm.go:90,94).
		expect(packed.mcpName).toBe(server.name);
		expect(packed.version).toBe(server.version);
	});

	it("does not ship a repo checkout with it", () => {
		// Guards the assumption the launch test rests on: if the tarball ever
		// started shipping `evals/`, the no-checkout assertions below would
		// pass for the wrong reason.
		//
		// It probes `evals/` itself, not `evals/pain-points`. The old probe named
		// a suite the public export withholds, so it asserted the ABSENCE of
		// something already absent by policy — true for the wrong reason, and one
		// character away from the defect that shipped in `findRepoRoot`. Absence
		// of `evals/` at every level is what actually makes the walk return null,
		// whatever suites the manifest names.
		expect(existsSync(join(installed, "evals"))).toBe(false);
		let dir = installed;
		for (let i = 0; i < 8; i++) {
			expect(existsSync(join(dir, "evals"))).toBe(false);
			dir = resolve(dir, "..");
		}
	});
});

describe("npx-equivalent launch", () => {
	it("serves the full MCP tool surface when exec'd with no interpreter", async () => {
		expect(statSync(binPath).mode & 0o111).not.toBe(0);

		const client = new Client({ name: "plt-21-proof", version: "1.0.0" });
		// `command: binPath` with no args = execve on the file itself,
		// which is what `node_modules/.bin/tracelane-mcp` resolves to on
		// an npm install.
		const transport = new StdioClientTransport({
			command: binPath,
			cwd: consumer,
		});

		try {
			await client.connect(transport);

			const info = client.getServerVersion();
			expect(info?.name).toBe("tracelane");
			// Reported version must be the installed one — it was pinned at
			// "0.1.0" in source while the package moved on.
			const packed = JSON.parse(
				readFileSync(join(installed, "package.json"), "utf8"),
			) as { version: string };
			expect(info?.version).toBe(packed.version);

			const { tools } = await client.listTools();
			expect(tools.map((t) => t.name).sort()).toEqual(
				[...EXPECTED_TOOLS].sort(),
			);

			// A tool RESULT, not just a registration. `list_evals` is the
			// one tool needing no ClickHouse, so it is the honest
			// end-to-end assertion available without a live stack.
			const res = (await client.callTool({
				name: "list_evals",
				arguments: {},
			})) as { content: { type: string; text: string }[] };
			const first = res.content[0];
			if (!first) throw new Error("list_evals returned no content");
			const payload = JSON.parse(first.text) as {
				eval_count: number;
				eval_ids: string[];
				sources_available: boolean;
			};

			// The corpus is reported from the BUNDLED manifest, so it is
			// right with no checkout in sight — the state the hardcoded
			// 49-id array could not reach.
			const expected = JSON.parse(
				readFileSync(join(PKG_ROOT, "src", "eval-manifest.json"), "utf8"),
			) as { total: number; suites: Record<string, { id: string }[]> };
			expect(payload.eval_count).toBe(expected.total);
			expect(payload.eval_ids).toHaveLength(expected.total);
			expect(payload.sources_available).toBe(false);

			// Ids only a manifest-driven list can hold — the retired shape regex
			// `/^(PP-[A-Z0-9]+|FT-\d+|PR\d+)$/` rejected every one of them.
			//
			// TAKEN FROM THE MANIFEST, NOT NAMED. This asserted two literal ids,
			// one of them from `evals/pain-points` — a suite the public export
			// withholds — so the exported copy of this test failed on a tarball
			// that was behaving perfectly. Same defect as the sibling file, found
			// the same way: by running the suite inside a built export.
			const hyphenated = Object.values(expected.suites)
				.flat()
				.map((e) => e.id)
				.filter((id) => !/^(PP-[A-Z0-9]+|FT-\d+|PR\d+)$/.test(id));
			// The corpus must actually CONTAIN such an id, or the loop below
			// passes by being empty — the regression would go unguarded silently.
			expect(hyphenated.length).toBeGreaterThan(0);
			for (const id of hyphenated.slice(0, 2)) {
				expect(payload.eval_ids).toContain(id);
			}
		} finally {
			await client.close().catch(() => undefined);
		}
	}, 60_000);
});
