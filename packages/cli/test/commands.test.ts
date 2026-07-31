/**
 * Unit tests for the tlane init / eval / trace commands + the DPDP export pack.
 *
 * Tests the pure logic (config builder, INDEX parser, trace renderer) and the
 * trace fetch with an injected fetch — no live server, no child processes.
 * The DPDP pack is exercised against a tempdir and asserted to write real
 * evidence files (it previously wrote only placeholder manifest entries).
 */

import {
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseEvalIndex } from "../src/commands/eval.js";
import { buildDpdpPhase2Pack } from "../src/commands/export.js";
import { buildInitConfig, registerInitCommand } from "../src/commands/init.js";
import { fetchTrace, renderTrace } from "../src/commands/trace.js";

describe("tlane init — buildInitConfig", () => {
	it("strips a trailing slash and defaults sample rate to 1.0", () => {
		const c = buildInitConfig({
			endpoint: "https://ingest.tracelane.dev/",
			serviceName: "agent-x",
		});
		expect(c).toEqual({
			endpoint: "https://ingest.tracelane.dev",
			serviceName: "agent-x",
			sampleRate: 1.0,
		});
	});

	it("clamps sample rate into [0, 1]", () => {
		expect(
			buildInitConfig({ endpoint: "e", serviceName: "s", sampleRate: 2 })
				.sampleRate,
		).toBe(1);
		expect(
			buildInitConfig({ endpoint: "e", serviceName: "s", sampleRate: -1 })
				.sampleRate,
		).toBe(0);
		expect(
			buildInitConfig({ endpoint: "e", serviceName: "s", sampleRate: 0.25 })
				.sampleRate,
		).toBe(0.25);
	});
});

describe("tlane eval list — parseEvalIndex", () => {
	const md = [
		"# Index",
		"| ID | Title | Status | ref |",
		"|---|---|---|---|",
		"| **PP-G1** | **BYOK gateway** | **🟢 structural pass; ⏭️ live-skipped** | spec |",
		"| **PP-G3** | **5K RPS** | **⏭️ live perf — skipped** | ADR-002 |",
		"some prose line | not a row",
	].join("\n");

	it("extracts eval rows and strips bold markers", () => {
		const entries = parseEvalIndex(md);
		expect(entries).toHaveLength(2);
		expect(entries[0]).toMatchObject({ id: "PP-G1", title: "BYOK gateway" });
		expect(entries[0]?.status).toContain("structural pass");
		expect(entries[1]?.id).toBe("PP-G3");
	});

	it("skips header, separator, and prose rows", () => {
		const ids = parseEvalIndex(md).map((e) => e.id);
		expect(ids).not.toContain("ID");
		expect(ids.every((id) => id.startsWith("PP-"))).toBe(true);
	});
});

describe("tlane trace — renderTrace", () => {
	const trace = {
		spans: [
			{
				span_id: "a1b2c3",
				name: "llm.chat",
				duration_us: 1500,
				status_code: 0,
			},
			{
				span_id: "d4e5f6",
				name: "tool.search",
				duration_us: 500,
				status_code: 1,
			},
		],
	};

	it("renders json verbatim", () => {
		expect(JSON.parse(renderTrace(trace, "json"))).toEqual(trace);
	});

	it("renders a table with names and status", () => {
		const out = renderTrace(trace, "table");
		expect(out).toContain("llm.chat");
		expect(out).toContain("tool.search");
		expect(out).toContain("OK");
		expect(out).toContain("ERROR");
	});

	it("renders a timeline with proportional bars", () => {
		const out = renderTrace(trace, "timeline");
		expect(out).toContain("llm.chat");
		expect(out).toContain("█");
	});

	it("handles an empty trace gracefully", () => {
		expect(renderTrace({ spans: [] }, "table")).toBe("(no spans in trace)");
	});
});

describe("tlane trace — fetchTrace", () => {
	it("GETs the tenant-scoped URL with the api key header and parses JSON", async () => {
		let seenUrl = "";
		let seenKey: string | undefined;
		const fakeFetch = (async (url: string, init?: RequestInit) => {
			seenUrl = url;
			seenKey = (init?.headers as Record<string, string>)?.[
				"x-tracelane-api-key"
			];
			return {
				ok: true,
				status: 200,
				json: async () => ({ spans: [] }),
			} as Response;
		}) as unknown as typeof fetch;

		const out = await fetchTrace({
			endpoint: "https://app.tracelane.dev/",
			traceId: "trace 1/with?weird",
			apiKey: "tl_secret",
			fetchImpl: fakeFetch,
		});
		expect(seenUrl).toBe(
			"https://app.tracelane.dev/api/traces/trace%201%2Fwith%3Fweird",
		);
		expect(seenKey).toBe("tl_secret");
		expect(out).toEqual({ spans: [] });
	});

	it("throws on a non-2xx response", async () => {
		const fakeFetch = (async () =>
			({
				ok: false,
				status: 404,
				json: async () => ({}),
			}) as Response) as unknown as typeof fetch;
		await expect(
			fetchTrace({ endpoint: "e", traceId: "x", fetchImpl: fakeFetch }),
		).rejects.toThrow("HTTP 404");
	});
});

describe("tlane export — DPDP Phase 2 pack writes real evidence files", () => {
	let dir: string;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "dpdp-pack-"));
	});
	afterEach(() => rmSync(dir, { recursive: true, force: true }));

	it("emits three included items, each backed by a real markdown file", () => {
		const manifest = buildDpdpPhase2Pack(dir);
		expect(manifest.pack).toBe("dpdp-phase-2");
		expect(manifest.items).toHaveLength(3);
		// No more placeholders — every item is backed by a file.
		for (const item of manifest.items) {
			expect(item.status).toBe("included");
			const body = readFileSync(join(dir, item.filename), "utf8");
			expect(body.length).toBeGreaterThan(200);
			expect(body).toContain("DPDP");
		}
		const files = readdirSync(dir);
		expect(files).toContain("dpdp-01-localisation.md");
		expect(files).toContain("dpdp-02-consent.md");
		expect(files).toContain("dpdp-03-rights.md");
		expect(files).toContain("manifest.json");
	});
});


describe("tlane init — writes atomically (no check-then-write race)", () => {
	// Regression for CodeQL js/file-system-race (high): the command used to
	// `existsSync(target)` and THEN `writeFileSync`, so anything appearing in the
	// window between the two — including a symlink to a path the user never meant
	// to touch — was overwritten without --force. The write is now a single `wx`
	// syscall, which is why the refusal is asserted through the EEXIST path.
	let dir: string;
	let cwd: string;

	beforeEach(() => {
		cwd = process.cwd();
		dir = mkdtempSync(join(tmpdir(), "tlane-init-"));
		process.chdir(dir);
	});
	afterEach(() => {
		process.chdir(cwd);
		rmSync(dir, { recursive: true, force: true });
		vi.restoreAllMocks();
	});

	const runInit = async (argv: string[]) => {
		const program = new Command();
		program.exitOverride();
		registerInitCommand(program);
		vi.spyOn(console, "log").mockImplementation(() => {});
		vi.spyOn(console, "error").mockImplementation(() => {});
		vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`process.exit:${code}`);
		}) as never);
		return program.parseAsync(["node", "tlane", "init", ...argv]);
	};

	it("refuses to clobber an existing config and leaves it byte-identical", async () => {
		const target = join(dir, "tracelane.config.json");
		writeFileSync(target, '{"do":"not clobber"}');
		await expect(runInit([])).rejects.toThrow("process.exit:1");
		expect(readFileSync(target, "utf-8")).toBe('{"do":"not clobber"}');
	});

	it("writes the config when none exists", async () => {
		await runInit(["--service-name", "agent-x"]);
		const written = JSON.parse(
			readFileSync(join(dir, "tracelane.config.json"), "utf-8"),
		);
		expect(written.serviceName).toBe("agent-x");
	});

	it("--force overwrites an existing config", async () => {
		const target = join(dir, "tracelane.config.json");
		writeFileSync(target, '{"stale":true}');
		await runInit(["--force", "--service-name", "agent-y"]);
		const written = JSON.parse(readFileSync(target, "utf-8"));
		expect(written.serviceName).toBe("agent-y");
		expect(written.stale).toBeUndefined();
	});
});
