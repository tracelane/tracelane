/**
 * Tests for the Helicone/LiteLLM migration transforms (V1 Tier-A
 * `tlane import-*` / `tlane migrate`). These functions REWRITE customer env
 * files and source code, so a regression silently corrupts a migration —
 * worth locking the exact mappings.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	emitEnvStanza,
	parseEnvFile,
} from "../src/commands/import-helicone.js";
import { inferProviderName } from "../src/commands/import-litellm.js";
import {
	applyEnvTransforms,
	applySourceTransforms,
	hasHeliconeRef,
} from "../src/commands/migrate.js";

describe("migrate transforms (rewrite customer env + code)", () => {
	it("renames Helicone env keys to Tracelane, leaving others untouched", () => {
		const out = applyEnvTransforms(
			"HELICONE_API_KEY=sk-x\nHELICONE_BASE_URL=https://h\nDATABASE_URL=pg://y",
		);
		expect(out).toContain("TRACELANE_API_KEY=sk-x");
		expect(out).toContain("TRACELANE_GATEWAY_URL=https://h");
		expect(out).toContain("DATABASE_URL=pg://y");
		expect(out).not.toMatch(/^HELICONE_API_KEY=/m);
	});

	it("rewrites Helicone proxy base URLs to the Tracelane gateway", () => {
		const out = applySourceTransforms(
			'client = OpenAI(base_url="https://oai.helicone.ai/v1")',
		);
		expect(out).toContain("https://gateway.tracelane.dev/v1");
		expect(out).not.toContain("oai.helicone.ai");
	});

	it("detects Helicone references case-insensitively", () => {
		expect(hasHeliconeRef("import Helicone")).toBe(true);
		expect(hasHeliconeRef("os.environ['HELICONE_API_KEY']")).toBe(true);
		expect(hasHeliconeRef("import openai")).toBe(false);
	});
});

describe("import-litellm inferProviderName", () => {
	const cases: [string, string][] = [
		["openai/gpt-4o", "openai"],
		["anthropic/claude-3", "anthropic"],
		["gemini/gemini-pro", "google"],
		["vertex_ai/gemini-1.5", "google"],
		["bedrock/anthropic.claude", "bedrock"],
		["groq/llama-3", "groq"],
		["together_ai/mixtral", "together"],
	];
	it.each(cases)("maps %s -> %s", (model, provider) => {
		expect(inferProviderName(model)).toBe(provider);
	});
	it("defaults unknown / bare models to openai-compatible", () => {
		expect(inferProviderName("gpt-4o")).toBe("openai");
		expect(inferProviderName("some-unknown/model")).toBe("openai");
	});
});

describe("import-helicone parseEnvFile + emitEnvStanza", () => {
	let dir: string;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "hel-import-"));
	});
	afterEach(() => rmSync(dir, { recursive: true, force: true }));

	it("splits Helicone vars from others and emits a Tracelane stanza", () => {
		const f = join(dir, ".env");
		writeFileSync(
			f,
			"# a comment\nHELICONE_API_KEY=hl-secret\nDATABASE_URL=postgres://y\n",
		);
		const parsed = parseEnvFile(f);
		expect(parsed.heliconeVars.get("HELICONE_API_KEY")).toBe("hl-secret");
		expect(parsed.otherVars.get("DATABASE_URL")).toBe("postgres://y");

		const stanza = emitEnvStanza(parsed);
		expect(stanza).toContain("TRACELANE_API_KEY=hl-secret");
		expect(stanza).toContain("was HELICONE_API_KEY");
	});

	it("returns empty maps for a missing file (no throw)", () => {
		const parsed = parseEnvFile(join(dir, "does-not-exist.env"));
		expect(parsed.heliconeVars.size).toBe(0);
		expect(parsed.otherVars.size).toBe(0);
	});
});
