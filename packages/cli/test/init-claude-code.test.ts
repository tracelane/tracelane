/**
 * `tlane init claude-code` — PLT-46 end-state tests.
 *
 * Two layers, mirroring `init.test.ts` / `commands.test.ts` conventions:
 * pure functions (`buildClaudeCodeEnv`, `mergeClaudeSettings`, …) tested
 * directly, and the full command tested through `registerInitCommand` with an
 * injected `fetchImpl` — no live gateway, no real `~/.claude/settings.json`
 * touched (every test runs in a temp dir with `--project`, or targets
 * `settingsPath` directly).
 */

import {
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	buildClaudeCodeEnv,
	checkChatScope,
	checkIngestScope,
	checkWhoami,
	envAsShellExports,
	mergeClaudeSettings,
	settingsPath,
} from "../src/commands/init-claude-code.js";
import { registerInitCommand } from "../src/commands/init.js";

function jsonResponse(body: unknown, status = 200): Response {
	return {
		ok: status >= 200 && status < 300,
		status,
		json: async () => body,
	} as Response;
}

// ── pure functions ──────────────────────────────────────────────────────────

describe("buildClaudeCodeEnv", () => {
	it("emits exactly the nine spec variables, gateway trailing slash stripped", () => {
		const env = buildClaudeCodeEnv("https://gateway.tracelane.dev/", "tlane_x");
		expect(Object.keys(env)).toEqual([
			"CLAUDE_CODE_ENABLE_TELEMETRY",
			"CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
			"OTEL_TRACES_EXPORTER",
			"OTEL_METRICS_EXPORTER",
			"OTEL_LOGS_EXPORTER",
			"OTEL_EXPORTER_OTLP_PROTOCOL",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
			"OTEL_EXPORTER_OTLP_HEADERS",
			"OTEL_RESOURCE_ATTRIBUTES",
		]);
		expect(env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT).toBe(
			"https://gateway.tracelane.dev/v1/traces",
		);
		expect(env.OTEL_EXPORTER_OTLP_HEADERS).toBe("Authorization=Bearer tlane_x");
		expect(env.OTEL_RESOURCE_ATTRIBUTES).toBe(
			"service.name=claude-code,gen_ai.agent.name=claude-code",
		);
	});
});

describe("buildClaudeCodeEnv --proxy", () => {
	it("appends exactly the two GWY-47 variables and changes nothing else", () => {
		const plain = buildClaudeCodeEnv("https://gw/", "tlane_x");
		const proxied = buildClaudeCodeEnv("https://gw/", "tlane_x", true);
		expect(Object.keys(proxied)).toEqual([
			...Object.keys(plain),
			"ANTHROPIC_BASE_URL",
			"ANTHROPIC_AUTH_TOKEN",
		]);
		// The nine OTel variables must be byte-identical: proxy mode ADDS a
		// recording path, it does not alter the existing one.
		for (const k of Object.keys(plain)) {
			expect(proxied[k]).toBe(plain[k]);
		}
		expect(proxied.ANTHROPIC_BASE_URL).toBe("https://gw");
		expect(proxied.ANTHROPIC_AUTH_TOKEN).toBe("tlane_x");
	});

	it("writes nothing Anthropic-shaped without the flag", () => {
		const plain = buildClaudeCodeEnv("https://gw", "tlane_x");
		expect(plain.ANTHROPIC_BASE_URL).toBeUndefined();
		expect(plain.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
	});
});

describe("checkChatScope", () => {
	it("is ok on 400 — the scope gate passed and the empty body was refused after it", async () => {
		const fake = (async () =>
			jsonResponse(
				{ error: { type: "invalid_request_error", code: "invalid_request" } },
				400,
			)) as unknown as typeof fetch;
		await expect(
			checkChatScope("https://gw", "tlane_x", fake),
		).resolves.toEqual({
			verdict: "ok",
		});
	});

	it("reports missing_chat with the gateway's nested message on 403", async () => {
		const fake = (async () =>
			jsonResponse(
				{
					type: "error",
					error: {
						type: "permission_error",
						message: "This API key is not scoped for completions.",
						code: "insufficient_scope",
						required_scope: "chat",
					},
				},
				403,
			)) as unknown as typeof fetch;
		const res = await checkChatScope("https://gw", "tlane_x", fake);
		expect(res.verdict).toBe("missing_chat");
		if (res.verdict === "missing_chat") {
			expect(res.message).toContain("not scoped for completions");
		}
	});

	it("is undetermined — never a scope failure — on 404, an odd status, or a network error", async () => {
		// A 404 means the gateway predates GWY-47. That needs a different fix
		// from "mint a key with the chat scope", so it must not be reported as
		// the scope failing.
		for (const status of [404, 500, 502]) {
			const fake = (async () =>
				jsonResponse({}, status)) as unknown as typeof fetch;
			await expect(
				checkChatScope("https://gw", "tlane_x", fake),
			).resolves.toEqual({ verdict: "undetermined", status });
		}
		const boom = (async () => {
			throw new Error("ECONNREFUSED");
		}) as unknown as typeof fetch;
		await expect(
			checkChatScope("https://gw", "tlane_x", boom),
		).resolves.toEqual({
			verdict: "undetermined",
			status: 0,
		});
	});

	it("probes POST /v1/messages with an empty body, so nothing is dispatched or ledgered", async () => {
		let seen: { url: string; init?: RequestInit } | undefined;
		const fake = (async (url: string, init?: RequestInit) => {
			seen = { url: String(url), init };
			return jsonResponse({}, 400);
		}) as unknown as typeof fetch;
		await checkChatScope("https://gw/", "tlane_x", fake);
		expect(seen?.url).toBe("https://gw/v1/messages");
		expect(seen?.init?.method).toBe("POST");
		// `{}` has no `model`, so the handler refuses it after the scope gate and
		// before the audit publish — the probe cannot spend money or write a row.
		expect(seen?.init?.body).toBe("{}");
	});
});

describe("envAsShellExports", () => {
	it("quotes values and escapes an embedded single quote", () => {
		const out = envAsShellExports({ A: "1", B: "it's" });
		expect(out).toBe("export A='1'\nexport B='it'\\''s'");
	});
});

describe("checkWhoami", () => {
	it("returns ok:true with the tenant id on 200", async () => {
		const fake = (async () =>
			jsonResponse({
				tenant_id: "t-1",
				auth_method: "ApiKey",
			})) as unknown as typeof fetch;
		const res = await checkWhoami("https://gw", "tlane_x", fake);
		expect(res).toEqual({ ok: true, tenantId: "t-1" });
	});

	it("returns ok:false with the gateway's message on 401", async () => {
		const fake = (async () =>
			jsonResponse(
				{ error: "invalid credentials" },
				401,
			)) as unknown as typeof fetch;
		const res = await checkWhoami("https://gw", "tlane_bad", fake);
		expect(res).toEqual({
			ok: false,
			status: 401,
			message: "invalid credentials",
		});
	});
});

describe("checkIngestScope", () => {
	it("is ok on 200 (empty batch accepted)", async () => {
		let seenBody: unknown;
		let seenContentType: string | undefined;
		const fake = (async (_url: string, init?: RequestInit) => {
			seenBody = init?.body;
			seenContentType = (init?.headers as Record<string, string>)?.[
				"content-type"
			];
			return jsonResponse({});
		}) as unknown as typeof fetch;
		const res = await checkIngestScope("https://gw", "tlane_x", fake);
		expect(res).toEqual({ verdict: "ok" });
		expect(seenBody).toBe(JSON.stringify({ resourceSpans: [] }));
		expect(seenContentType).toBe("application/json");
	});

	it("is ok on 503 (capture_disabled — the scope gate already passed)", async () => {
		const fake = (async () =>
			jsonResponse(
				{ error: "capture_disabled" },
				503,
			)) as unknown as typeof fetch;
		const res = await checkIngestScope("https://gw", "tlane_x", fake);
		expect(res).toEqual({ verdict: "ok" });
	});

	it("reports missing_ingest with the gateway's nested message on 403", async () => {
		const fake = (async () =>
			jsonResponse(
				{
					error: {
						message: "This API key is not scoped to send traces.",
						type: "insufficient_scope",
						required_scope: "ingest",
					},
				},
				403,
			)) as unknown as typeof fetch;
		const res = await checkIngestScope("https://gw", "tlane_x", fake);
		expect(res).toEqual({
			verdict: "missing_ingest",
			message: "This API key is not scoped to send traces.",
		});
	});

	it("is undetermined, never blocking, on a network failure or odd status", async () => {
		const netFail = (async () => {
			throw new Error("ECONNREFUSED");
		}) as unknown as typeof fetch;
		expect(await checkIngestScope("https://gw", "k", netFail)).toEqual({
			verdict: "undetermined",
			status: 0,
		});

		const weird = (async () =>
			jsonResponse({}, 500)) as unknown as typeof fetch;
		expect(await checkIngestScope("https://gw", "k", weird)).toEqual({
			verdict: "undetermined",
			status: 500,
		});
	});
});

describe("mergeClaudeSettings", () => {
	it("creates a fresh file with the full env block when none existed", () => {
		const merge = mergeClaudeSettings(
			undefined,
			{ A: "1", B: "2" },
			"/tmp/settings.json",
		);
		expect(JSON.parse(merge.content)).toEqual({ env: { A: "1", B: "2" } });
		expect(merge.written).toEqual(["A", "B"]);
		expect(merge.skipped).toEqual([]);
	});

	it("preserves unrelated top-level keys and unrelated + existing env keys, never overwriting", () => {
		const existing = JSON.stringify(
			{
				permissions: { allow: ["Bash(ls:*)"] },
				env: { UNRELATED: "keep-me", CLAUDE_CODE_ENABLE_TELEMETRY: "0" },
			},
			null,
			2,
		);
		const merge = mergeClaudeSettings(
			existing,
			{ CLAUDE_CODE_ENABLE_TELEMETRY: "1", OTEL_TRACES_EXPORTER: "otlp" },
			"/tmp/settings.json",
		);
		const parsed = JSON.parse(merge.content);
		expect(parsed.permissions).toEqual({ allow: ["Bash(ls:*)"] });
		// existing value untouched, even though the new block wanted "1"
		expect(parsed.env.CLAUDE_CODE_ENABLE_TELEMETRY).toBe("0");
		expect(parsed.env.UNRELATED).toBe("keep-me");
		expect(parsed.env.OTEL_TRACES_EXPORTER).toBe("otlp");
		expect(merge.written).toEqual(["OTEL_TRACES_EXPORTER"]);
		expect(merge.skipped).toEqual(["CLAUDE_CODE_ENABLE_TELEMETRY"]);
	});

	it("preserves the existing file's indentation", () => {
		const existingTabIndented = '{\n\t"env": {\n\t\t"X": "1"\n\t}\n}\n';
		const merge = mergeClaudeSettings(
			existingTabIndented,
			{ Y: "2" },
			"/tmp/settings.json",
		);
		expect(merge.content).toContain('\t"env"');
		expect(merge.content).toContain('\t\t"Y": "2"');
	});

	it("throws naming the file on invalid JSON, and never on valid-JSON-but-non-object", () => {
		expect(() =>
			mergeClaudeSettings("{not json", { A: "1" }, "/x/settings.json"),
		).toThrow(/x\/settings\.json is not valid JSON/);
		expect(() =>
			mergeClaudeSettings("[1,2,3]", { A: "1" }, "/x/settings.json"),
		).toThrow(/does not contain a JSON object/);
	});
});

describe("settingsPath", () => {
	it("targets ./.claude/settings.json under --project, else the home dir", () => {
		expect(settingsPath(true, "/work/proj")).toBe(
			join("/work/proj", ".claude", "settings.json"),
		);
		expect(settingsPath(false)).toContain(join(".claude", "settings.json"));
		expect(settingsPath(false)).not.toContain("/work/proj");
	});
});

// ── full command, through registerInitCommand ───────────────────────────────

describe("tlane init claude-code — command", () => {
	let dir: string;
	let cwd: string;
	let out: string[];
	let errOut: string[];

	beforeEach(() => {
		cwd = process.cwd();
		dir = mkdtempSync(join(tmpdir(), "tlane-init-cc-"));
		process.chdir(dir);
		out = [];
		errOut = [];
	});

	afterEach(() => {
		process.chdir(cwd);
		rmSync(dir, { recursive: true, force: true });
		vi.restoreAllMocks();
	});

	function run(argv: string[], fetchImpl: typeof fetch) {
		const program = new Command();
		program.exitOverride();
		registerInitCommand(program, { fetchImpl });
		vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
			out.push(a.join(" "));
		});
		vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => {
			errOut.push(a.join(" "));
		});
		vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`process.exit:${code}`);
		}) as never);
		return program.parseAsync([
			"node",
			"tlane",
			"init",
			"claude-code",
			...argv,
		]);
	}

	const okWhoami = async () => jsonResponse({ tenant_id: "t-1" });
	function happyFetch(): typeof fetch {
		return (async (url: string) => {
			const u = String(url);
			if (u.endsWith("/v1/auth/whoami")) return okWhoami();
			if (u.endsWith("/v1/traces")) return jsonResponse({});
			throw new Error(`unexpected fetch: ${u}`);
		}) as unknown as typeof fetch;
	}

	it("--print emits JSON and export lines, writes nothing", async () => {
		await run(
			["--api-key", "tlane_secret", "--gateway", "https://gw", "--print"],
			happyFetch(),
		);
		const joined = out.join("\n");
		expect(joined).toContain('"OTEL_TRACES_EXPORTER": "otlp"');
		expect(joined).toContain("export OTEL_TRACES_EXPORTER='otlp'");
		expect(existsSync(join(dir, ".claude", "settings.json"))).toBe(false);
	});

	it("creates ./.claude/settings.json under --project", async () => {
		await run(
			["--api-key", "tlane_secret", "--gateway", "https://gw", "--project"],
			happyFetch(),
		);
		const target = join(dir, ".claude", "settings.json");
		expect(existsSync(target)).toBe(true);
		const settings = JSON.parse(readFileSync(target, "utf8"));
		expect(settings.env.OTEL_TRACES_EXPORTER).toBe("otlp");
		expect(settings.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT).toBe(
			"https://gw/v1/traces",
		);
	});

	it("merges into an existing settings.json, preserving unrelated keys and never overwriting", async () => {
		const dirWithFile = mkdtempSync(join(tmpdir(), "tlane-init-cc-existing-"));
		process.chdir(dirWithFile);
		const target = join(dirWithFile, ".claude", "settings.json");
		const { mkdirSync } = await import("node:fs");
		mkdirSync(join(dirWithFile, ".claude"), { recursive: true });
		writeFileSync(
			target,
			`${JSON.stringify(
				{
					model: "opus",
					env: { OTEL_TRACES_EXPORTER: "console", KEEP: "me" },
				},
				null,
				2,
			)}\n`,
		);

		await run(
			["--api-key", "tlane_secret", "--gateway", "https://gw", "--project"],
			happyFetch(),
		);

		const settings = JSON.parse(readFileSync(target, "utf8"));
		expect(settings.model).toBe("opus");
		expect(settings.env.KEEP).toBe("me");
		// pre-existing value wins even though the new block wanted "otlp"
		expect(settings.env.OTEL_TRACES_EXPORTER).toBe("console");
		expect(settings.env.CLAUDE_CODE_ENABLE_TELEMETRY).toBe("1");

		process.chdir(cwd);
		rmSync(dirWithFile, { recursive: true, force: true });
	});

	it("401 from whoami: exits 1, writes nothing", async () => {
		const fake = (async () =>
			jsonResponse(
				{ error: "invalid credentials" },
				401,
			)) as unknown as typeof fetch;

		await expect(
			run(
				["--api-key", "tlane_bad", "--gateway", "https://gw", "--project"],
				fake,
			),
		).rejects.toThrow("process.exit:1");

		expect(errOut.join("\n")).toContain("invalid credentials");
		expect(existsSync(join(dir, ".claude", "settings.json"))).toBe(false);
	});

	it("a key missing the ingest scope: exits 1, writes nothing", async () => {
		const fake = (async (url: string) => {
			const u = String(url);
			if (u.endsWith("/v1/auth/whoami")) return okWhoami();
			return jsonResponse(
				{
					error: {
						message:
							"This API key is not scoped to send traces. It needs the `ingest` scope; mint a new key with it in Settings → API Keys.",
						required_scope: "ingest",
					},
				},
				403,
			);
		}) as unknown as typeof fetch;

		await expect(
			run(
				["--api-key", "tlane_readonly", "--gateway", "https://gw", "--project"],
				fake,
			),
		).rejects.toThrow("process.exit:1");

		expect(errOut.join("\n")).toContain("ingest");
		expect(existsSync(join(dir, ".claude", "settings.json"))).toBe(false);
	});

	it("no key (flag or env): usage error, exits 2", async () => {
		const savedEnv = process.env.TRACELANE_API_KEY;
		process.env.TRACELANE_API_KEY = "";
		try {
			await expect(
				run(["--gateway", "https://gw"], happyFetch()),
			).rejects.toThrow("process.exit:2");
		} finally {
			if (savedEnv === undefined) {
				// biome-ignore lint/performance/noDelete: an undefined ASSIGNMENT stringifies to "undefined" in process.env (truthy) — delete is the only way to restore "unset".
				delete process.env.TRACELANE_API_KEY;
			} else {
				process.env.TRACELANE_API_KEY = savedEnv;
			}
		}
		expect(errOut.join("\n")).toContain("no API key");
	});

	it("--proxy writes the two Anthropic variables alongside the OTel block", async () => {
		const seen: string[] = [];
		const fake = (async (url: string) => {
			const u = String(url);
			seen.push(u);
			if (u.endsWith("/v1/auth/whoami")) return okWhoami();
			if (u.endsWith("/v1/traces")) return jsonResponse({});
			if (u.endsWith("/v1/messages")) return jsonResponse({}, 400);
			throw new Error(`unexpected fetch: ${u}`);
		}) as unknown as typeof fetch;

		await run(
			[
				"--api-key",
				"tlane_secret",
				"--gateway",
				"https://gw",
				"--project",
				"--proxy",
			],
			fake,
		);

		const written = JSON.parse(
			readFileSync(join(dir, ".claude", "settings.json"), "utf8"),
		) as { env: Record<string, string> };
		expect(written.env.ANTHROPIC_BASE_URL).toBe("https://gw");
		expect(written.env.ANTHROPIC_AUTH_TOKEN).toBe("tlane_secret");
		// The OTel block is still there — proxy mode adds, never replaces.
		expect(written.env.OTEL_TRACES_EXPORTER).toBe("otlp");
		expect(seen).toContain("https://gw/v1/messages");
		// BYOK is a prerequisite, and the user has to be told BEFORE being told to
		// start a session — otherwise every call in that session is refused.
		const joined = out.join("\n");
		expect(joined).toContain("Settings → LLM providers");
		expect(joined.indexOf("LLM providers")).toBeLessThan(
			joined.indexOf("Start a new Claude Code session"),
		);
	});

	it("--proxy with a key lacking the chat scope: exits 1, writes nothing", async () => {
		const fake = (async (url: string) => {
			const u = String(url);
			if (u.endsWith("/v1/auth/whoami")) return okWhoami();
			if (u.endsWith("/v1/traces")) return jsonResponse({});
			if (u.endsWith("/v1/messages")) {
				return jsonResponse(
					{
						type: "error",
						error: {
							type: "permission_error",
							message:
								"This API key is not scoped for completions. It needs the `chat` scope; mint a new key with it in Settings → API Keys.",
							code: "insufficient_scope",
						},
					},
					403,
				);
			}
			throw new Error(`unexpected fetch: ${u}`);
		}) as unknown as typeof fetch;

		await expect(
			run(
				[
					"--api-key",
					"tlane_ingest_only",
					"--gateway",
					"https://gw",
					"--project",
					"--proxy",
				],
				fake,
			),
		).rejects.toThrow("process.exit:1");

		expect(errOut.join("\n")).toContain("chat");
		expect(existsSync(join(dir, ".claude", "settings.json"))).toBe(false);
	});

	it("without --proxy the chat scope is never probed and nothing Anthropic-shaped is written", async () => {
		const seen: string[] = [];
		const fake = (async (url: string) => {
			const u = String(url);
			seen.push(u);
			if (u.endsWith("/v1/auth/whoami")) return okWhoami();
			if (u.endsWith("/v1/traces")) return jsonResponse({});
			throw new Error(`unexpected fetch: ${u}`);
		}) as unknown as typeof fetch;

		await run(
			["--api-key", "tlane_secret", "--gateway", "https://gw", "--project"],
			fake,
		);
		expect(seen).not.toContain("https://gw/v1/messages");
		const written = JSON.parse(
			readFileSync(join(dir, ".claude", "settings.json"), "utf8"),
		) as { env: Record<string, string> };
		expect(written.env.ANTHROPIC_BASE_URL).toBeUndefined();
	});

	it("falls back to TRACELANE_API_KEY when --api-key is not passed", async () => {
		const savedEnv = process.env.TRACELANE_API_KEY;
		process.env.TRACELANE_API_KEY = "tlane_from_env";
		try {
			await run(["--gateway", "https://gw", "--print"], happyFetch());
		} finally {
			if (savedEnv === undefined) {
				// biome-ignore lint/performance/noDelete: an undefined ASSIGNMENT stringifies to "undefined" in process.env (truthy) — delete is the only way to restore "unset".
				delete process.env.TRACELANE_API_KEY;
			} else {
				process.env.TRACELANE_API_KEY = savedEnv;
			}
		}
		expect(out.join("\n")).toContain(
			'OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer tlane_from_env"',
		);
	});
});
