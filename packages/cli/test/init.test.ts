/**
 * `tlane init` — end-state tests.
 *
 * Every assertion here is about what is true on disk (or what argv the user's
 * package manager was handed) after the command ran in a real temporary
 * project. None of them asserts "a function was called".
 *
 * The load-bearing one is the drift guard at the bottom: it reads the actual
 * TypeScript and Python SDK sources and proves every import the scaffold
 * generates resolves to something the SDK really exports. Rename an adapter in
 * the SDK and this fails here, instead of shipping a bootstrap that does not
 * import.
 */

import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	NODE_ADAPTERS,
	PYTHON_ADAPTERS,
	buildEnvEntries,
	buildNodeBootstrap,
	buildPythonBootstrap,
	detectProject,
	ensureEnvIgnored,
	extractPythonDeps,
	mergeEnv,
} from "../src/commands/init-detect.js";
import {
	type CommandRunner,
	registerInitCommand,
} from "../src/commands/init.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_PACKAGES = join(HERE, "..", "..");

interface Invocation {
	command: string;
	args: string[];
	cwd: string;
}

describe("tlane init — scaffolds a real project", () => {
	let dir: string;
	let cwd: string;
	let calls: Invocation[];
	let runner: CommandRunner;
	let exitStatus: number;
	let out: string[];

	beforeEach(() => {
		cwd = process.cwd();
		dir = mkdtempSync(join(tmpdir(), "tlane-init-scaffold-"));
		process.chdir(dir);
		calls = [];
		exitStatus = 0;
		out = [];
		runner = (command, args, runCwd) => {
			calls.push({ command, args: [...args], cwd: runCwd });
			return { status: exitStatus };
		};
	});

	afterEach(() => {
		process.chdir(cwd);
		rmSync(dir, { recursive: true, force: true });
		vi.restoreAllMocks();
	});

	const runInit = async (argv: string[] = []) => {
		const program = new Command();
		program.exitOverride();
		registerInitCommand(program, { run: runner });
		vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
			out.push(a.join(" "));
		});
		vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => {
			out.push(a.join(" "));
		});
		vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
			throw new Error(`process.exit:${code}`);
		}) as never);
		return program.parseAsync(["node", "tlane", "init", ...argv]);
	};

	const read = (name: string) => readFileSync(join(dir, name), "utf8");

	// -- .env scaffold -------------------------------------------------------

	it("writes a .env carrying every TRACELANE_ key the shipped surface reads", async () => {
		await runInit([]);
		const env = read(".env");
		for (const entry of buildEnvEntries()) {
			expect(env).toContain(`${entry.key}=`);
		}
		expect(env).toContain("TRACELANE_API_KEY=\n");
		expect(env).toContain(
			"TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev",
		);
	});

	// NEGATIVE: `replay.ts:161` reads TRACELANE_ENDPOINT as a GATEWAY base URL.
	// Scaffolding the OTLP receiver URL under that name would silently send
	// `tlane replay` to the wrong port, so it must never appear in .env.
	it("does not scaffold TRACELANE_ENDPOINT, which replay reads as a gateway URL", async () => {
		await runInit(["--endpoint", "http://otel.internal:4318"]);
		expect(read(".env")).not.toContain("TRACELANE_ENDPOINT");
	});

	it("threads --endpoint into the config and the generated bootstrap", async () => {
		writeFileSync(join(dir, "requirements.txt"), "openai\n");
		await runInit(["--endpoint", "http://otel.internal:4318/"]);
		expect(JSON.parse(read("tracelane.config.json")).endpoint).toBe(
			"http://otel.internal:4318",
		);
		expect(read("tracelane_init.py")).toContain(
			'endpoint="http://otel.internal:4318"',
		);
	});

	// NEGATIVE: a .env holds live credentials. The one thing init must never do
	// is change a value that is already there.
	it("never rewrites a TRACELANE_ value the user already set — even with --force", async () => {
		writeFileSync(
			join(dir, ".env"),
			"TRACELANE_API_KEY=tlane_do_not_touch\nFOO=1\n",
		);
		await runInit(["--force"]);
		const env = read(".env");
		expect(env).toContain("TRACELANE_API_KEY=tlane_do_not_touch");
		expect(env.match(/TRACELANE_API_KEY=/g)).toHaveLength(1);
		expect(env).toContain("FOO=1");
		// the keys that were missing are still appended
		expect(env).toContain("TRACELANE_GATEWAY_URL=");
	});

	it("--no-env writes no .env at all", async () => {
		await runInit(["--no-env"]);
		expect(existsSync(join(dir, ".env"))).toBe(false);
	});

	it("adds .env to an existing .gitignore that does not already cover it", async () => {
		writeFileSync(join(dir, ".gitignore"), "node_modules\n");
		await runInit([]);
		const gi = read(".gitignore");
		expect(gi).toContain("node_modules");
		expect(gi.split(/\r?\n/)).toContain(".env");
	});

	// NEGATIVE: no duplicate entry when the project already ignores .env.
	it("leaves a .gitignore that already ignores .env byte-identical", async () => {
		const before = "node_modules\n.env\ndist\n";
		writeFileSync(join(dir, ".gitignore"), before);
		await runInit([]);
		expect(read(".gitignore")).toBe(before);
	});

	// -- framework detection + bootstrap -------------------------------------

	it("detects a Node framework and generates a bootstrap that imports its adapter", async () => {
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({
				name: "checkout-agent",
				dependencies: { openai: "^4.0.0", "@langchain/langgraph": "^0.2.0" },
			}),
		);
		await runInit(["--service-name", "checkout-agent"]);

		const boot = read("tracelane.mjs");
		expect(boot).toContain('import { init } from "@tracelanedev/sdk";');
		expect(boot).toContain(
			'import { instrumentOpenAI } from "@tracelanedev/sdk/openai";',
		);
		expect(boot).toContain(
			'import { instrumentLangGraph } from "@tracelanedev/sdk/langgraph";',
		);
		expect(boot).toContain('serviceName: "checkout-agent"');
		expect(boot).toContain("export { instrumentOpenAI, instrumentLangGraph };");
		// the generated file must be valid JavaScript, not merely plausible text
		expect(nodeSyntaxCheck(join(dir, "tracelane.mjs"))).toBe("");
	});

	it("emits a .ts bootstrap when the project has a tsconfig", async () => {
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ dependencies: { openai: "^4.0.0" } }),
		);
		writeFileSync(join(dir, "tsconfig.json"), "{}");
		await runInit([]);
		expect(existsSync(join(dir, "tracelane.ts"))).toBe(true);
		expect(existsSync(join(dir, "tracelane.mjs"))).toBe(false);
	});

	it("detects a Python framework and turns on the auto_instrument set it really covers", async () => {
		writeFileSync(
			join(dir, "requirements.txt"),
			"# agent deps\nopenai==1.40.0\nlanggraph>=0.2\nflask\n",
		);
		await runInit([]);

		const boot = read("tracelane_init.py");
		expect(boot).toContain("from tracelane import init");
		expect(boot).toContain("auto_instrument=True,  # wraps installed openai");
		// langgraph is a documented no-op inside auto_instrument(), so it must be
		// surfaced as a call the user still has to make — not silently claimed.
		expect(boot).toContain("from tracelane import instrument_langgraph");
		expect(boot).toContain("instrument_langgraph(graph)");
	});

	// NEGATIVE: a dependency with no Tracelane adapter must not be claimed.
	it("does not claim a framework it has no adapter for", async () => {
		writeFileSync(join(dir, "requirements.txt"), "flask\ndjango\nrequests\n");
		await runInit([]);
		const boot = read("tracelane_init.py");
		expect(boot).not.toContain("flask");
		expect(boot).not.toContain("django");
		expect(boot).toContain("auto_instrument=False");
		expect(boot).toContain("No Tracelane adapter matched");
	});

	// NEGATIVE: never clobber a bootstrap the user has edited.
	it("keeps an existing bootstrap byte-identical without --force, and regenerates with it", async () => {
		writeFileSync(join(dir, "requirements.txt"), "openai\n");
		writeFileSync(
			join(dir, "tracelane_init.py"),
			"# hand-edited, do not lose\n",
		);
		await runInit([]);
		expect(read("tracelane_init.py")).toBe("# hand-edited, do not lose\n");

		rmSync(join(dir, "tracelane.config.json"));
		await runInit(["--force"]);
		expect(read("tracelane_init.py")).toContain("from tracelane import init");
	});

	it("--no-instrument writes no bootstrap", async () => {
		writeFileSync(join(dir, "requirements.txt"), "openai\n");
		await runInit(["--no-instrument"]);
		expect(existsSync(join(dir, "tracelane_init.py"))).toBe(false);
	});

	it("scaffolds both ecosystems in a polyglot project", async () => {
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ dependencies: { ai: "^4.0.0" } }),
		);
		writeFileSync(join(dir, "requirements.txt"), "anthropic\n");
		await runInit([]);
		expect(read("tracelane.mjs")).toContain("instrumentVercelAI");
		expect(read("tracelane_init.py")).toContain("auto_instrument=True");
		expect(calls.map((c) => c.command).sort()).toEqual(["npm", "python3"]);
	});

	// -- SDK install ---------------------------------------------------------

	it("installs the TypeScript SDK with the package manager the lockfile names", async () => {
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ dependencies: {} }),
		);
		writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
		await runInit([]);
		expect(calls).toEqual([
			{ command: "pnpm", args: ["add", "@tracelanedev/sdk"], cwd: dir },
		]);
	});

	it("falls back to npm when there is no lockfile", async () => {
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ dependencies: {} }),
		);
		await runInit([]);
		expect(calls[0]).toMatchObject({
			command: "npm",
			args: ["install", "@tracelanedev/sdk"],
		});
	});

	it("installs the Python SDK into the project interpreter, and uses uv when locked", async () => {
		writeFileSync(join(dir, "requirements.txt"), "openai\n");
		await runInit([]);
		expect(calls[0]).toMatchObject({
			command: "python3",
			args: ["-m", "pip", "install", "tracelane"],
		});

		calls.length = 0;
		writeFileSync(join(dir, "uv.lock"), "version = 1\n");
		rmSync(join(dir, "tracelane.config.json"));
		await runInit(["--force"]);
		expect(calls[0]).toMatchObject({
			command: "uv",
			args: ["add", "tracelane"],
		});
	});

	// NEGATIVE: --no-install must not spawn anything.
	it("--no-install runs nothing and prints the command instead", async () => {
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ dependencies: {} }),
		);
		await runInit(["--no-install"]);
		expect(calls).toEqual([]);
		expect(out.join("\n")).toContain("npm install @tracelanedev/sdk");
	});

	// NEGATIVE: a failed install must be loud and non-zero, not swallowed.
	it("exits 1 when the install fails, and leaves the scaffold on disk", async () => {
		writeFileSync(
			join(dir, "package.json"),
			JSON.stringify({ dependencies: {} }),
		);
		exitStatus = 127;
		await expect(runInit([])).rejects.toThrow("process.exit:1");
		expect(existsSync(join(dir, "tracelane.config.json"))).toBe(true);
		expect(existsSync(join(dir, "tracelane.mjs"))).toBe(true);
		expect(out.join("\n")).toContain("install exited 127");
	});

	// NEGATIVE: nothing to detect means say so, not fake a success.
	it("says nothing was detected and spawns nothing in a bare directory", async () => {
		await runInit([]);
		expect(calls).toEqual([]);
		expect(existsSync(join(dir, "tracelane.mjs"))).toBe(false);
		expect(out.join("\n")).toContain("no package.json");
	});

	it("surfaces an unparseable package.json instead of reporting zero frameworks", async () => {
		writeFileSync(join(dir, "package.json"), "{ not json");
		await runInit(["--no-install"]);
		expect(out.join("\n")).toContain("package.json could not be parsed");
	});
});

// ---------------------------------------------------------------------------
// Pure units
// ---------------------------------------------------------------------------

describe("extractPythonDeps", () => {
	it("reads requirements.txt, pyproject arrays and poetry tables", () => {
		expect(extractPythonDeps("openai==1.40.0\nlanggraph>=0.2\n")).toContain(
			"openai",
		);
		expect(
			extractPythonDeps('dependencies = ["anthropic>=0.30", "crewai"]\n'),
		).toEqual(expect.arrayContaining(["anthropic", "crewai"]));
		expect(
			extractPythonDeps('[tool.poetry.dependencies]\nllama-index = "^0.11"\n'),
		).toContain("llama-index");
	});

	it("normalises PEP 503 spellings", () => {
		expect(extractPythonDeps("Llama_Index==0.11\n")).toContain("llama-index");
	});

	// NEGATIVE: comments and prose must not become dependencies.
	it("ignores comments, options and prose", () => {
		const deps = extractPythonDeps(
			'# openai is not a dep here\n-r base.txt\n--index-url https://x\ndescription = "an openai wrapper"\n',
		);
		expect(deps).not.toContain("openai");
	});
});

describe("mergeEnv", () => {
	const entries = buildEnvEntries();

	it("appends every missing key to an empty file", () => {
		const m = mergeEnv("", entries);
		expect(m.added).toEqual(entries.map((e) => e.key));
		expect(m.content).toContain("TRACELANE_API_KEY=");
	});

	// NEGATIVE: an already-complete .env is a no-op, byte for byte.
	it("returns the input unchanged when every key is present", () => {
		const body = entries.map((e) => `${e.key}=x`).join("\n");
		const m = mergeEnv(body, entries);
		expect(m.content).toBe(body);
		expect(m.added).toEqual([]);
	});

	it("recognises `export FOO=` form so it is not duplicated", () => {
		const m = mergeEnv("export TRACELANE_API_KEY=abc\n", entries);
		expect(m.added).not.toContain("TRACELANE_API_KEY");
		expect(m.kept).toContain("TRACELANE_API_KEY");
	});
});

describe("ensureEnvIgnored", () => {
	it("appends .env when absent", () => {
		expect(ensureEnvIgnored("node_modules\n")).toContain("\n.env\n");
	});

	// NEGATIVE: every spelling that already covers .env means no edit.
	it.each([".env", "/.env", ".env*", "*.env"])(
		"leaves a .gitignore alone when it already has %s",
		(pattern) => {
			expect(ensureEnvIgnored(`node_modules\n${pattern}\n`)).toBeUndefined();
		},
	);
});

// ---------------------------------------------------------------------------
// Drift guard — the generated scaffold must import things the SDK really has
// ---------------------------------------------------------------------------

describe("generated bootstraps import only real SDK exports", () => {
	const config = { endpoint: "http://x:4318", serviceName: "s", sampleRate: 1 };

	it("every Node adapter subpath is declared in the SDK exports map", () => {
		const pkg = JSON.parse(
			readFileSync(
				join(REPO_PACKAGES, "sdk-typescript", "package.json"),
				"utf8",
			),
		) as { exports: Record<string, unknown> };
		const declared = new Set(Object.keys(pkg.exports));
		expect(declared.has(".")).toBe(true);
		for (const a of NODE_ADAPTERS) {
			const subpath = a.module.replace("@tracelanedev/sdk", ".");
			expect(
				declared.has(subpath),
				`${a.id}: ${a.module} is not in the SDK exports map`,
			).toBe(true);
		}
	});

	it("every Node adapter function is exported by its instrumentation module", () => {
		for (const a of NODE_ADAPTERS) {
			const mod = a.module.replace("@tracelanedev/sdk/", "");
			const src = readFileSync(
				join(
					REPO_PACKAGES,
					"sdk-typescript",
					"src",
					"instrumentations",
					`${mod}.ts`,
				),
				"utf8",
			);
			expect(
				src.includes(`export function ${a.fn}(`) ||
					src.includes(`export const ${a.fn} `),
				`${a.id}: ${a.fn} is not exported by instrumentations/${mod}.ts`,
			).toBe(true);
		}
	});

	it("every instrument_* name the Python scaffold emits is exported by the SDK", () => {
		const sdkInit = readFileSync(
			join(REPO_PACKAGES, "sdk-python", "tracelane", "__init__.py"),
			"utf8",
		);
		const body = buildPythonBootstrap(config, PYTHON_ADAPTERS);
		const emitted = new Set(body.match(/instrument_[a-z0-9_]+/g) ?? []);
		expect(emitted.size).toBeGreaterThan(0);
		for (const name of emitted) {
			if (
				name === "instrument_openai" &&
				sdkInit.includes("instrument_openai,")
			) {
				continue; // imported on a shared line with instrument_openai_async
			}
			expect(
				sdkInit.includes(`import ${name}\n`) || sdkInit.includes(`${name},`),
				`${name} is not imported by tracelane/__init__.py`,
			).toBe(true);
		}
	});

	it("the Python scaffold marks exactly the four adapters auto_instrument() covers", () => {
		const auto = PYTHON_ADAPTERS.filter((a) => a.wiring === "auto").map(
			(a) => a.id,
		);
		expect(auto.sort()).toEqual(
			["anthropic", "claude_code", "litellm", "openai"].sort(),
		);
	});

	it("a Node bootstrap with no adapters is still valid JavaScript", () => {
		const scratch = mkdtempSync(join(tmpdir(), "tlane-syntax-"));
		try {
			const file = join(scratch, "tracelane.mjs");
			writeFileSync(file, buildNodeBootstrap(config, [], "tracelane.mjs"));
			expect(nodeSyntaxCheck(file)).toBe("");
		} finally {
			rmSync(scratch, { recursive: true, force: true });
		}
	});

	it("a Node bootstrap with every adapter is still valid JavaScript", () => {
		const scratch = mkdtempSync(join(tmpdir(), "tlane-syntax-all-"));
		try {
			const file = join(scratch, "tracelane.mjs");
			writeFileSync(
				file,
				buildNodeBootstrap(config, NODE_ADAPTERS, "tracelane.mjs"),
			);
			expect(nodeSyntaxCheck(file)).toBe("");
		} finally {
			rmSync(scratch, { recursive: true, force: true });
		}
	});
});

describe("detectProject", () => {
	let dir: string;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "tlane-detect-"));
	});
	afterEach(() => rmSync(dir, { recursive: true, force: true }));

	it("returns nothing for a directory with no manifest", () => {
		mkdirSync(join(dir, "src"));
		expect(detectProject(dir)).toEqual([]);
	});

	it("picks poetry from a [tool.poetry] pyproject with no lockfile", () => {
		writeFileSync(
			join(dir, "pyproject.toml"),
			'[tool.poetry]\nname = "agent"\n[tool.poetry.dependencies]\nopenai = "^1.0"\n',
		);
		const [det] = detectProject(dir);
		expect(det?.install).toEqual({
			command: "poetry",
			args: ["add", "tracelane"],
		});
		expect(det?.adapters.map((a) => a.id)).toContain("openai");
	});
});

/** `node --check <file>`; returns "" when the file parses, else the parse error. */
function nodeSyntaxCheck(file: string): string {
	const r = spawnSync(process.execPath, ["--check", file], {
		encoding: "utf8",
	});
	return r.status === 0 ? "" : `${r.stderr ?? ""}${r.stdout ?? ""}`;
}
