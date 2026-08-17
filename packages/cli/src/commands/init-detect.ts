/**
 * Project detection + scaffold generation for `tlane init`.
 *
 * Three jobs, all of them deliberately separated from the command wiring in
 * `init.ts` so they can be asserted against real fixture trees:
 *
 *  1. **Detect** the ecosystem (Node / Python), the package manager, and every
 *     dependency that has a real Tracelane adapter behind it.
 *  2. **Generate** the instrumentation bootstrap for what was detected — with
 *     import specifiers that are checked against the SDK's own export surface
 *     by `test/init.test.ts`, so an SDK rename fails the CLI build rather than
 *     shipping a scaffold that does not compile.
 *  3. **Merge** `TRACELANE_*` keys into a `.env` without ever touching a value
 *     the user already set.
 *
 * Honesty boundary, stated once here and repeated in the generated files: the
 * TypeScript SDK has no zero-config patching — `autoInstrument()` throws by
 * design and lands in v1.1 — so for Node the bootstrap wires `init()` and emits
 * the exact per-client call. The Python SDK's `auto_instrument()` really does
 * wrap installed `openai` / `anthropic` / `litellm` / `claude_code`, so for
 * Python those four need no user edit at all.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type Ecosystem = "node" | "python";

/** How far the generated bootstrap can get on its own. */
export type Wiring =
	/** Wired by the generated file itself — the user edits nothing. */
	| "auto"
	/** Needs an object only the user can construct; the exact call is emitted. */
	| "object";

export interface AdapterSpec {
	/** Adapter id — matches the SDK instrumentation module name. */
	readonly id: string;
	/** Dependency names (already normalised) that indicate this framework. */
	readonly deps: readonly string[];
	/** Instrument function exported by the SDK. */
	readonly fn: string;
	/** Import specifier the generated bootstrap uses to reach `fn`. */
	readonly module: string;
	readonly wiring: Wiring;
	/** One-line wire-up shown to the user for `wiring: "object"`. */
	readonly example: string;
}

export interface PackageManagerPlan {
	/** Executable, spawned WITHOUT a shell — never interpolate user input here. */
	readonly command: string;
	readonly args: readonly string[];
}

export interface Detection {
	readonly ecosystem: Ecosystem;
	/** Manifest files actually read, relative to the project dir. */
	readonly manifests: readonly string[];
	readonly sdkPackage: string;
	readonly install: PackageManagerPlan;
	/** Bootstrap filename written into the project dir. */
	readonly bootstrapFile: string;
	readonly adapters: readonly AdapterSpec[];
	/** Non-fatal problems (e.g. an unparseable manifest) — always surfaced. */
	readonly warnings: readonly string[];
}

export const NODE_SDK_PACKAGE = "@tracelanedev/sdk";
export const PYTHON_SDK_PACKAGE = "tracelane";

/**
 * Normalise a dependency name for comparison.
 *
 * PEP 503 for Python (`Llama_Index` and `llama-index` are the same project);
 * harmless for npm, whose names are already lowercase.
 */
export function normalizeDepName(name: string): string {
	return name
		.trim()
		.toLowerCase()
		.replace(/[-_.]+/g, "-");
}

/**
 * npm dependency -> Tracelane TypeScript adapter.
 *
 * `module` is always a subpath export because `instrumentLangChain` is NOT
 * re-exported from the package root — importing every adapter by subpath keeps
 * one rule instead of two, and every subpath here is declared in the SDK's
 * `exports` map (asserted in `test/init.test.ts`).
 */
export const NODE_ADAPTERS: readonly AdapterSpec[] = [
	{
		id: "openai",
		deps: ["openai"],
		fn: "instrumentOpenAI",
		module: "@tracelanedev/sdk/openai",
		wiring: "object",
		example: "const client = new OpenAI(); instrumentOpenAI(client);",
	},
	{
		id: "anthropic",
		deps: ["@anthropic-ai/sdk"],
		fn: "instrumentAnthropic",
		module: "@tracelanedev/sdk/anthropic",
		wiring: "object",
		example: "const client = new Anthropic(); instrumentAnthropic(client);",
	},
	{
		id: "litellm",
		deps: ["litellm"],
		fn: "instrumentLiteLLM",
		module: "@tracelanedev/sdk/litellm",
		wiring: "object",
		example: "instrumentLiteLLM(client);",
	},
	{
		id: "openrouter",
		deps: ["@openrouter/ai-sdk-provider", "openrouter"],
		fn: "instrumentOpenRouter",
		module: "@tracelanedev/sdk/openrouter",
		wiring: "object",
		example: "instrumentOpenRouter(client);",
	},
	{
		id: "langchain",
		deps: [
			"langchain",
			"@langchain/core",
			"@langchain/openai",
			"@langchain/anthropic",
			"@langchain/community",
		],
		fn: "instrumentLangChain",
		module: "@tracelanedev/sdk/langchain",
		wiring: "object",
		example:
			"instrumentLangChain(model);   // your ChatOpenAI / ChatAnthropic instance",
	},
	{
		id: "langgraph",
		deps: ["@langchain/langgraph"],
		fn: "instrumentLangGraph",
		module: "@tracelanedev/sdk/langgraph",
		wiring: "object",
		example: "const app = graph.compile(); instrumentLangGraph(app);",
	},
	{
		id: "openai_agents",
		deps: ["@openai/agents"],
		fn: "instrumentOpenAIAgents",
		module: "@tracelanedev/sdk/openai_agents",
		wiring: "object",
		example: "instrumentOpenAIAgents(Runner);   // the class, not an instance",
	},
	{
		id: "vercel_ai",
		deps: ["ai"],
		fn: "instrumentVercelAI",
		module: "@tracelanedev/sdk/vercel_ai",
		wiring: "object",
		example:
			'import * as ai from "ai"; instrumentVercelAI(ai);   // patches the module in place, so a frozen ESM namespace will reject it',
	},
	{
		id: "mcp",
		deps: ["@modelcontextprotocol/sdk"],
		fn: "instrumentMCP",
		module: "@tracelanedev/sdk/mcp",
		wiring: "object",
		example: "instrumentMCP(client);",
	},
	{
		id: "claude_code",
		deps: ["@anthropic-ai/claude-code", "@anthropic-ai/claude-agent-sdk"],
		fn: "instrumentClaudeCode",
		module: "@tracelanedev/sdk/claude_code",
		wiring: "object",
		example: "instrumentClaudeCode(client);",
	},
	{
		id: "pinecone",
		deps: ["@pinecone-database/pinecone"],
		fn: "instrumentPinecone",
		module: "@tracelanedev/sdk/pinecone",
		wiring: "object",
		example: "instrumentPinecone(index);   // an index handle, not the client",
	},
	{
		id: "qdrant",
		deps: ["@qdrant/js-client-rest"],
		fn: "instrumentQdrant",
		module: "@tracelanedev/sdk/qdrant",
		wiring: "object",
		example: "instrumentQdrant(client);",
	},
	{
		id: "composio",
		deps: ["composio-core", "@composio/core"],
		fn: "instrumentComposio",
		module: "@tracelanedev/sdk/composio",
		wiring: "object",
		example: "instrumentComposio(toolset);",
	},
	{
		id: "browserbase",
		deps: ["@browserbasehq/sdk"],
		fn: "instrumentBrowserbase",
		module: "@tracelanedev/sdk/browserbase",
		wiring: "object",
		example: "instrumentBrowserbase(client);",
	},
	{
		id: "e2b",
		deps: ["e2b", "@e2b/code-interpreter"],
		fn: "instrumentE2B",
		module: "@tracelanedev/sdk/e2b",
		wiring: "object",
		example: "instrumentE2B(Sandbox);   // the class, not an instance",
	},
	{
		id: "mem0",
		deps: ["mem0ai"],
		fn: "instrumentMem0",
		module: "@tracelanedev/sdk/mem0",
		wiring: "object",
		example: "instrumentMem0(client);",
	},
	{
		id: "letta",
		deps: ["@letta-ai/letta-client"],
		fn: "instrumentLetta",
		module: "@tracelanedev/sdk/letta",
		wiring: "object",
		example: "instrumentLetta(client);",
	},
	{
		id: "firecrawl",
		deps: ["@mendable/firecrawl-js"],
		fn: "instrumentFirecrawl",
		module: "@tracelanedev/sdk/firecrawl",
		wiring: "object",
		example: "instrumentFirecrawl(app);",
	},
] as const;

/**
 * PyPI distribution -> Tracelane Python adapter.
 *
 * The four `wiring: "auto"` entries are exactly the set `auto_instrument()`
 * really wraps (`tracelane/__init__.py:62-89`). `langgraph` is listed there too
 * but is a documented no-op, so it is `"object"` here — claiming otherwise
 * would be the whole failure mode this row exists to close.
 */
export const PYTHON_ADAPTERS: readonly AdapterSpec[] = [
	{
		id: "openai",
		deps: ["openai"],
		fn: "instrument_openai",
		module: "tracelane",
		wiring: "auto",
		example: "instrument_openai(client)",
	},
	{
		id: "anthropic",
		deps: ["anthropic"],
		fn: "instrument_anthropic",
		module: "tracelane",
		wiring: "auto",
		example: "instrument_anthropic(client)",
	},
	{
		id: "litellm",
		deps: ["litellm"],
		fn: "instrument_litellm",
		module: "tracelane",
		wiring: "auto",
		example: "instrument_litellm()",
	},
	{
		id: "claude_code",
		deps: ["claude-code-sdk", "claude-agent-sdk"],
		fn: "instrument_claude_code",
		module: "tracelane",
		wiring: "auto",
		example: "instrument_claude_code()",
	},
	{
		id: "langchain",
		deps: [
			"langchain",
			"langchain-core",
			"langchain-openai",
			"langchain-anthropic",
			"langchain-community",
		],
		fn: "instrument_langchain",
		module: "tracelane",
		wiring: "object",
		example:
			"instrument_langchain(model)   # your ChatOpenAI / ChatAnthropic instance",
	},
	{
		id: "langgraph",
		deps: ["langgraph"],
		fn: "instrument_langgraph",
		module: "tracelane",
		wiring: "object",
		example: "instrument_langgraph(graph)   # after graph.compile()",
	},
	{
		id: "llamaindex",
		deps: ["llama-index", "llama-index-core"],
		fn: "instrument_llamaindex",
		module: "tracelane",
		wiring: "object",
		example: "instrument_llamaindex(client)",
	},
	{
		id: "crewai",
		deps: ["crewai"],
		fn: "instrument_crewai",
		module: "tracelane",
		wiring: "object",
		example: "instrument_crewai(agent)",
	},
	{
		id: "autogen",
		deps: ["pyautogen", "autogen", "autogen-agentchat"],
		fn: "instrument_autogen",
		module: "tracelane",
		wiring: "object",
		example: "instrument_autogen(agent)",
	},
	{
		id: "magentic_one",
		deps: ["autogen-magentic-one"],
		fn: "instrument_magentic_one",
		module: "tracelane",
		wiring: "object",
		example: "instrument_magentic_one(agent)",
	},
	{
		id: "smolagents",
		deps: ["smolagents"],
		fn: "instrument_smolagents",
		module: "tracelane",
		wiring: "object",
		example: "instrument_smolagents(agent)",
	},
	{
		id: "haystack",
		deps: ["haystack-ai"],
		fn: "instrument_haystack",
		module: "tracelane",
		wiring: "object",
		example: "instrument_haystack(pipeline)",
	},
	{
		id: "pydantic_ai",
		deps: ["pydantic-ai", "pydantic-ai-slim"],
		fn: "instrument_pydantic_ai",
		module: "tracelane",
		wiring: "object",
		example: "instrument_pydantic_ai(agent)",
	},
	{
		id: "openai_agents",
		deps: ["openai-agents"],
		fn: "instrument_openai_agents",
		module: "tracelane",
		wiring: "object",
		example: "instrument_openai_agents(Runner)   # the class, not an instance",
	},
	{
		id: "openrouter",
		deps: ["openrouter"],
		fn: "instrument_openrouter",
		module: "tracelane",
		wiring: "object",
		example: "instrument_openrouter(client)",
	},
	{
		id: "vertexai",
		deps: ["google-cloud-aiplatform", "vertexai"],
		fn: "instrument_vertexai",
		module: "tracelane",
		wiring: "object",
		example: "instrument_vertexai(model)",
	},
	{
		id: "mcp",
		deps: ["mcp", "fastmcp"],
		fn: "instrument_mcp",
		module: "tracelane",
		wiring: "object",
		example: "instrument_mcp(client)",
	},
	{
		id: "pinecone",
		deps: ["pinecone", "pinecone-client"],
		fn: "instrument_pinecone",
		module: "tracelane",
		wiring: "object",
		example: "instrument_pinecone(index)   # an index handle, not the client",
	},
	{
		id: "qdrant",
		deps: ["qdrant-client"],
		fn: "instrument_qdrant",
		module: "tracelane",
		wiring: "object",
		example: "instrument_qdrant(client)",
	},
	{
		id: "composio",
		deps: ["composio-core", "composio"],
		fn: "instrument_composio",
		module: "tracelane",
		wiring: "object",
		example: "instrument_composio(toolset)",
	},
	{
		id: "browserbase",
		deps: ["browserbase"],
		fn: "instrument_browserbase",
		module: "tracelane",
		wiring: "object",
		example: "instrument_browserbase(client)",
	},
	{
		id: "e2b",
		deps: ["e2b", "e2b-code-interpreter"],
		fn: "instrument_e2b",
		module: "tracelane",
		wiring: "object",
		example: "instrument_e2b(Sandbox)   # the class, not an instance",
	},
	{
		id: "mem0",
		deps: ["mem0ai"],
		fn: "instrument_mem0",
		module: "tracelane",
		wiring: "object",
		example: "instrument_mem0(memory)",
	},
	{
		id: "letta",
		deps: ["letta", "letta-client"],
		fn: "instrument_letta",
		module: "tracelane",
		wiring: "object",
		example: "instrument_letta(client)",
	},
	{
		id: "firecrawl",
		deps: ["firecrawl-py", "firecrawl"],
		fn: "instrument_firecrawl",
		module: "tracelane",
		wiring: "object",
		example: "instrument_firecrawl(app)",
	},
] as const;

/** Dependency names declared in a `package.json`, normalised. */
export function extractNodeDeps(packageJsonText: string): string[] {
	const parsed = JSON.parse(packageJsonText) as Record<string, unknown>;
	const fields = [
		"dependencies",
		"devDependencies",
		"peerDependencies",
		"optionalDependencies",
	];
	const out = new Set<string>();
	for (const field of fields) {
		const block = parsed[field];
		if (block && typeof block === "object") {
			for (const name of Object.keys(block as Record<string, unknown>)) {
				out.add(normalizeDepName(name));
			}
		}
	}
	return [...out];
}

/** Leading distribution name of a PEP 508 requirement, or "" if there is none. */
function leadingRequirementName(raw: string): string {
	const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(raw.trim());
	return m?.[1] ? normalizeDepName(m[1]) : "";
}

/**
 * Dependency names declared in a `requirements.txt`, `pyproject.toml` or
 * `Pipfile`, normalised.
 *
 * Deliberately a scanner, not a TOML parser — Node ships no TOML reader and a
 * dependency for one is not worth it. It over-collects (a `[project] name` key
 * lands here too); that is safe because a name only matters when it matches an
 * entry in `PYTHON_ADAPTERS`, and the adapter names are specific enough that a
 * manifest key never collides with one.
 */
export function extractPythonDeps(text: string): string[] {
	const out = new Set<string>();
	for (const rawLine of text.split(/\r?\n/)) {
		const line = (rawLine.split("#")[0] ?? "").trim();
		if (!line || line.startsWith("-") || line.startsWith("[")) continue;

		const quoted = line.match(/["']([^"']+)["']/g);
		if (quoted) {
			// `dependencies = ["openai>=1.0", "anthropic"]` — the requirement is
			// inside the quotes.
			for (const q of quoted) {
				const name = leadingRequirementName(q.slice(1, -1));
				if (name) out.add(name);
			}
			// `openai = "^1.0"` (poetry / Pipfile table form) — the requirement is
			// the key on the left.
			const lhs = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line);
			if (lhs?.[1]) out.add(normalizeDepName(lhs[1]));
			continue;
		}

		const name = leadingRequirementName(line);
		if (name) out.add(name);
	}
	return [...out];
}

/** Adapters whose declared dependencies intersect `deps`. */
export function matchAdapters(
	deps: readonly string[],
	registry: readonly AdapterSpec[],
): AdapterSpec[] {
	const present = new Set(deps);
	return registry.filter((a) => a.deps.some((d) => present.has(d)));
}

const NODE_LOCKFILES: readonly {
	file: string;
	command: string;
	args: string[];
}[] = [
	{ file: "pnpm-lock.yaml", command: "pnpm", args: ["add"] },
	{ file: "bun.lockb", command: "bun", args: ["add"] },
	{ file: "bun.lock", command: "bun", args: ["add"] },
	{ file: "yarn.lock", command: "yarn", args: ["add"] },
	{ file: "package-lock.json", command: "npm", args: ["install"] },
];

function nodeInstallPlan(dir: string): PackageManagerPlan {
	for (const lock of NODE_LOCKFILES) {
		if (existsSync(join(dir, lock.file))) {
			return { command: lock.command, args: [...lock.args, NODE_SDK_PACKAGE] };
		}
	}
	return { command: "npm", args: ["install", NODE_SDK_PACKAGE] };
}

function pythonInstallPlan(
	dir: string,
	pyprojectText: string,
): PackageManagerPlan {
	if (existsSync(join(dir, "uv.lock"))) {
		return { command: "uv", args: ["add", PYTHON_SDK_PACKAGE] };
	}
	if (
		existsSync(join(dir, "poetry.lock")) ||
		pyprojectText.includes("[tool.poetry")
	) {
		return { command: "poetry", args: ["add", PYTHON_SDK_PACKAGE] };
	}
	if (
		existsSync(join(dir, "Pipfile.lock")) ||
		existsSync(join(dir, "Pipfile"))
	) {
		return { command: "pipenv", args: ["install", PYTHON_SDK_PACKAGE] };
	}
	// `python3 -m pip` rather than bare `pip`: it installs into the interpreter
	// the project actually runs, including inside an activated venv where a bare
	// `pip` may not be on PATH at all.
	return {
		command: "python3",
		args: ["-m", "pip", "install", PYTHON_SDK_PACKAGE],
	};
}

function readIfPresent(dir: string, name: string): string | undefined {
	const p = join(dir, name);
	return existsSync(p) ? readFileSync(p, "utf8") : undefined;
}

/**
 * Detect every ecosystem present in `dir`.
 *
 * Returns one entry per ecosystem, so a polyglot repo (a Next.js app plus a
 * Python agent) is scaffolded for both rather than silently for whichever
 * manifest was checked first. An empty array means no manifest was found —
 * the caller must say so out loud instead of reporting a successful scaffold.
 */
export function detectProject(dir: string): Detection[] {
	const out: Detection[] = [];

	const pkgJson = readIfPresent(dir, "package.json");
	if (pkgJson !== undefined) {
		const warnings: string[] = [];
		let deps: string[] = [];
		try {
			deps = extractNodeDeps(pkgJson);
		} catch (err) {
			warnings.push(
				`package.json could not be parsed (${(err as Error).message}) — no Node frameworks were detected.`,
			);
		}
		out.push({
			ecosystem: "node",
			manifests: ["package.json"],
			sdkPackage: NODE_SDK_PACKAGE,
			install: nodeInstallPlan(dir),
			bootstrapFile: existsSync(join(dir, "tsconfig.json"))
				? "tracelane.ts"
				: "tracelane.mjs",
			adapters: matchAdapters(deps, NODE_ADAPTERS),
			warnings,
		});
	}

	const pyManifests: string[] = [];
	let pyText = "";
	for (const name of ["pyproject.toml", "requirements.txt", "Pipfile"]) {
		const text = readIfPresent(dir, name);
		if (text !== undefined) {
			pyManifests.push(name);
			pyText += `\n${text}`;
		}
	}
	if (pyManifests.length > 0) {
		out.push({
			ecosystem: "python",
			manifests: pyManifests,
			sdkPackage: PYTHON_SDK_PACKAGE,
			install: pythonInstallPlan(
				dir,
				readIfPresent(dir, "pyproject.toml") ?? "",
			),
			bootstrapFile: "tracelane_init.py",
			adapters: matchAdapters(extractPythonDeps(pyText), PYTHON_ADAPTERS),
			warnings: [],
		});
	}

	return out;
}

// ---------------------------------------------------------------------------
// .env scaffold
// ---------------------------------------------------------------------------

export interface EnvEntry {
	readonly key: string;
	readonly value: string;
	readonly comment: string;
}

/**
 * The `TRACELANE_*` keys scaffolded into `.env`.
 *
 * Both are read by shipped code: `TRACELANE_API_KEY` by the generated bootstrap,
 * by `tlane trace` (`trace.ts:89`) and as `tlane replay`'s token alias
 * (`replay.ts:172`); `TRACELANE_GATEWAY_URL` by the gateway-backed commands
 * (`replay.ts:160`). Keys nobody reads are deliberately NOT scaffolded — a
 * placeholder that does nothing is a lie with a long half-life.
 *
 * `TRACELANE_ENDPOINT` in particular is absent on purpose: `replay.ts:161`
 * consumes it as a **gateway** base URL, so scaffolding the OTLP receiver URL
 * under that name would silently point `tlane replay` at the wrong port. The
 * OTLP endpoint lives in `tracelane.config.json` and is inlined into the
 * generated bootstrap instead.
 */
export function buildEnvEntries(): EnvEntry[] {
	return [
		{
			key: "TRACELANE_API_KEY",
			value: "",
			comment:
				"Tenant API key (tlane_…). Create one in the dashboard under Settings -> API keys.",
		},
		{
			key: "TRACELANE_GATEWAY_URL",
			value: "https://gateway.tracelane.dev",
			comment:
				"Gateway base URL. Point an OpenAI-compatible client at $TRACELANE_GATEWAY_URL/v1.",
		},
	];
}

export interface EnvMerge {
	readonly content: string;
	readonly added: string[];
	readonly kept: string[];
}

/**
 * Merge Tracelane keys into an existing `.env` body.
 *
 * **Never rewrites a key that is already present**, whatever its value and
 * whatever `--force` says. A `.env` holds live credentials; the only safe edit
 * is an append, so this needs no overwrite flag and cannot destroy a secret.
 */
export function mergeEnv(
	existing: string,
	entries: readonly EnvEntry[],
): EnvMerge {
	const present = new Set<string>();
	for (const m of existing.matchAll(
		/^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=/gm,
	)) {
		if (m[1]) present.add(m[1]);
	}

	const missing = entries.filter((e) => !present.has(e.key));
	const kept = entries.filter((e) => present.has(e.key)).map((e) => e.key);
	if (missing.length === 0) {
		return { content: existing, added: [], kept };
	}

	const block: string[] = [];
	if (existing.length > 0 && !existing.endsWith("\n")) block.push("");
	if (existing.trim().length > 0) block.push("");
	block.push("# --- Tracelane (added by `tlane init`) ---");
	for (const e of missing) {
		block.push(`# ${e.comment}`);
		block.push(`${e.key}=${e.value}`);
	}

	return {
		content: `${existing}${block.join("\n")}\n`,
		added: missing.map((e) => e.key),
		kept,
	};
}

/**
 * Append `.env` to a `.gitignore` body when it is not already ignored.
 *
 * Scaffolding a credential file into a tracked tree without this is how an API
 * key reaches a public repo. Returns `undefined` when no change is needed.
 */
export function ensureEnvIgnored(existing: string): string | undefined {
	const ignored = existing
		.split(/\r?\n/)
		.map((l) => l.trim())
		.some(
			(l) => l === ".env" || l === "/.env" || l === ".env*" || l === "*.env",
		);
	if (ignored) return undefined;
	const sep = existing.length === 0 || existing.endsWith("\n") ? "" : "\n";
	return `${existing}${sep}\n# Added by \`tlane init\` — .env holds your TRACELANE_API_KEY.\n.env\n`;
}

// ---------------------------------------------------------------------------
// Bootstrap generation
// ---------------------------------------------------------------------------

export interface BootstrapConfig {
	readonly endpoint: string;
	readonly serviceName: string;
	readonly sampleRate: number;
}

/** JSON string syntax is a literal subset of both TS and Python — reuse it. */
function lit(value: string): string {
	return JSON.stringify(value);
}

function floatLit(n: number): string {
	return Number.isInteger(n) ? `${n}.0` : String(n);
}

/**
 * Generate the Node instrumentation bootstrap.
 *
 * The file is honest about its own ceiling: the TypeScript SDK exposes no
 * zero-config patching (`autoInstrument()` throws — v1.1), so what is generated
 * is `init()` plus the exact wrap call for every detected client, re-exported so
 * the imports are real rather than decorative.
 */
export function buildNodeBootstrap(
	config: BootstrapConfig,
	adapters: readonly AdapterSpec[],
	bootstrapFile: string,
): string {
	const importSuffix = bootstrapFile.endsWith(".ts") ? ".js" : ".mjs";
	const L: string[] = [];
	L.push("/**");
	L.push(" * Tracelane bootstrap — generated by `tlane init`. Edit freely.");
	L.push(" *");
	L.push(" * Import this ONCE, before anything that talks to a model:");
	L.push(
		` *     import "./${bootstrapFile.replace(/\.(ts|mjs)$/, importSuffix)}";`,
	);
	L.push(" *");
	L.push(
		" * Tracing fails OPEN here: with no TRACELANE_API_KEY this warns and stays off",
	);
	L.push(
		" * rather than taking your process down. It warns loudly, because a silent",
	);
	L.push(" * no-op is exactly how a total span drop ships unnoticed.");
	L.push(" */");
	L.push("");
	L.push('import { init } from "@tracelanedev/sdk";');
	for (const a of adapters) {
		L.push(`import { ${a.fn} } from ${lit(a.module)};`);
	}
	L.push("");
	L.push("const apiKey = process.env.TRACELANE_API_KEY;");
	L.push("");
	L.push("if (apiKey) {");
	L.push("\tinit({");
	L.push(`\t\tendpoint: ${lit(config.endpoint)},`);
	L.push(`\t\tserviceName: ${lit(config.serviceName)},`);
	L.push(`\t\tsampleRate: ${config.sampleRate},`);
	L.push("\t\tapiKey,");
	L.push("\t});");
	L.push("} else {");
	L.push("\tconsole.warn(");
	L.push(
		'\t\t"[tracelane] TRACELANE_API_KEY is not set — tracing is OFF. Set it in .env.",',
	);
	L.push("\t);");
	L.push("}");
	L.push("");

	if (adapters.length === 0) {
		L.push(
			"// No Tracelane adapter matched a dependency in package.json. Add one",
		);
		L.push(
			"// (openai, @anthropic-ai/sdk, @langchain/langgraph, ai, …) and re-run",
		);
		L.push("// `tlane init --force` to regenerate this file with the wire-up.");
		return `${L.join("\n")}\n`;
	}

	L.push("// Detected in package.json. The TypeScript SDK has no zero-config");
	L.push(
		"// patching — autoInstrument() throws by design and ships in v1.1 — so",
	);
	L.push("// each client is wrapped explicitly, once, where you construct it:");
	L.push("//");
	for (const a of adapters) {
		L.push(`//   ${a.id}: ${a.example}`);
	}
	L.push("");
	L.push(`export { ${adapters.map((a) => a.fn).join(", ")} };`);
	return `${L.join("\n")}\n`;
}

/**
 * Generate the Python instrumentation bootstrap.
 *
 * `auto_instrument=True` is emitted only when a dependency it actually covers
 * was detected — `tracelane/__init__.py:62-89` wraps exactly anthropic, openai,
 * litellm and claude_code, and nothing else.
 */
export function buildPythonBootstrap(
	config: BootstrapConfig,
	adapters: readonly AdapterSpec[],
): string {
	const auto = adapters.filter((a) => a.wiring === "auto");
	const manual = adapters.filter((a) => a.wiring === "object");

	const L: string[] = [];
	L.push('"""Tracelane bootstrap — generated by `tlane init`. Edit freely.');
	L.push("");
	L.push("Import this ONCE, before anything that talks to a model::");
	L.push("");
	L.push("    import tracelane_init  # noqa: F401");
	L.push("");
	L.push(
		"Tracing fails OPEN here: with no TRACELANE_API_KEY this warns on stderr and",
	);
	L.push(
		"stays off rather than taking your process down. It warns loudly, because a",
	);
	L.push("silent no-op is exactly how a total span drop ships unnoticed.");
	L.push('"""');
	L.push("");
	L.push("import os");
	L.push("import sys");
	L.push("");
	L.push("from tracelane import init");
	L.push("");
	L.push('_api_key = os.environ.get("TRACELANE_API_KEY")');
	L.push("");
	L.push("if _api_key:");
	L.push("    init(");
	L.push(`        endpoint=${lit(config.endpoint)},`);
	L.push("        api_key=_api_key,");
	L.push(`        service_name=${lit(config.serviceName)},`);
	L.push(`        sample_rate=${floatLit(config.sampleRate)},`);
	if (auto.length > 0) {
		L.push(
			`        auto_instrument=True,  # wraps installed ${auto.map((a) => a.id).join(", ")}`,
		);
	} else {
		L.push(
			"        auto_instrument=False,  # nothing auto_instrument() covers is installed",
		);
	}
	L.push("    )");
	L.push("else:");
	L.push("    print(");
	L.push(
		'        "[tracelane] TRACELANE_API_KEY is not set — tracing is OFF. Set it in .env.",',
	);
	L.push("        file=sys.stderr,");
	L.push("    )");
	L.push("");

	if (adapters.length === 0) {
		L.push(
			"# No Tracelane adapter matched a dependency in your Python manifests.",
		);
		L.push("# Add one (openai, anthropic, langgraph, crewai, …) and re-run");
		L.push("# `tlane init --force` to regenerate this file with the wire-up.");
		return `${L.join("\n")}\n`;
	}

	if (manual.length > 0) {
		L.push(
			"# Also detected, but these wrap an object only you can construct. Call",
		);
		L.push("# each one after you build it:");
		L.push("#");
		for (const a of manual) {
			L.push(`#     from tracelane import ${a.fn}`);
			L.push(`#     ${a.example}`);
		}
	}
	return `${L.join("\n")}\n`;
}
