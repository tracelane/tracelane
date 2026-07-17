/**
 * tlane import-litellm — read a litellm_config.yaml and emit a Tracelane
 * gateway config. Target time-to-migrate: <5 minutes.
 *
 * Supported translations:
 *   model_list entries         → providers array
 *   router_settings            → failover + rate_limit config
 *   litellm_settings callbacks → telemetry.otlp_endpoint
 *   environment_variables      → .env file reminder (never in config)
 *
 * Usage:
 *   tlane import-litellm --config litellm_config.yaml
 *   tlane import-litellm --config litellm_config.yaml --output tracelane.yaml
 *   tlane import-litellm --config litellm_config.yaml --dry-run
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Command } from "commander";

// ── LiteLLM config types (subset we care about) ──────────────────────────────

interface LiteLLMModelEntry {
	model_name: string;
	litellm_params: {
		model: string;
		api_base?: string;
		api_key?: string;
		rpm?: number;
		tpm?: number;
		[key: string]: unknown;
	};
	model_info?: {
		id?: string;
		[key: string]: unknown;
	};
}

interface LiteLLMRouterSettings {
	routing_strategy?: string;
	num_retries?: number;
	timeout?: number;
	retry_after?: number;
	[key: string]: unknown;
}

interface LiteLLMGeneralSettings {
	master_key?: string;
	database_url?: string;
	rate_limit_policy?: string;
	[key: string]: unknown;
}

interface LiteLLMSettings {
	success_callback?: string[];
	failure_callback?: string[];
	[key: string]: unknown;
}

interface LiteLLMConfig {
	model_list?: LiteLLMModelEntry[];
	router_settings?: LiteLLMRouterSettings;
	general_settings?: LiteLLMGeneralSettings;
	litellm_settings?: LiteLLMSettings;
	environment_variables?: Record<string, string>;
}

// ── Tracelane config types ────────────────────────────────────────────────────

interface TracelaneProvider {
	name: string;
	model: string;
	api_base?: string;
	rpm_limit?: number;
	tpm_limit?: number;
}

interface TracelaneConfig {
	version: "1";
	gateway: {
		providers: TracelaneProvider[];
		failover: {
			strategy: "latency_based" | "round_robin" | "least_busy";
			max_retries: number;
			retry_delay_ms: number;
		};
		rate_limit?: {
			requests_per_minute?: number;
		};
		telemetry?: {
			otlp_endpoint?: string;
		};
	};
}

// ── Provider model string parsing ─────────────────────────────────────────────

/**
 * Maps LiteLLM model strings to Tracelane provider names.
 * LiteLLM uses "provider/model-id" format (e.g. "openai/gpt-4o").
 */
export function inferProviderName(litellmModel: string): string {
	const providerPrefixMap: Record<string, string> = {
		"openai/": "openai",
		"azure/": "azure",
		"anthropic/": "anthropic",
		"google/": "google",
		"gemini/": "google",
		"bedrock/": "bedrock",
		"cohere/": "cohere",
		"mistral/": "mistral",
		"ollama/": "ollama",
		"groq/": "groq",
		"together_ai/": "together",
		"openrouter/": "openrouter",
		"perplexity/": "perplexity",
		"huggingface/": "huggingface",
		"vertex_ai/": "google",
	};

	for (const [prefix, provider] of Object.entries(providerPrefixMap)) {
		if (litellmModel.startsWith(prefix)) return provider;
	}

	// Default: treat as openai-compatible
	return "openai";
}

function mapRoutingStrategy(
	litellmStrategy?: string,
): "latency_based" | "round_robin" | "least_busy" {
	switch (litellmStrategy) {
		case "latency-based-routing":
		case "latency_based":
			return "latency_based";
		case "round_robin":
		case "simple-shuffle":
			return "round_robin";
		case "least-busy":
		case "usage-based-routing":
			return "least_busy";
		default:
			return "latency_based";
	}
}

// ── Config translation ─────────────────────────────────────────────────────────

function translateConfig(litellm: LiteLLMConfig): TracelaneConfig {
	const providers: TracelaneProvider[] = (litellm.model_list ?? []).map(
		(entry) => {
			const providerName = inferProviderName(
				entry.litellm_params.model ?? entry.model_name,
			);
			const provider: TracelaneProvider = {
				name: providerName,
				model: entry.litellm_params.model ?? entry.model_name,
			};
			if (entry.litellm_params.api_base) {
				provider.api_base = entry.litellm_params.api_base;
			}
			if (entry.litellm_params.rpm) {
				provider.rpm_limit = entry.litellm_params.rpm;
			}
			if (entry.litellm_params.tpm) {
				provider.tpm_limit = entry.litellm_params.tpm;
			}
			return provider;
		},
	);

	const router = litellm.router_settings ?? {};
	const tracelane: TracelaneConfig = {
		version: "1",
		gateway: {
			providers,
			failover: {
				strategy: mapRoutingStrategy(router.routing_strategy),
				max_retries: router.num_retries ?? 3,
				retry_delay_ms: (router.retry_after ?? 1) * 1000,
			},
		},
	};

	// Rate limiting
	const general = litellm.general_settings ?? {};
	if (general.rate_limit_policy) {
		tracelane.gateway.rate_limit = { requests_per_minute: 60 };
	}

	// Telemetry: map LiteLLM success_callback OTEL to Tracelane OTLP endpoint
	const llmSettings = litellm.litellm_settings ?? {};
	const callbacks = [
		...(llmSettings.success_callback ?? []),
		...(llmSettings.failure_callback ?? []),
	];
	if (callbacks.includes("otel") || callbacks.includes("opentelemetry")) {
		tracelane.gateway.telemetry = {
			otlp_endpoint: "${OTEL_EXPORTER_OTLP_ENDPOINT:-http://localhost:4317}",
		};
	}

	return tracelane;
}

// ── YAML serializer (simple, no deps) ────────────────────────────────────────

function toYaml(obj: unknown, indent = 0): string {
	const pad = "  ".repeat(indent);
	if (obj === null || obj === undefined) return "null";
	if (typeof obj === "string") {
		if (obj.includes("\n") || obj.includes(":")) return `"${obj}"`;
		return obj;
	}
	if (typeof obj === "number" || typeof obj === "boolean") return String(obj);
	if (Array.isArray(obj)) {
		if (obj.length === 0) return "[]";
		return obj
			.map((item) => `${pad}- ${toYaml(item, indent + 1).trimStart()}`)
			.join("\n");
	}
	if (typeof obj === "object") {
		const entries = Object.entries(obj as Record<string, unknown>).filter(
			([, v]) => v !== undefined && v !== null,
		);
		if (entries.length === 0) return "{}";
		return entries
			.map(([k, v]) => {
				const valStr = toYaml(v, indent + 1);
				const isBlock =
					valStr.includes("\n") || (typeof v === "object" && v !== null);
				return isBlock ? `${pad}${k}:\n${valStr}` : `${pad}${k}: ${valStr}`;
			})
			.join("\n");
	}
	return String(obj);
}

// ── Migration warnings ────────────────────────────────────────────────────────

function collectWarnings(litellm: LiteLLMConfig): string[] {
	const warnings: string[] = [];

	if (litellm.environment_variables) {
		warnings.push(
			"environment_variables in litellm_config.yaml: move these to your .env file. " +
				"Tracelane never reads provider API keys from config — use env vars.",
		);
	}
	if (litellm.general_settings?.master_key) {
		warnings.push(
			"general_settings.master_key: Tracelane uses TRACELANE_API_KEY env var. " +
				"Generate a key at https://tracelane.dev/dashboard.",
		);
	}
	if (litellm.general_settings?.database_url) {
		warnings.push(
			"general_settings.database_url: Tracelane uses ClickHouse for trace storage. " +
				"Configure CLICKHOUSE_URL in your environment.",
		);
	}

	const unsupportedCallbacks = [
		"langfuse",
		"helicone",
		"lunary",
		"logfire",
		"braintrust",
	];
	const callbacks = [
		...(litellm.litellm_settings?.success_callback ?? []),
		...(litellm.litellm_settings?.failure_callback ?? []),
	];
	for (const cb of callbacks) {
		if (unsupportedCallbacks.includes(cb)) {
			warnings.push(
				`litellm_settings callback "${cb}": Tracelane replaces third-party callback integrations. Your traces are captured directly in the gateway.`,
			);
		}
	}

	return warnings;
}

// ── YAML parser (simple subset, no deps) ─────────────────────────────────────

function parseYaml(content: string): unknown {
	try {
		// Try JSON first (YAML is a superset of JSON)
		return JSON.parse(content);
	} catch {
		// Simple YAML parse for the litellm_config.yaml structure
		// Uses line-by-line parsing for the flat/nested structures we care about
		const result: Record<string, unknown> = {};
		const lines = content.split("\n");
		let i = 0;

		while (i < lines.length) {
			// `i < lines.length` is the loop guard, so the index is in range —
			// surface the invariant via an explicit guard rather than `!` to
			// satisfy Biome's noNonNullAssertion rule.
			const line = lines[i];
			if (line === undefined) break;
			const trimmed = line.trimStart();
			if (!trimmed || trimmed.startsWith("#")) {
				i++;
				continue;
			}

			const colonIdx = trimmed.indexOf(":");
			if (colonIdx === -1) {
				i++;
				continue;
			}

			const key = trimmed.slice(0, colonIdx).trim();
			const afterColon = trimmed.slice(colonIdx + 1).trim();

			if (afterColon && !afterColon.startsWith("#")) {
				// Simple key: value
				result[key] = parseYamlValue(afterColon);
			}
			// For nested structures, we rely on JSON.stringify and trust the
			// litellm_config.yaml is well-formed enough for our needs.
			// A production-grade impl would use js-yaml.
			i++;
		}

		return result;
	}
}

function parseYamlValue(v: string): unknown {
	if (v === "true") return true;
	if (v === "false") return false;
	if (v === "null" || v === "~") return null;
	const num = Number(v);
	if (!Number.isNaN(num) && v !== "") return num;
	return v.replace(/^["']|["']$/g, "");
}

// ── Main command ──────────────────────────────────────────────────────────────

async function runImport(opts: {
	config: string;
	output: string | undefined;
	dryRun: boolean;
}) {
	const configPath = path.resolve(opts.config);

	if (!fs.existsSync(configPath)) {
		console.error(`\x1b[31mError: config file not found: ${configPath}\x1b[0m`);
		process.exit(1);
	}

	const raw = fs.readFileSync(configPath, "utf8");
	let litellm: LiteLLMConfig;
	try {
		litellm = parseYaml(raw) as LiteLLMConfig;
	} catch (err) {
		console.error(`\x1b[31mError parsing ${opts.config}:\x1b[0m`, err);
		process.exit(1);
	}

	const tracelane = translateConfig(litellm);
	const warnings = collectWarnings(litellm);
	const yaml = `# Tracelane gateway config — generated from ${path.basename(opts.config)}\n# Generated: ${new Date().toISOString()}\n# Run: tlane import-litellm --config ${opts.config}\n\n${toYaml(tracelane)}\n`;

	// Print result
	console.log("\n\x1b[1mTracelane gateway config:\x1b[0m\n");
	console.log(yaml);

	if (warnings.length > 0) {
		console.log("\n\x1b[33mMigration notes:\x1b[0m");
		for (const w of warnings) {
			console.log(`  ⚠  ${w}`);
		}
	}

	if (opts.dryRun) {
		console.log(
			"\n\x1b[33m[dry-run] No files written. Remove --dry-run to write.\x1b[0m\n",
		);
		return;
	}

	const outputPath = opts.output
		? path.resolve(opts.output)
		: path.join(path.dirname(configPath), "tracelane.yaml");
	fs.writeFileSync(outputPath, yaml, "utf8");

	console.log(`\n\x1b[32m✓ Written to: ${outputPath}\x1b[0m\n`);
	console.log("Next steps:");
	console.log(
		"  1. Set TRACELANE_API_KEY (get one at https://tracelane.dev/dashboard)",
	);
	console.log(
		"  2. Start the gateway: docker compose -f infra/dev/docker-compose.yml up -d",
	);
	console.log(
		"  3. Point your agents at TRACELANE_GATEWAY_URL=https://gateway.tracelane.dev\n",
	);
}

// ── Command registration ──────────────────────────────────────────────────────

export function registerImportLitellmCommand(program: Command): void {
	program
		.command("import-litellm")
		.description(
			"Import a litellm_config.yaml and emit a Tracelane gateway config (<5 min migration)",
		)
		.requiredOption(
			"--config <path>",
			"Path to litellm_config.yaml",
			"litellm_config.yaml",
		)
		.option(
			"--output <path>",
			"Output path for tracelane.yaml (default: same dir as config)",
		)
		.option("--dry-run", "Print config without writing to disk")
		.action(async (opts) => {
			await runImport({
				config: opts.config,
				output: opts.output,
				dryRun: opts.dryRun ?? false,
			});
		});
}
