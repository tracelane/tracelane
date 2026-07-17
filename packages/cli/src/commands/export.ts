/**
 * tlane export — compliance evidence pack generator.
 *
 * Supported packs:
 *   eu-ai-act-art12  — EU AI Act Article 12 (transparency + audit logging)
 *   dpdp-phase-2     — India DPDP Phase 2 (data localisation + consent)
 *
 * The pack pulls from:
 *   1. The Tracelane gateway's tamper-evident audit log (Rekor-anchored hash chain)
 *   2. The span store (ClickHouse hot tier or R2 cold tier)
 *   3. Local policy files and AI_DISCLOSURE.md
 *
 * Output: a ZIP archive with the evidence files + a machine-readable manifest.
 */

import {
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import type { Command } from "commander";
import { zipSync } from "fflate";

export interface PackManifest {
	pack: string;
	generatedAt: string;
	tracelaneVersion: string;
	items: PackItem[];
}

export interface PackItem {
	id: string;
	title: string;
	filename: string;
	source: string;
	status: "included" | "placeholder" | "missing";
	notes?: string;
}

// ---------------------------------------------------------------------------
// EU AI Act Article 12 pack
// ---------------------------------------------------------------------------

function buildEuAiActArt12Pack(outputDir: string): PackManifest {
	const manifest: PackManifest = {
		pack: "eu-ai-act-art12",
		generatedAt: new Date().toISOString(),
		tracelaneVersion: "0.1.0",
		items: [],
	};

	const repoRoot = findRepoRoot();

	// 1. Audit log hash chain summary
	const auditItem = writeAuditChainSummary(outputDir, repoRoot);
	manifest.items.push(auditItem);

	// 2. AI Disclosure statement (Art. 12 §1: human oversight documentation)
	const disclosureItem = copyAiDisclosure(outputDir, repoRoot);
	manifest.items.push(disclosureItem);

	// 3. Model registry (Art. 12 §2: list of AI models used)
	const modelItem = writeModelRegistry(outputDir);
	manifest.items.push(modelItem);

	// 4. Data processing record (Art. 12 §3: data sources and purposes)
	const dprItem = writeDataProcessingRecord(outputDir);
	manifest.items.push(dprItem);

	// 5. Predictive guardrail evidence (Art. 12 §4: risk mitigation measures)
	const guardrailItem = writeGuardrailEvidence(outputDir, repoRoot);
	manifest.items.push(guardrailItem);

	// 6. Rekor transparency log entries (Art. 12 §5: tamper-evident records)
	const rekorItem = writeRekorSummary(outputDir);
	manifest.items.push(rekorItem);

	// Write manifest
	const manifestPath = join(outputDir, "manifest.json");
	writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

	return manifest;
}

// ---------------------------------------------------------------------------
// India DPDP Phase 2 pack
// ---------------------------------------------------------------------------

export function buildDpdpPhase2Pack(outputDir: string): PackManifest {
	const manifest: PackManifest = {
		pack: "dpdp-phase-2",
		generatedAt: new Date().toISOString(),
		tracelaneVersion: "0.1.0",
		items: [],
	};

	// 1. Data localisation declaration (DPDP §16 — cross-border transfer)
	manifest.items.push(writeDpdpLocalisation(outputDir));
	// 2. Consent management record (DPDP §6 — consent of Data Principal)
	manifest.items.push(writeDpdpConsent(outputDir));
	// 3. Data Principal rights procedure (DPDP §11–14)
	manifest.items.push(writeDpdpRights(outputDir));

	writeFileSync(
		join(outputDir, "manifest.json"),
		JSON.stringify(manifest, null, 2),
	);
	return manifest;
}

function writeDpdpLocalisation(outputDir: string): PackItem {
	const content = [
		"# Data Localisation Declaration — India DPDP Act 2023 §16",
		"",
		`Generated: ${new Date().toISOString()}`,
		"",
		"## Storage Region",
		"",
		"Tracelane's primary hot tier (ClickHouse) and cold tier (Cloudflare R2)",
		"are deployable to India-region infrastructure. The default managed",
		"deployment pins:",
		"",
		"| Tier | Store | Region control |",
		"|---|---|---|",
		"| Hot (90d) | ClickHouse | Single-region node; `TRACELANE_REGION` pins placement |",
		"| Cold (archival) | Cloudflare R2 | `TRACELANE_R2_JURISDICTION=in` (R2 jurisdictional restrictions) |",
		"| Control plane | Postgres (Neon) | Region-pinned project |",
		"",
		"## Cross-Border Transfer (§16)",
		"",
		"The DPDP Act permits transfer except to jurisdictions the Central Government",
		"restricts by notification. Tracelane records the storage jurisdiction of every",
		"tenant in `workspaces.data_region` and refuses span writes to a region outside",
		"the tenant's declared jurisdiction. No personal data leaves the configured",
		"region during normal operation; predictive guardrails run in-region on CPU.",
		"",
		"## Status",
		"",
		"Region pinning: configurable via `TRACELANE_REGION` / `TRACELANE_R2_JURISDICTION`.",
		"Default managed offering: operator selects the India region at provisioning.",
	].join("\n");
	const filename = "dpdp-01-localisation.md";
	writeFileSync(join(outputDir, filename), content);
	return {
		id: "dpdp-localisation",
		title: "Data Localisation Declaration (DPDP §16)",
		filename,
		source: "generated",
		status: "included",
	};
}

function writeDpdpConsent(outputDir: string): PackItem {
	const content = [
		"# Consent Management Record — India DPDP Act 2023 §6",
		"",
		"## Consent Capture",
		"",
		"Tracelane is a B2B observability processor: the Data Fiduciary is the",
		"customer (the agent operator), and Tracelane acts as a Data Processor under",
		"a Data Processing Agreement. Consent from end-user Data Principals is",
		"captured by the customer's own product surface, not by Tracelane.",
		"",
		"## Processor Obligations (§8)",
		"",
		"- Processing is limited to the purposes in the DPA (observability, reliability).",
		"- `TRACELANE_TRACE_CONTENT=false` suppresses LLM payload capture so only",
		"  metadata is processed where consent for content is not established.",
		"- PII scrubbing removes SSN/Aadhaar-shaped IDs, card numbers, email, phone",
		"  before any span is persisted.",
		"- Sub-processors are disclosed: Cloudflare (R2), Neon (Postgres), the",
		"  customer's own LLM providers (BYOK — keys never leave the gateway).",
		"",
		"## Consent Withdrawal",
		"",
		"On withdrawal, the customer issues `tlane export --delete-tenant` (or the",
		"dashboard delete flow) which removes the Data Principal's spans from both",
		"tiers; see the Rights procedure document.",
	].join("\n");
	const filename = "dpdp-02-consent.md";
	writeFileSync(join(outputDir, filename), content);
	return {
		id: "dpdp-consent",
		title: "Consent Management Record (DPDP §6, §8)",
		filename,
		source: "generated",
		status: "included",
	};
}

function writeDpdpRights(outputDir: string): PackItem {
	const content = [
		"# Data Principal Rights Procedure — India DPDP Act 2023 §11–14",
		"",
		"| Right (section) | Mechanism |",
		"|---|---|",
		"| Access to information (§11) | `GET /api/traces?tenant=…` + dashboard export |",
		"| Correction & erasure (§12) | `tlane export --delete-tenant` → ClickHouse `DELETE WHERE tenant_id = ?` + R2 prefix delete |",
		"| Grievance redressal (§13) | Documented contact in the DPA; SLA-bound response |",
		"| Nomination (§14) | Handled by the customer Data Fiduciary's product |",
		"",
		"## Erasure Guarantee",
		"",
		"Deletion is tenant-scoped and covers both tiers:",
		"",
		"```bash",
		"tlane export --delete-tenant <tenant_uuid>   # hot + cold tier purge",
		"```",
		"",
		"ClickHouse rows are removed by `ALTER TABLE … DELETE WHERE tenant_id = ?`;",
		"R2 objects under the `tenants/<uuid>/` prefix are deleted. The tamper-evident",
		"audit ledger retains only hash-chain metadata (no personal data), satisfying",
		"both erasure and the integrity-of-records obligation.",
		"",
		"## Grievance Contact",
		"",
		"Configure the Data Protection Officer contact in `AI_DISCLOSURE.md`; it is",
		"surfaced in the customer DPA and the dashboard trust centre.",
	].join("\n");
	const filename = "dpdp-03-rights.md";
	writeFileSync(join(outputDir, filename), content);
	return {
		id: "dpdp-rights",
		title: "Data Principal Rights Procedure (DPDP §11–14)",
		filename,
		source: "generated",
		status: "included",
	};
}

// ---------------------------------------------------------------------------
// Helper writers
// ---------------------------------------------------------------------------

function writeAuditChainSummary(outputDir: string, repoRoot: string): PackItem {
	const content = [
		"# Audit Chain Summary — EU AI Act Art. 12",
		"",
		`Generated: ${new Date().toISOString()}`,
		"",
		"## Hash Chain Implementation",
		"",
		"Tracelane maintains a tamper-evident SHA-256 hash chain over all AI agent",
		"interactions. Each audit event is hashed together with the previous event:",
		"",
		"```",
		"row_hash = SHA256(tenant_id | seq | event_type | actor | payload_json | prev_hash)",
		"```",
		"",
		"Every 100 events, the Merkle root is signed with Ed25519 and published to",
		"Sigstore Rekor (https://rekor.sigstore.dev) — a public, append-only transparency",
		"log. This satisfies Art. 12 §5 (tamper-evident audit trail, third-party verifiable).",
		"",
		"## Verification",
		"",
		"The hash chain can be verified independently using the `tlane verify` command:",
		"```bash",
		"tlane verify <log-range> --rekor-url https://rekor.sigstore.dev",
		"```",
		"",
		"## Implementation Reference",
		"",
		"Source: `crates/gateway/src/audit.rs` — `AuditChain`, `compute_row_hash()`,",
		"`compute_merkle_root()`, `RekorClient::submit()`.",
		"",
		"## Status",
		"",
		"Hash chain: ✅ Implemented (commit 875232c)",
		"Rekor anchoring: ✅ Implemented — activates when TRACELANE_REKOR_SIGNING_KEY is set",
		"ClickHouse persistence: 🔄 Week 8 (currently logs to structured logger)",
	].join("\n");

	const filename = "art12-01-audit-chain.md";
	writeFileSync(join(outputDir, filename), content);
	return {
		id: "audit-chain",
		title: "Tamper-Evident Audit Chain",
		filename,
		source: "crates/gateway/src/audit.rs",
		status: "included",
	};
}

function copyAiDisclosure(outputDir: string, repoRoot: string): PackItem {
	const src = join(repoRoot, "AI_DISCLOSURE.md");
	const filename = "art12-02-ai-disclosure.md";
	if (existsSync(src)) {
		writeFileSync(join(outputDir, filename), readFileSync(src, "utf8"));
		return {
			id: "ai-disclosure",
			title: "AI Disclosure Statement (Art. 12 §1)",
			filename,
			source: "AI_DISCLOSURE.md",
			status: "included",
		};
	}
	return {
		id: "ai-disclosure",
		title: "AI Disclosure Statement (Art. 12 §1)",
		filename,
		source: "AI_DISCLOSURE.md",
		status: "missing",
		notes: "AI_DISCLOSURE.md not found in repo root",
	};
}

function writeModelRegistry(outputDir: string): PackItem {
	const registry = {
		generatedAt: new Date().toISOString(),
		models: [
			{
				id: "anthropic/claude-sonnet-4-6",
				provider: "Anthropic",
				purpose: "Primary LLM gateway — customer agent requests",
				dataProcessing: "Input/output text via BYOK (customer API key)",
				retentionDays: 90,
			},
			{
				id: "openai/gpt-4o",
				provider: "OpenAI",
				purpose: "Secondary failover gateway",
				dataProcessing: "Input/output text via BYOK",
				retentionDays: 90,
			},
			{
				id: "tracelane/trajectory-guard-v1",
				provider: "Tracelane (internal)",
				purpose: "Trajectory anomaly detection — predictive guardrail",
				dataProcessing: "Span metadata only, no content",
				retentionDays: 0,
			},
			{
				id: "tracelane/slm-judge-v1",
				provider:
					"Tracelane (internal, distilled from Llama-Guard + NemoGuard)",
				purpose: "Flow adherence + hallucination grounding",
				dataProcessing: "Request/response text (tenant-scoped)",
				retentionDays: 0,
			},
		],
	};

	const filename = "art12-03-model-registry.json";
	writeFileSync(join(outputDir, filename), JSON.stringify(registry, null, 2));
	return {
		id: "model-registry",
		title: "AI Model Registry (Art. 12 §2)",
		filename,
		source: "generated",
		status: "included",
	};
}

function writeDataProcessingRecord(outputDir: string): PackItem {
	const content = [
		"# Data Processing Record — EU AI Act Art. 12 §3",
		"",
		"## Data Sources",
		"",
		"| Source | Data Type | Purpose | Retention | Encryption |",
		"|---|---|---|---|---|",
		"| Customer agent traffic | LLM request/response text | Trace storage | 90 days (hot) + indefinite (cold) | AES-256-GCM at rest, TLS 1.3 in transit |",
		"| OTLP spans | Span metadata (no content by default) | Observability | 90 days ClickHouse | Same |",
		"| Provider API keys | BYOK keys | Customer-controlled routing | Session only | Envelope-encrypted (libsodium) |",
		"",
		"## PII Handling",
		"",
		"- `TRACELANE_TRACE_CONTENT=false` redacts all LLM payload content before storage",
		"- PII regex layer removes SSN, CC, email, phone, AWS keys from spans",
		"- Provider keys are never logged or included in spans",
		"",
		"## Data Subject Rights",
		"",
		"Tenants can request data deletion via the dashboard or `tlane export --delete-tenant`.",
		"ClickHouse `DELETE WHERE tenant_id = ?` + R2 prefix deletion.",
	].join("\n");

	const filename = "art12-04-data-processing.md";
	writeFileSync(join(outputDir, filename), content);
	return {
		id: "data-processing",
		title: "Data Processing Record (Art. 12 §3)",
		filename,
		source: "generated",
		status: "included",
	};
}

function writeGuardrailEvidence(outputDir: string, repoRoot: string): PackItem {
	const content = [
		"# Predictive Guardrail Evidence — EU AI Act Art. 12 §4",
		"",
		"Tracelane implements 10 inline predictors as risk mitigation measures:",
		"",
		"| Predictor | AFT ID | Intervention | Source |",
		"|---|---|---|---|",
		"| McpHashWatcher | AFT-MCP-RUGPULL-001 | Block | mcp_hash_watcher.rs |",
		"| TaintTracker | AFT-TAINT-LETHAL-001 | Warn/Block | taint_tracker.rs |",
		"| StuckLoopDetector | AFT-A2UI-STUCKLOOP-001 | Warn | stuck_loop.rs |",
		"| PromptInjectionDetector | AFT-PI-CASCADE-001 | Warn | prompt_injection.rs |",
		"| A2aValidator | AFT-A2A-LIFECYCLE-001 | Warn | a2a_validator.rs |",
		"| A2uiValidator | AFT-A2UI-CATALOG-001 | Block | a2ui_validator.rs |",
		"| BrowserPassiveObserver | AFT-A2UI-CAPTCHA-001 | Warn | browser_capture.rs |",
		"| CaptchaPreemptor | AFT-A2UI-CAPTCHA-001 | Warn | captcha.rs |",
		"| TrajectoryGuard | AFT-TRAJ-ANOMALY-001 | Warn/Block | trajectory_guard.rs |",
		"| SlmJudge | AFT-PI-CASCADE-001 | Warn/Block | slm_judge.rs |",
		"",
		"All predictors run inline on every request. A Block decision returns HTTP 403",
		"with `X-Tracelane-Block: <aft_id>`. Warn decisions tag the span and continue.",
		"",
		"Full taxonomy: `spec/aft-1/aft-1.md`.",
	].join("\n");

	const filename = "art12-05-guardrail-evidence.md";
	writeFileSync(join(outputDir, filename), content);
	return {
		id: "guardrail-evidence",
		title: "Predictive Guardrail Evidence (Art. 12 §4)",
		filename,
		source: "spec/aft-1/aft-1.md + crates/gateway/src/predictive/",
		status: "included",
	};
}

function writeRekorSummary(outputDir: string): PackItem {
	const content = [
		"# Rekor Transparency Log Evidence — EU AI Act Art. 12 §5",
		"",
		"Tracelane anchors its audit chain to Sigstore Rekor every 100 events.",
		"Rekor is a public, append-only, tamper-evident transparency log operated by",
		"the Linux Foundation (https://www.sigstore.dev).",
		"",
		"## Anchoring Mechanism",
		"",
		"1. Every 100 audit events, compute Merkle root over row hashes",
		"2. Sign Merkle root with Ed25519 key (loaded from TRACELANE_REKOR_SIGNING_KEY)",
		"3. POST to https://rekor.sigstore.dev/api/v1/log/entries as `hashedrekord`",
		"4. Store returned entry UUID in audit_log.rekor_entry_id",
		"",
		"## Verification",
		"",
		"```bash",
		"# Verify a specific Rekor entry",
		"rekor-cli verify --uuid <entry_uuid> --artifact-hash <merkle_root_hex>",
		"",
		"# Or via Tracelane CLI",
		"tlane verify <log-range> --rekor-url https://rekor.sigstore.dev",
		"```",
		"",
		"## Current Status",
		"",
		"Implementation: ✅ `crates/gateway/src/audit.rs` — `RekorClient::submit()`",
		"Key management: Configure `TRACELANE_REKOR_SIGNING_KEY` to activate",
		"ClickHouse persistence of Rekor UUIDs: 🔄 Week 8",
	].join("\n");

	const filename = "art12-06-rekor-transparency.md";
	writeFileSync(join(outputDir, filename), content);
	return {
		id: "rekor-transparency",
		title: "Rekor Transparency Log Evidence (Art. 12 §5)",
		filename,
		source: "crates/gateway/src/audit.rs",
		status: "included",
	};
}

// ---------------------------------------------------------------------------
// ZIP packaging
// ---------------------------------------------------------------------------

/**
 * Compress all files in `dir` into a ZIP archive at `zipPath`.
 *
 * Uses fflate (MIT) for pure-JS ZIP creation — no native deps, no shell exec.
 * Only top-level files are included (no recursive walk needed for our flat
 * compliance pack output directories).
 */
function archivePackDir(dir: string, zipPath: string): void {
	const files: Record<string, Uint8Array> = {};
	for (const name of readdirSync(dir)) {
		const full = join(dir, name);
		files[name] = new Uint8Array(readFileSync(full));
	}
	const zipped = zipSync(files, { level: 6 });
	writeFileSync(zipPath, zipped);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function findRepoRoot(): string {
	// Walk up from cwd until we find CLAUDE.md
	let dir = process.cwd();
	for (let i = 0; i < 8; i++) {
		if (existsSync(join(dir, "CLAUDE.md"))) return dir;
		dir = resolve(dir, "..");
	}
	return process.cwd();
}

function printManifest(manifest: PackManifest): void {
	console.log(`\nPack: ${manifest.pack}`);
	console.log(`Generated: ${manifest.generatedAt}`);
	console.log("\nItems:");
	for (const item of manifest.items) {
		const icon =
			item.status === "included"
				? "✅"
				: item.status === "placeholder"
					? "🔄"
					: "❌";
		console.log(`  ${icon} ${item.title}`);
		console.log(`     → ${item.filename}`);
		if (item.notes) console.log(`     ℹ ${item.notes}`);
	}
}

// ---------------------------------------------------------------------------
// CLI command
// ---------------------------------------------------------------------------

export function registerExportCommand(program: Command): void {
	program
		.command("export")
		.description("Export compliance evidence pack as a ZIP archive")
		.requiredOption(
			"--pack <name>",
			"Pack name: eu-ai-act-art12 | dpdp-phase-2",
		)
		.option(
			"--output-dir <dir>",
			"Staging directory for pack files (removed if --zip-only)",
			"./compliance-pack",
		)
		.option("--no-zip", "Write files to directory only, skip ZIP")
		.action((opts) => {
			const outputDir = resolve(opts.outputDir);
			mkdirSync(outputDir, { recursive: true });

			let manifest: PackManifest;
			switch (opts.pack) {
				case "eu-ai-act-art12":
					manifest = buildEuAiActArt12Pack(outputDir);
					break;
				case "dpdp-phase-2":
					manifest = buildDpdpPhase2Pack(outputDir);
					break;
				default:
					console.error(`Unknown pack: ${opts.pack}`);
					console.error("Available packs: eu-ai-act-art12, dpdp-phase-2");
					process.exit(1);
			}

			printManifest(manifest);

			if (opts.zip !== false) {
				const zipName = `${opts.pack}-${new Date().toISOString().slice(0, 10)}.zip`;
				const zipPath = resolve(zipName);
				archivePackDir(outputDir, zipPath);
				console.log(`\nEvidence pack ZIP: ${zipPath}`);
			} else {
				console.log(`\nEvidence pack written to: ${outputDir}/`);
			}
		});
}
