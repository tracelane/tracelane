#!/usr/bin/env node
/**
 * tlane — Tracelane CLI
 *
 * Commands:
 *   tlane init                    — initialise Tracelane in the current project
 *   tlane trace <id>              — fetch and display a trace
 *   tlane eval run                — run the eval suite
 *   tlane eval list               — list all evals and their status
 *   tlane migrate helicone        — migrate Helicone configuration to Tracelane
 *   tlane import-litellm          — import litellm_config.yaml as Tracelane gateway config
 *   tlane verify <ledger>         — verify a tamper-evident audit ledger (NDJSON)
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";
import { registerEvalCommand } from "./commands/eval.js";
import { registerExportCommand } from "./commands/export.js";
import { registerImportHeliconeCommand } from "./commands/import-helicone.js";
import { registerImportLitellmCommand } from "./commands/import-litellm.js";
import { registerInitCommand } from "./commands/init.js";
import { registerMigrateCommand } from "./commands/migrate.js";
import { registerPromptCommand } from "./commands/prompt.js";
import { registerReplayCommand } from "./commands/replay.js";
import { registerRollbackCommand } from "./commands/rollback.js";
import { registerTraceCommand } from "./commands/trace.js";
import { registerVerifyCommand } from "./commands/verify.js";

// Single source of truth for the CLI version: the package manifest — never
// hardcode (it silently drifts on a version bump). In the built CJS bundle
// __dirname is dist/, so ../package.json is the package root manifest that npm
// always ships alongside dist/.
const { version } = JSON.parse(
	readFileSync(join(__dirname, "..", "package.json"), "utf8"),
) as { version: string };

const program = new Command();

program
	.name("tlane")
	.description("Tracelane CLI — the flight recorder for AI agents")
	.version(version);

registerInitCommand(program);
registerTraceCommand(program);
registerEvalCommand(program);
registerExportCommand(program);
registerMigrateCommand(program);
registerReplayCommand(program);
registerImportHeliconeCommand(program);
registerImportLitellmCommand(program);
registerVerifyCommand(program);
registerPromptCommand(program);
registerRollbackCommand(program);

program.parse();
