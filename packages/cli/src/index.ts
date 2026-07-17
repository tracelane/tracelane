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

const program = new Command();

program
	.name("tlane")
	.description("Tracelane CLI — predictive reliability for AI agents")
	.version("0.1.0");

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
