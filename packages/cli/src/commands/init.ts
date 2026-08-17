/**
 * tlane init — scaffold Tracelane into the current project.
 *
 * Four things, in this order, each independently skippable:
 *
 *  1. `tracelane.config.json` — endpoint, service name, sample rate.
 *  2. `.env` — the `TRACELANE_*` keys something in the shipped surface actually
 *     reads, merged in without ever rewriting a value you already set, plus a
 *     `.gitignore` entry so the key file is not tracked.
 *  3. `tracelane.ts` / `tracelane.mjs` / `tracelane_init.py` — the
 *     instrumentation bootstrap for whatever frameworks were detected in your
 *     manifests.
 *  4. The SDK install, run with your own package manager (inferred from the
 *     lockfile), inheriting stdio so you see exactly what it does.
 *
 * Both writes that could destroy something refuse to: the config uses an
 * exclusive-create (`wx`) syscall and needs `--force`, and `.env` is only ever
 * appended to. `--no-env`, `--no-instrument` and `--no-install` opt out.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { relative, resolve } from "node:path";
import process from "node:process";
import type { Command } from "commander";
import {
	type Detection,
	buildEnvEntries,
	buildNodeBootstrap,
	buildPythonBootstrap,
	detectProject,
	ensureEnvIgnored,
	mergeEnv,
} from "./init-detect.js";

export interface TracelaneInitConfig {
	endpoint: string;
	serviceName: string;
	sampleRate: number;
}

export const CONFIG_FILENAME = "tracelane.config.json";
export const ENV_FILENAME = ".env";

/**
 * Runs the SDK install. Injected so tests can assert the exact argv without a
 * network call — a real install in a unit test is a banned pattern here.
 */
export type CommandRunner = (
	command: string,
	args: readonly string[],
	cwd: string,
) => { status: number | null; error?: Error };

export interface InitDeps {
	run?: CommandRunner;
}

const defaultRunner: CommandRunner = (command, args, cwd) => {
	// `shell: false` (the default) is load-bearing: command and args come from a
	// fixed table, and running them through a shell would make any future
	// project-derived value an injection sink.
	const r = spawnSync(command, [...args], { cwd, stdio: "inherit" });
	return { status: r.status, error: r.error };
};

/** Build the config object written by `tlane init` (pure — unit-tested). */
export function buildInitConfig(opts: {
	endpoint: string;
	serviceName: string;
	sampleRate?: number;
}): TracelaneInitConfig {
	const rate =
		opts.sampleRate === undefined
			? 1.0
			: Math.min(1, Math.max(0, opts.sampleRate));
	return {
		endpoint: opts.endpoint.replace(/\/$/, ""),
		serviceName: opts.serviceName,
		sampleRate: rate,
	};
}

function writeExclusive(
	target: string,
	body: string,
	force: boolean,
): "written" | "exists" {
	// `wx` fails if the path exists, so the exists-check and the write are ONE
	// atomic syscall. The previous `existsSync(target)` + `writeFileSync` was a
	// TOCTOU race (CodeQL js/file-system-race, high): anything created in the
	// window between the two — including a symlink into a path the user did not
	// intend to write — was overwritten without --force.
	try {
		writeFileSync(target, body, { flag: force ? "w" : "wx" });
		return "written";
	} catch (err) {
		if ((err as NodeJS.ErrnoException).code === "EEXIST") return "exists";
		throw err;
	}
}

/** Merge the Tracelane keys into `.env` and make sure git ignores it. */
function scaffoldEnv(dir: string): void {
	const target = resolve(dir, ENV_FILENAME);
	const existing = existsSync(target) ? readFileSync(target, "utf8") : "";
	const merged = mergeEnv(existing, buildEnvEntries());

	if (merged.added.length === 0) {
		console.log(
			`  ${ENV_FILENAME}  unchanged — already has ${merged.kept.join(", ")}`,
		);
	} else {
		writeFileSync(target, merged.content, "utf8");
		const keptNote =
			merged.kept.length > 0
				? ` (left ${merged.kept.join(", ")} untouched)`
				: "";
		console.log(`  ${ENV_FILENAME}  +${merged.added.join(", +")}${keptNote}`);
	}

	const gitignore = resolve(dir, ".gitignore");
	if (!existsSync(gitignore)) {
		console.log(
			`  note: no .gitignore here — make sure ${ENV_FILENAME} is not committed.`,
		);
		return;
	}
	const updated = ensureEnvIgnored(readFileSync(gitignore, "utf8"));
	if (updated !== undefined) {
		writeFileSync(gitignore, updated, "utf8");
		console.log(`  .gitignore  +${ENV_FILENAME}`);
	}
}

/** Write the instrumentation bootstrap for one detected ecosystem. */
function scaffoldBootstrap(
	dir: string,
	det: Detection,
	config: TracelaneInitConfig,
	force: boolean,
): void {
	const body =
		det.ecosystem === "node"
			? buildNodeBootstrap(config, det.adapters, det.bootstrapFile)
			: buildPythonBootstrap(config, det.adapters);
	const target = resolve(dir, det.bootstrapFile);

	if (writeExclusive(target, body, force) === "exists") {
		console.log(
			`  ${det.bootstrapFile}  kept — already exists (re-run with --force to regenerate)`,
		);
		return;
	}

	const wired = det.adapters.filter((a) => a.wiring === "auto");
	const manual = det.adapters.filter((a) => a.wiring === "object");
	const summary =
		det.adapters.length === 0
			? "no framework detected"
			: [
					wired.length > 0 ? `wired: ${wired.map((a) => a.id).join(", ")}` : "",
					manual.length > 0
						? `wire up yourself: ${manual.map((a) => a.id).join(", ")}`
						: "",
				]
					.filter(Boolean)
					.join("; ");
	console.log(`  ${det.bootstrapFile}  ${summary}`);
}

/**
 * Install the SDK with the project's own package manager.
 *
 * @returns true on success. A failure is reported with the exact command so it
 * can be re-run by hand; the scaffolded files are already on disk and are not
 * rolled back.
 */
function installSdk(dir: string, det: Detection, run: CommandRunner): boolean {
	const display = [det.install.command, ...det.install.args].join(" ");
	console.log(`  $ ${display}`);
	const r = run(det.install.command, det.install.args, dir);
	if (r.error) {
		console.error(
			`  install failed to start (${r.error.message}) — run it yourself:\n    ${display}`,
		);
		return false;
	}
	if (r.status !== 0) {
		console.error(
			`  install exited ${r.status ?? "with a signal"} — run it yourself:\n    ${display}`,
		);
		return false;
	}
	return true;
}

export function registerInitCommand(
	program: Command,
	deps: InitDeps = {},
): void {
	const run = deps.run ?? defaultRunner;
	program
		.command("init")
		.description("Initialise Tracelane in the current project")
		// NB: the default is an ingest receiver YOU run. Tracelane Cloud has no
		// public OTLP ingress — hosted traces are captured at the gateway, so a
		// Cloud user sets no endpoint here and points their OpenAI-compatible
		// client at https://gateway.tracelane.dev/v1 instead. The pre-0.2.2
		// default was `https://ingest.tracelane.dev`, a hostname that has never
		// resolved (NXDOMAIN), so `tlane init` scaffolded a dead config.
		.option(
			"--endpoint <url>",
			"OTLP endpoint of the ingest receiver you run",
			"http://localhost:4318",
		)
		.option("--service-name <name>", "OTel service.name", "my-agent")
		.option("--sample-rate <rate>", "Head sample rate 0.0–1.0", "1.0")
		.option("--force", "Overwrite an existing config / bootstrap")
		.option("--no-env", "Do not scaffold .env")
		.option("--no-instrument", "Do not write the instrumentation bootstrap")
		.option("--no-install", "Do not install the SDK")
		.action((opts) => {
			const dir = process.cwd();
			const config = buildInitConfig({
				endpoint: opts.endpoint,
				serviceName: opts.serviceName,
				sampleRate: Number(opts.sampleRate),
			});

			const configTarget = resolve(dir, CONFIG_FILENAME);
			const body = `${JSON.stringify(config, null, 2)}\n`;
			if (
				writeExclusive(configTarget, body, Boolean(opts.force)) === "exists"
			) {
				console.error(
					`${CONFIG_FILENAME} already exists. Re-run with --force to overwrite.`,
				);
				process.exit(1);
			}
			console.log(`Wrote ${relative(dir, configTarget) || CONFIG_FILENAME}`);

			if (opts.env !== false) scaffoldEnv(dir);

			const detections = detectProject(dir);
			for (const det of detections) {
				for (const w of det.warnings) console.error(`  warning: ${w}`);
			}

			if (detections.length === 0) {
				console.log(
					"  no package.json, pyproject.toml, requirements.txt or Pipfile here —" +
						" skipped the SDK install and the instrumentation bootstrap.",
				);
			}

			if (opts.instrument !== false) {
				for (const det of detections) {
					scaffoldBootstrap(dir, det, config, Boolean(opts.force));
				}
			}

			let installOk = true;
			if (opts.install !== false) {
				for (const det of detections) {
					if (!installSdk(dir, det, run)) installOk = false;
				}
			} else if (detections.length > 0) {
				for (const det of detections) {
					console.log(
						`  skipped install — run it yourself: ${[det.install.command, ...det.install.args].join(" ")}`,
					);
				}
			}

			console.log("\nNext steps:");
			let step = 1;
			for (const det of detections) {
				if (opts.instrument !== false) {
					console.log(
						`  ${step++}. Import ${det.bootstrapFile} once, before any model call.`,
					);
				}
			}
			console.log(
				`  ${step++}. Put your key in ${ENV_FILENAME} (TRACELANE_API_KEY=tlane_…).`,
			);
			console.log(
				`  ${step}. Confirm spans land: tlane trace <traceId> --format timeline`,
			);

			if (!installOk) process.exit(1);
		});
}
