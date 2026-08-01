/**
 * tlane init — scaffold Tracelane into the current project.
 *
 * Writes a `tracelane.config.json` to the working directory with the ingest
 * endpoint, service name, and sample rate, then prints the SDK install + wire
 * steps. Refuses to clobber an existing config unless `--force` is given.
 */

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import type { Command } from "commander";

export interface TracelaneInitConfig {
	endpoint: string;
	serviceName: string;
	sampleRate: number;
}

export const CONFIG_FILENAME = "tracelane.config.json";

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

export function registerInitCommand(program: Command): void {
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
		.option("--force", "Overwrite an existing tracelane.config.json")
		.action((opts) => {
			const target = resolve(process.cwd(), CONFIG_FILENAME);
			const config = buildInitConfig({
				endpoint: opts.endpoint,
				serviceName: opts.serviceName,
				sampleRate: Number(opts.sampleRate),
			});
			const body = `${JSON.stringify(config, null, 2)}\n`;
			// `wx` fails if the path exists, so the exists-check and the write are
			// ONE atomic syscall. The previous `existsSync(target)` + `writeFileSync`
			// was a TOCTOU race (CodeQL js/file-system-race, high): anything created
			// in the window between the two — including a symlink into a path the
			// user did not intend to write — was overwritten without --force.
			try {
				writeFileSync(target, body, { flag: opts.force ? "w" : "wx" });
			} catch (err) {
				if ((err as NodeJS.ErrnoException).code === "EEXIST") {
					console.error(
						`${CONFIG_FILENAME} already exists. Re-run with --force to overwrite.`,
					);
					process.exit(1);
				}
				throw err;
			}
			console.log(`Wrote ${target}`);
			console.log("\nNext steps:");
			console.log("  1. Install the SDK:");
			console.log("       pip install tracelane      # Python");
			console.log("       pnpm add @tracelanedev/sdk     # TypeScript");
			console.log("  2. Initialise at startup:");
			console.log(
				`       init(endpoint="${config.endpoint}", api_key=os.environ["TRACELANE_API_KEY"])`,
			);
		});
}
