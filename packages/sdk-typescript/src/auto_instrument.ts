/**
 * Zero-config auto-instrumentation is NOT available in this release.
 *
 * Auto-detecting and wrapping every installed AI client requires patching each
 * `autoInstrument()` today throws with a pointer to the real API rather than
 * silently doing nothing — an honest failure beats a no-op that looks wired.
 *
 * For v1, use the explicit surface: `init()` once, then wrap each client:
 *
 * @example
 * ```ts
 * import { init, instrumentAnthropic } from "@tracelanedev/sdk";
 * import Anthropic from "@anthropic-ai/sdk";
 *
 * init({ endpoint: "https://ingest.tracelane.dev", apiKey: process.env.TRACELANE_API_KEY! });
 *
 * const client = new Anthropic();
 * instrumentAnthropic(client); // client.messages.create() now emits spans
 * ```
 */

/**
 * Not implemented in v1 — always throws. Zero-config auto-instrumentation ships
 *
 * @throws Always — with a pointer to the real API.
 */
export function autoInstrument(): never {
	throw new Error(
		"autoInstrument() is not available yet — zero-config auto-instrumentation ships in " +
			"tracelane v1.1. For now: call init() once, then wrap each client explicitly, e.g.\n" +
			'  import { init, instrumentAnthropic } from "@tracelanedev/sdk";\n' +
			'  init({ endpoint: "https://ingest.tracelane.dev", apiKey: process.env.TRACELANE_API_KEY });\n' +
			"  const client = new Anthropic();\n" +
			"  instrumentAnthropic(client);\n" +
			"See the instrument* exports (instrumentOpenAI, instrumentLangGraph, …) — one per supported library.",
	);
}
