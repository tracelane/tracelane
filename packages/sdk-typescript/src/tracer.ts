/**
 * OTel tracer initialisation for the Tracelane SDK.
 *
 * Uses the official @opentelemetry/sdk-node and OTLP HTTP exporter.
 * Never calls home from the SDK — all telemetry goes to the configured
 * endpoint only, which defaults to the Tracelane ingest OTLP port.
 */

import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { NodeSDK } from "@opentelemetry/sdk-node";

export interface TracelaneConfig {
	/** OTLP endpoint, e.g. https://ingest.tracelane.dev or http://localhost:4318 */
	endpoint: string;
	/** Tracelane API key for tenant authentication */
	apiKey: string;
	/** Service name for resource attribution (default: "unknown-service") */
	serviceName?: string;
	/** Sampling ratio 0.0–1.0 (default: 1.0 — full trace, tail sampler decides) */
	sampleRate?: number;
}

let sdk: NodeSDK | undefined;

/**
 * Initialise the Tracelane OTel SDK.
 *
 * Must be called before any instrumented code runs.
 * Safe to call multiple times — subsequent calls are no-ops.
 *
 * @param config - Tracelane connection config
 */
export function init(config: TracelaneConfig): void {
	if (sdk) return;

	const exporter = new OTLPTraceExporter({
		url: `${config.endpoint}/v1/traces`,
		headers: {
			"x-tracelane-api-key": config.apiKey,
		},
	});

	sdk = new NodeSDK({
		serviceName: config.serviceName ?? "unknown-service",
		traceExporter: exporter,
	});

	sdk.start();

	process.on("beforeExit", async () => {
		await shutdown();
	});
}

/**
 * Flush pending spans and shut down the OTel SDK.
 *
 * Call at application shutdown to ensure all spans are exported.
 */
export async function shutdown(): Promise<void> {
	if (sdk) {
		await sdk.shutdown();
		sdk = undefined;
	}
}
