/**
 * Browserbase instrumentation for Tracelane.
 *
 * Wraps Browserbase session lifecycle to emit OTel spans.
 * Browser-agent traces are the noisiest in agent pipelines — DOM mutations,
 * CAPTCHA detections, and navigation events need observability context.
 * These spans feed Tracelane's stuck-loop predictor (PP-PR4, PP-PR5).
 *
 * @example
 * ```ts
 * import Browserbase from "@browserbasehq/sdk";
 * import { instrumentBrowserbase } from "@tracelanedev/sdk/browserbase";
 *
 * const bb = new Browserbase({ apiKey: process.env.BROWSERBASE_API_KEY! });
 * instrumentBrowserbase(bb);
 * const session = await bb.sessions.create({ projectId: "proj_abc" });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-browserbase", "0.1.0");

interface BrowserbaseClientLike {
	sessions: {
		create: (...args: unknown[]) => Promise<unknown>;
		retrieve?: (...args: unknown[]) => Promise<unknown>;
	};
}

/**
 * Instrument a Browserbase client to emit OTel spans for session operations.
 *
 * @param client - A @browserbasehq/sdk Browserbase instance
 */
export function instrumentBrowserbase(client: BrowserbaseClientLike): void {
	_patchSessionsCreate(client.sessions);
	if (client.sessions.retrieve) {
		_patchSessionsRetrieve(
			client.sessions as Required<BrowserbaseClientLike["sessions"]>,
		);
	}
}

function _patchSessionsCreate(
	sessions: BrowserbaseClientLike["sessions"],
): void {
	const originalCreate = sessions.create.bind(sessions);

	sessions.create = async (...args: unknown[]) => {
		const opts = args[0] as Record<string, unknown> | undefined;
		const projectId = String(opts?.projectId ?? "");

		return tracer.startActiveSpan(
			"browserbase.sessions.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "browserbase",
					"browserbase.project_id": projectId,
					"browserbase.operation": "create_session",
				},
			},
			async (span) => {
				try {
					const result = (await originalCreate(...args)) as Record<
						string,
						unknown
					>;
					const sessionId = result.id ?? result.sessionId;
					if (typeof sessionId === "string") {
						span.setAttribute("browserbase.session_id", sessionId);
					}
					const region = result.region;
					if (typeof region === "string") {
						span.setAttribute("browserbase.region", region);
					}
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}

function _patchSessionsRetrieve(sessions: {
	retrieve: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalRetrieve = sessions.retrieve.bind(sessions);

	sessions.retrieve = async (...args: unknown[]) => {
		const sessionId = String(args[0] ?? "unknown");

		return tracer.startActiveSpan(
			"browserbase.sessions.retrieve",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "browserbase",
					"browserbase.session_id": sessionId,
					"browserbase.operation": "retrieve_session",
				},
			},
			async (span) => {
				try {
					const result = (await originalRetrieve(...args)) as Record<
						string,
						unknown
					>;
					const status = result.status;
					if (typeof status === "string") {
						span.setAttribute("browserbase.session_status", status);
					}
					span.setStatus({ code: SpanStatusCode.OK });
					return result;
				} catch (e) {
					span.recordException(e as Error);
					span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
					throw e;
				} finally {
					span.end();
				}
			},
		);
	};
}
