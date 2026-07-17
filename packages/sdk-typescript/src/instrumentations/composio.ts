/**
 * Composio instrumentation for Tracelane.
 *
 * Wraps ComposioToolSet.executeAction() to emit OTel spans.
 * Composio agents generate the highest cardinality of tool-call traces —
 * these spans let operators detect runaway tool chains and cost overruns
 * in complex multi-tool agent workflows.
 *
 * @example
 * ```ts
 * import { ComposioToolSet } from "composio-core";
 * import { instrumentComposio } from "@tracelanedev/sdk/composio";
 *
 * const toolset = new ComposioToolSet({ apiKey: process.env.COMPOSIO_API_KEY! });
 * instrumentComposio(toolset);
 * const result = await toolset.executeAction("GITHUB_CREATE_ISSUE", {
 *   owner: "myorg", repo: "myrepo", title: "Bug report"
 * });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-composio", "0.1.0");

interface ComposioToolSetLike {
	executeAction: (...args: unknown[]) => Promise<unknown>;
	getTools?: (...args: unknown[]) => Promise<unknown>;
}

/**
 * Instrument a ComposioToolSet instance to emit OTel spans.
 *
 * @param toolset - A composio-core ComposioToolSet instance
 */
export function instrumentComposio(toolset: ComposioToolSetLike): void {
	_patchExecuteAction(toolset);
	if (toolset.getTools) {
		_patchGetTools(
			toolset as Required<Pick<ComposioToolSetLike, "getTools">> &
				ComposioToolSetLike,
		);
	}
}

function _patchExecuteAction(toolset: ComposioToolSetLike): void {
	const originalExecuteAction = toolset.executeAction.bind(toolset);

	toolset.executeAction = async (...args: unknown[]) => {
		const action = String(args[0] ?? "unknown");
		const params = args[1] as Record<string, unknown> | undefined;
		const entityId = String(args[2] ?? "");
		const paramCount = params ? Object.keys(params).length : 0;

		return tracer.startActiveSpan(
			"composio.executeAction",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "composio",
					"composio.action": action,
					"composio.entity_id": entityId,
					"composio.param_count": paramCount,
				},
			},
			async (span) => {
				try {
					const result = (await originalExecuteAction(...args)) as Record<
						string,
						unknown
					>;
					const successful = result.successful ?? result.success;
					if (typeof successful === "boolean") {
						span.setAttribute("composio.successful", successful);
					}
					const error = result.error;
					if (error) {
						span.setAttribute(
							"composio.error_message",
							String(error).slice(0, 256),
						);
					}
					span.setStatus({
						code: error ? SpanStatusCode.ERROR : SpanStatusCode.OK,
						message: error ? String(error).slice(0, 256) : "",
					});
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

function _patchGetTools(toolset: {
	getTools: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalGetTools = toolset.getTools.bind(toolset);

	toolset.getTools = async (...args: unknown[]) => {
		return tracer.startActiveSpan(
			"composio.getTools",
			{
				kind: SpanKind.CLIENT,
				attributes: { "gen_ai.provider.name": "composio" },
			},
			async (span) => {
				try {
					const result = await originalGetTools(...args);
					if (Array.isArray(result)) {
						span.setAttribute("composio.tools_count", result.length);
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
