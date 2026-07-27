/**
 * OpenAI Agents SDK instrumentation for Tracelane.
 *
 * Wraps the OpenAI Agents SDK Runner.run() class method to emit OTel spans
 * for every agent execution. Captures agent name, output length, and
 * handoff metadata. The Agents SDK is the direct route to OpenAI Frontier
 *
 * @example
 * ```ts
 * import { Agent, Runner } from "openai/agents";
 * import { instrumentOpenAIAgents } from "@tracelanedev/sdk/openai_agents";
 *
 * instrumentOpenAIAgents(Runner);
 * const result = await Runner.run(agent, "hello");
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-openai-agents", "0.1.0");

interface RunnerLike {
	run: (...args: unknown[]) => Promise<unknown>;
	runSync?: (...args: unknown[]) => unknown;
}

/**
 * Instrument the OpenAI Agents Runner class to emit OTel spans.
 *
 * @param runnerClass - The openai/agents Runner class (not an instance)
 */
export function instrumentOpenAIAgents(runnerClass: RunnerLike): void {
	_patchRun(runnerClass);
	if (runnerClass.runSync) {
		_patchRunSync(
			runnerClass as RunnerLike & { runSync: (...args: unknown[]) => unknown },
		);
	}
}

function _patchRun(runnerClass: RunnerLike): void {
	const originalRun = runnerClass.run.bind(runnerClass);

	runnerClass.run = async (...args: unknown[]) => {
		const agent = args[0] as Record<string, unknown> | undefined;
		const agentName = typeof agent?.name === "string" ? agent.name : "unknown";
		const input = args[1];

		return tracer.startActiveSpan(
			"openai_agents.runner.run",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "openai-agents",
					"ai.agent.name": agentName,
					"openai_agents.input_length":
						typeof input === "string" ? input.length : 0,
				},
			},
			async (span) => {
				try {
					const result = (await originalRun(...args)) as Record<
						string,
						unknown
					>;
					_recordRunResult(span, result);
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

function _patchRunSync(
	runnerClass: RunnerLike & { runSync: NonNullable<RunnerLike["runSync"]> },
): void {
	const originalRunSync = runnerClass.runSync.bind(runnerClass);

	runnerClass.runSync = (...args: unknown[]) => {
		const agent = args[0] as Record<string, unknown> | undefined;
		const agentName = typeof agent?.name === "string" ? agent.name : "unknown";
		const span = tracer.startSpan("openai_agents.runner.run_sync", {
			kind: SpanKind.CLIENT,
			attributes: {
				"gen_ai.provider.name": "openai-agents",
				"ai.agent.name": agentName,
			},
		});
		try {
			const result = originalRunSync(...args) as Record<string, unknown>;
			_recordRunResult(span, result);
			span.setStatus({ code: SpanStatusCode.OK });
			return result;
		} catch (e) {
			span.recordException(e as Error);
			span.setStatus({ code: SpanStatusCode.ERROR, message: String(e) });
			throw e;
		} finally {
			span.end();
		}
	};
}

function _recordRunResult(
	span: ReturnType<typeof tracer.startSpan>,
	result: Record<string, unknown>,
): void {
	const finalOutput = result.final_output ?? result.finalOutput;
	if (finalOutput !== undefined && finalOutput !== null) {
		span.setAttribute(
			"openai_agents.output_length",
			String(finalOutput).length,
		);
	}
	const messages = result.messages ?? result.new_messages;
	if (Array.isArray(messages)) {
		span.setAttribute("openai_agents.messages_count", messages.length);
	}
	const nextAgent = result.next_agent ?? result.nextAgent;
	if (nextAgent !== null && nextAgent !== undefined) {
		const nextName = (nextAgent as Record<string, unknown>).name;
		span.setAttribute("ai.agent.handoff_count", 1);
		if (typeof nextName === "string") {
			span.setAttribute("ai.agent.handoff_target", nextName);
		}
	}
}
