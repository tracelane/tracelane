/**
 * Letta instrumentation for Tracelane.
 *
 * Wraps Letta (formerly MemGPT) client agent creation and message-sending
 * methods to emit OTel spans. Letta's tiered/archival memory model is a V2
 * foundation for memory performance and coherence analysis.
 *
 * @example
 * ```ts
 * import { LettaClient } from "@letta-ai/letta-client";
 * import { instrumentLetta } from "@tracelanedev/sdk/letta";
 *
 * const client = new LettaClient({ token: process.env.LETTA_API_KEY! });
 * instrumentLetta(client);
 * const agent = await client.agents.create({ name: "my-agent" });
 * ```
 */

import { SpanKind, SpanStatusCode, trace } from "@opentelemetry/api";

const tracer = trace.getTracer("@tracelanedev/sdk-letta", "0.1.0");

interface LettaClientLike {
	agents: {
		create: (...args: unknown[]) => Promise<unknown>;
		messages?: {
			create: (...args: unknown[]) => Promise<unknown>;
		};
	};
}

/**
 * Instrument a Letta client instance to emit OTel spans.
 *
 * @param client - A @letta-ai/letta-client LettaClient instance
 */
export function instrumentLetta(client: LettaClientLike): void {
	_patchAgentsCreate(client.agents);
	if (client.agents.messages?.create) {
		_patchMessagesCreate(
			client.agents.messages as {
				create: (...args: unknown[]) => Promise<unknown>;
			},
		);
	}
}

function _patchAgentsCreate(agents: LettaClientLike["agents"]): void {
	const originalCreate = agents.create.bind(agents);

	agents.create = async (...args: unknown[]) => {
		const opts = args[0] as Record<string, unknown> | undefined;
		const agentName = String(opts?.name ?? "unnamed");

		return tracer.startActiveSpan(
			"letta.agents.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "letta",
					"letta.operation": "create_agent",
					"letta.agent_name": agentName,
				},
			},
			async (span) => {
				try {
					const result = (await originalCreate(...args)) as Record<
						string,
						unknown
					>;
					const agentId = result.id;
					if (typeof agentId === "string") {
						span.setAttribute("letta.agent_id", agentId);
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

function _patchMessagesCreate(messages: {
	create: (...args: unknown[]) => Promise<unknown>;
}): void {
	const originalCreate = messages.create.bind(messages);

	messages.create = async (...args: unknown[]) => {
		const agentId = String(args[0] ?? "unknown");
		const opts = args[1] as Record<string, unknown> | undefined;
		const msgArr = opts?.messages as Array<Record<string, unknown>> | undefined;
		const role = String(opts?.role ?? msgArr?.[0]?.role ?? "user");

		return tracer.startActiveSpan(
			"letta.agents.messages.create",
			{
				kind: SpanKind.CLIENT,
				attributes: {
					"gen_ai.provider.name": "letta",
					"letta.operation": "send_message",
					"letta.agent_id": agentId,
					"letta.role": role,
				},
			},
			async (span) => {
				try {
					const result = (await originalCreate(...args)) as Record<
						string,
						unknown
					>;
					const msgs = result.messages;
					if (Array.isArray(msgs)) {
						span.setAttribute("letta.messages_count", msgs.length);
					}
					const usage = result.usage as Record<string, unknown> | undefined;
					if (usage?.total_tokens !== undefined) {
						span.setAttribute(
							"gen_ai.usage.total_tokens",
							Number(usage.total_tokens),
						);
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
