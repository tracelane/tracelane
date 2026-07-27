/**
 * Span-emission tests for the Anthropic instrumentation.
 *
 * Negative case first per .claude/rules/testing.md: the span must NOT carry
 * the API key or the prompt content. Then the OTel-GenAI attribute
 * assertions, then the streaming pass-through guard (streamed calls must be
 * marked, never recorded as silent token-less spans).
 */

import { trace } from "@opentelemetry/api";
import {
	BasicTracerProvider,
	InMemorySpanExporter,
	SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { instrumentAnthropic } from "./anthropic.js";

const exporter = new InMemorySpanExporter();

const SECRET_KEY = "sk-ant-do-not-leak-unit-test";
const SECRET_PROMPT = "highly-confidential-prompt-body-unit-test";

const fakeResponse = {
	model: "claude-sonnet-4-6",
	usage: {
		input_tokens: 13,
		output_tokens: 5,
		cache_read_input_tokens: 2,
	},
};

function clientReturning(impl: (...args: unknown[]) => Promise<unknown>) {
	return { messages: { create: impl } };
}

function onlySpan() {
	const spans = exporter.getFinishedSpans();
	expect(spans).toHaveLength(1);
	const s = spans[0];
	if (!s) throw new Error("expected exactly one finished span");
	return s;
}

beforeAll(() => {
	const provider = new BasicTracerProvider({
		spanProcessors: [new SimpleSpanProcessor(exporter)],
	});
	trace.setGlobalTracerProvider(provider);
});

beforeEach(() => exporter.reset());

describe("instrumentAnthropic", () => {
	it("emits a gen_ai span with tokens and never leaks key or prompt", async () => {
		const client = clientReturning(async () => fakeResponse);
		instrumentAnthropic(client);

		await client.messages.create({
			model: "claude-sonnet-4-6",
			messages: [{ role: "user", content: SECRET_PROMPT }],
			api_key: SECRET_KEY,
		});

		const s = onlySpan();
		expect(s.name).toBe("anthropic.messages.create");
		expect(s.attributes["gen_ai.provider.name"]).toBe("anthropic");
		expect(s.attributes["gen_ai.usage.input_tokens"]).toBe(13);
		expect(s.attributes["gen_ai.usage.output_tokens"]).toBe(5);
		expect(s.attributes["gen_ai.usage.cache_read.input_tokens"]).toBe(2);
		const blob = JSON.stringify(s.attributes);
		expect(blob).not.toContain(SECRET_KEY);
		expect(blob).not.toContain(SECRET_PROMPT);
	});

	it("marks streamed calls and never fakes token counts", async () => {
		const streamLike = {
			[Symbol.asyncIterator]() {
				return {
					next: async () => ({ done: true as const, value: undefined }),
				};
			},
		};
		const client = clientReturning(async () => streamLike);
		instrumentAnthropic(client);

		const spy = vi
			.spyOn(process, "emitWarning")
			.mockImplementation((() => {}) as typeof process.emitWarning);
		const out = await client.messages.create({
			model: "claude-sonnet-4-6",
			stream: true,
		});
		spy.mockRestore();

		// The stream object passes through untouched.
		expect(out).toBe(streamLike);
		const s = onlySpan();
		expect(s.attributes["tracelane.streaming"]).toBe(true);
		// Usage attributes must be ABSENT — never a fake zero.
		expect(s.attributes["gen_ai.usage.input_tokens"]).toBeUndefined();
		expect(s.attributes["gen_ai.usage.output_tokens"]).toBeUndefined();
	});
});
