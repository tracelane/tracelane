/**
 * Streaming-guard rollout tests for the OpenAI-compatible adapters
 * (litellm, openrouter, cursor). Same contract as the openai/anthropic
 * tests: a `stream: true` call passes the stream object through untouched,
 * marks the span `tracelane.streaming`, and NEVER records token counts.
 */

import { trace } from "@opentelemetry/api";
import {
	BasicTracerProvider,
	InMemorySpanExporter,
	SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { instrumentCursor } from "./cursor.js";
import { instrumentLiteLLM } from "./litellm.js";
import { instrumentOpenRouter } from "./openrouter.js";

const exporter = new InMemorySpanExporter();

beforeAll(() => {
	const provider = new BasicTracerProvider({
		spanProcessors: [new SimpleSpanProcessor(exporter)],
	});
	trace.setGlobalTracerProvider(provider);
});

beforeEach(() => exporter.reset());

const streamLike = {
	[Symbol.asyncIterator]() {
		return { next: async () => ({ done: true as const, value: undefined }) };
	},
};

type ChatClient = {
	chat: { completions: { create: (...args: unknown[]) => Promise<unknown> } };
};

function onlySpan() {
	const spans = exporter.getFinishedSpans();
	expect(spans).toHaveLength(1);
	const s = spans[0];
	if (!s) throw new Error("expected exactly one finished span");
	return s;
}

async function assertGuarded(
	instrument: (client: ChatClient) => void,
): Promise<void> {
	const client: ChatClient = {
		chat: { completions: { create: async () => streamLike } },
	};
	instrument(client);
	const spy = vi
		.spyOn(process, "emitWarning")
		.mockImplementation((() => {}) as typeof process.emitWarning);
	const out = await client.chat.completions.create({
		model: "m",
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
}

describe("streaming guard — OpenAI-compatible adapters", () => {
	it("litellm marks streamed calls, never fakes tokens", async () => {
		await assertGuarded(instrumentLiteLLM);
	});

	it("openrouter marks streamed calls, never fakes tokens", async () => {
		await assertGuarded(instrumentOpenRouter);
	});

	it("cursor (chat.completions path) marks streamed calls", async () => {
		await assertGuarded(instrumentCursor);
	});

	it("cursor (complete() path) marks streamed calls", async () => {
		const client = { complete: async (..._args: unknown[]) => streamLike };
		instrumentCursor(client);
		const spy = vi
			.spyOn(process, "emitWarning")
			.mockImplementation((() => {}) as typeof process.emitWarning);
		const out = await client.complete({ model: "m", stream: true });
		spy.mockRestore();

		expect(out).toBe(streamLike);
		const s = onlySpan();
		expect(s.attributes["tracelane.streaming"]).toBe(true);
		expect(s.attributes["gen_ai.usage.input_tokens"]).toBeUndefined();
	});
});
