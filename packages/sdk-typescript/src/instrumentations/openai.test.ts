/**
 * Span-emission tests for the OpenAI instrumentation.
 *
 * Negative case first per .claude/rules/testing.md: the span must NOT carry
 * the API key or the prompt content. Then the OTel-GenAI attribute assertions.
 *
 * A hand-rolled fake client stands in for `openai` — the adapter only touches
 * `client.chat.completions.create`. An in-memory exporter captures spans (no
 * network, no live ingest).
 */

import { trace } from "@opentelemetry/api";
import {
	BasicTracerProvider,
	InMemorySpanExporter,
	SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { instrumentOpenAI, instrumentOpenAIAsync } from "./openai.js";

const exporter = new InMemorySpanExporter();

const SECRET_KEY = "sk-do-not-leak-unit-test";
const SECRET_PROMPT = "highly-confidential-prompt-body-unit-test";

const fakeResponse = {
	model: "gpt-4o-mini-2024-07-18",
	usage: { prompt_tokens: 11, completion_tokens: 7 },
	choices: [{ finish_reason: "stop" }],
};

function clientReturning(impl: (...args: unknown[]) => Promise<unknown>) {
	return { chat: { completions: { create: impl } } };
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

describe("instrumentOpenAI", () => {
	it("emits a gen_ai span with model, tokens, finish reason", async () => {
		const client = clientReturning(async () => fakeResponse);
		instrumentOpenAI(client);

		await client.chat.completions.create({
			model: "gpt-4o-mini",
			messages: [{ role: "user", content: SECRET_PROMPT }],
			api_key: SECRET_KEY,
		});

		const s = onlySpan();
		expect(s.name).toBe("openai.chat.completions.create");
		expect(s.attributes["gen_ai.provider.name"]).toBe("openai");
		expect(s.attributes["gen_ai.request.model"]).toBe("gpt-4o-mini");
		expect(s.attributes["gen_ai.usage.input_tokens"]).toBe(11);
		expect(s.attributes["gen_ai.usage.output_tokens"]).toBe(7);
		expect(s.attributes["gen_ai.response.finish_reason"]).toBe("stop");
		expect(s.attributes["gen_ai.response.model"]).toBe(
			"gpt-4o-mini-2024-07-18",
		);
	});

	it("never leaks the API key or prompt content into the span", async () => {
		const client = clientReturning(async () => fakeResponse);
		instrumentOpenAI(client);
		await client.chat.completions.create({
			model: "gpt-4o-mini",
			messages: [{ role: "user", content: SECRET_PROMPT }],
			api_key: SECRET_KEY,
		});
		const blob = JSON.stringify(onlySpan().attributes);
		expect(blob).not.toContain(SECRET_KEY);
		expect(blob).not.toContain(SECRET_PROMPT);
	});

	it("records an error status when the call throws, and rethrows", async () => {
		const client = clientReturning(async () => {
			throw new Error("upstream 500");
		});
		instrumentOpenAI(client);

		await expect(
			client.chat.completions.create({ model: "gpt-4o-mini" }),
		).rejects.toThrow("upstream 500");

		// SpanStatusCode.ERROR === 2 — the failure is surfaced, not swallowed.
		expect(onlySpan().status.code).toBe(2);
	});

	it("instrumentOpenAIAsync is the same entry point", () => {
		expect(instrumentOpenAIAsync).toBe(instrumentOpenAI);
	});
});
