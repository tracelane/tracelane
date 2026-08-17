/**
 * Session correlation — proved on the wire, not at the function boundary.
 *
 * The end state this feature owes a user is: "the HTTP request my client sends
 * to the Tracelane gateway carries `x-conversation-id`, so `/sessions` groups
 * my turns." So every acceptance test here runs a REAL vendor client (`openai`
 * / `@anthropic-ai/sdk`, both pinned in the lockfile for this package) against a
 * loopback `node:http` server and asserts on the bytes that server received.
 * Asserting that a helper returned the right object would prove nothing — the
 * shipped read path was already built; only the wire was missing.
 *
 * Negative cases come first, per .claude/rules/testing.md.
 */

import { type IncomingHttpHeaders, type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import Anthropic from "@anthropic-ai/sdk";
import { trace } from "@opentelemetry/api";
import {
	BasicTracerProvider,
	InMemorySpanExporter,
	SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import OpenAI from "openai";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { instrumentAnthropic } from "./instrumentations/anthropic.js";
import { instrumentLiteLLM } from "./instrumentations/litellm.js";
import { instrumentOpenAI } from "./instrumentations/openai.js";
import { instrumentOpenRouter } from "./instrumentations/openrouter.js";
import {
	CONVERSATION_ID_ATTRIBUTE,
	CONVERSATION_ID_HEADER,
	MAX_SESSION_ID_LENGTH,
	getSession,
	normalizeSessionId,
	sessionHeaders,
	setSession,
	withSession,
} from "./session.js";

const exporter = new InMemorySpanExporter();

/** A loopback origin that records the headers of every request it answers. */
interface Recorder {
	baseURL: string;
	received: IncomingHttpHeaders[];
	close: () => Promise<void>;
}

const CHAT_RESPONSE = JSON.stringify({
	id: "chatcmpl-test",
	object: "chat.completion",
	model: "claude-sonnet-4-6",
	choices: [
		{
			index: 0,
			finish_reason: "stop",
			message: { role: "assistant", content: "ok" },
		},
	],
	usage: { prompt_tokens: 3, completion_tokens: 1 },
});

const MESSAGE_RESPONSE = JSON.stringify({
	id: "msg_test",
	type: "message",
	role: "assistant",
	model: "claude-sonnet-4-6",
	content: [{ type: "text", text: "ok" }],
	stop_reason: "end_turn",
	usage: { input_tokens: 3, output_tokens: 1 },
});

async function startRecorder(body: string): Promise<Recorder> {
	const received: IncomingHttpHeaders[] = [];
	const server: Server = createServer((req, res) => {
		received.push(req.headers);
		// Drain the request body so the socket closes cleanly.
		req.resume();
		req.on("end", () => {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(body);
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	return {
		baseURL: `http://127.0.0.1:${port}/v1`,
		received,
		close: () =>
			new Promise<void>((resolve, reject) =>
				server.close((err) => (err ? reject(err) : resolve())),
			),
	};
}

/** The single request the recorder answered, with a useful failure message. */
function onlyRequest(rec: Recorder): IncomingHttpHeaders {
	expect(rec.received).toHaveLength(1);
	const first = rec.received[0];
	if (!first) throw new Error("recorder answered no request");
	return first;
}

beforeAll(() => {
	trace.setGlobalTracerProvider(
		new BasicTracerProvider({
			spanProcessors: [new SimpleSpanProcessor(exporter)],
		}),
	);
});

beforeEach(() => exporter.reset());

// A leaked ambient session would silently taint every later test.
afterEach(() => setSession(undefined));

describe("session id validation — must reject before it reaches the wire", () => {
	it("rejects the empty and whitespace-only id", () => {
		expect(() => normalizeSessionId("")).toThrow(/must not be empty/);
		expect(() => normalizeSessionId("   ")).toThrow(/must not be empty/);
	});

	it("rejects an over-long id rather than truncating it", () => {
		const tooLong = "s".repeat(MAX_SESSION_ID_LENGTH + 1);
		expect(() => normalizeSessionId(tooLong)).toThrow(/at most 256 characters/);
		// A truncated id is a WRONG id — it would split one conversation in two.
		expect(() => normalizeSessionId(tooLong)).toThrow(/truncated/);
	});

	it("rejects CR/LF — header injection must be unrepresentable", () => {
		expect(() => normalizeSessionId("sess-1\r\nx-admin: true")).toThrow(
			/visible ASCII/,
		);
		expect(() => normalizeSessionId("sess\r1")).toThrow(/visible ASCII/);
		expect(() => normalizeSessionId("sess\t1")).toThrow(/visible ASCII/);
		// A trailing newline is a file-read artifact, so it is trimmed — but the
		// result must be clean, never smuggled through.
		expect(normalizeSessionId("sess-1\n")).toBe("sess-1");
		expect(normalizeSessionId("sess-1\n")).not.toMatch(/[\r\n]/);
	});

	it("rejects non-ASCII, which the gateway would drop silently", () => {
		expect(() => normalizeSessionId("séssion-1")).toThrow(/visible ASCII/);
		expect(() => normalizeSessionId("会話-1")).toThrow(/visible ASCII/);
		// The error must say WHY, so the developer does not just retry.
		expect(() => normalizeSessionId("séssion-1")).toThrow(/silently/);
	});

	it("accepts a realistic id, and one exactly at the cap", () => {
		expect(normalizeSessionId("  sess_2026-08-08/42  ")).toBe(
			"sess_2026-08-08/42",
		);
		const atCap = "s".repeat(MAX_SESSION_ID_LENGTH);
		expect(normalizeSessionId(atCap)).toBe(atCap);
	});

	it("throws at the developer's call site, not inside the request", () => {
		let ran = false;
		expect(() =>
			withSession("bad\nid", () => {
				ran = true;
			}),
		).toThrow(/visible ASCII/);
		expect(ran).toBe(false);
		expect(() => sessionHeaders("bad\nid")).toThrow(/visible ASCII/);
		expect(() => setSession("bad\nid")).toThrow(/visible ASCII/);
		// A rejected setSession must not have taken effect.
		expect(getSession()).toBeUndefined();
	});
});

describe("wire proof — an instrumented OpenAI client inside withSession", () => {
	it("sends x-conversation-id on the real HTTP request", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentOpenAI(client as never);

			await withSession("sess-observable-1", () =>
				client.chat.completions.create({
					model: "claude-sonnet-4-6",
					messages: [{ role: "user", content: "Hello" }],
				}),
			);

			expect(onlyRequest(rec)[CONVERSATION_ID_HEADER]).toBe(
				"sess-observable-1",
			);
		} finally {
			await rec.close();
		}
	});

	it("sends NO session header when no session is active", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentOpenAI(client as never);

			await client.chat.completions.create({
				model: "claude-sonnet-4-6",
				messages: [{ role: "user", content: "Hello" }],
			});

			const headers = onlyRequest(rec);
			expect(headers[CONVERSATION_ID_HEADER]).toBeUndefined();
			expect(headers["x-session-id"]).toBeUndefined();
		} finally {
			await rec.close();
		}
	});

	it("lets an explicit per-call header win over the ambient session", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentOpenAI(client as never);
			setSession("sess-ambient");

			await client.chat.completions.create(
				{ model: "claude-sonnet-4-6", messages: [] },
				{ headers: { "X-Conversation-Id": "sess-explicit" } },
			);

			// Case-insensitive: the ambient value must not be added alongside.
			expect(onlyRequest(rec)[CONVERSATION_ID_HEADER]).toBe("sess-explicit");
		} finally {
			await rec.close();
		}
	});

	it("preserves caller headers it did not set", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentOpenAI(client as never);

			await withSession("sess-merge", () =>
				client.chat.completions.create(
					{ model: "claude-sonnet-4-6", messages: [] },
					{ headers: { "x-agent-id": "agent-7" } },
				),
			);

			const headers = onlyRequest(rec);
			expect(headers[CONVERSATION_ID_HEADER]).toBe("sess-merge");
			expect(headers["x-agent-id"]).toBe("agent-7");
		} finally {
			await rec.close();
		}
	});

	it("keeps overlapping sessions apart (AsyncLocalStorage, not a global)", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentOpenAI(client as never);

			const call = (id: string) =>
				withSession(id, () =>
					client.chat.completions.create({
						model: "claude-sonnet-4-6",
						messages: [{ role: "user", content: id }],
					}),
				);

			await Promise.all([call("sess-alpha"), call("sess-beta")]);

			const ids = rec.received.map((h) => h[CONVERSATION_ID_HEADER]).sort();
			expect(ids).toEqual(["sess-alpha", "sess-beta"]);
		} finally {
			await rec.close();
		}
	});
});

// Every adapter that wraps an OpenAI-shaped `chat.completions.create` must
// attach the session — otherwise "the SDK sets it" is true for one import path
// and quietly false for the others.
describe.each([
	["instrumentOpenAI", instrumentOpenAI],
	["instrumentLiteLLM", instrumentLiteLLM],
	["instrumentOpenRouter", instrumentOpenRouter],
])("wire proof — %s", (_name, instrument) => {
	it("attaches the session, and nothing when there is none", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			(instrument as (c: unknown) => void)(client);

			await withSession("sess-adapter", () =>
				client.chat.completions.create({
					model: "claude-sonnet-4-6",
					messages: [],
				}),
			);
			await client.chat.completions.create({
				model: "claude-sonnet-4-6",
				messages: [],
			});

			expect(rec.received).toHaveLength(2);
			expect(rec.received[0]?.[CONVERSATION_ID_HEADER]).toBe("sess-adapter");
			expect(rec.received[1]?.[CONVERSATION_ID_HEADER]).toBeUndefined();
		} finally {
			await rec.close();
		}
	});
});

describe("wire proof — the no-instrumentation path", () => {
	it("sessionHeaders() puts a plain client into a session", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			// No instrument*() call at all — the quickstart's hosted path.
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});

			await client.chat.completions.create(
				{ model: "claude-sonnet-4-6", messages: [] },
				{ headers: sessionHeaders("sess-plain") },
			);

			expect(onlyRequest(rec)[CONVERSATION_ID_HEADER]).toBe("sess-plain");
		} finally {
			await rec.close();
		}
	});

	it("sessionHeaders() is empty and harmless when no session is active", async () => {
		expect(sessionHeaders()).toEqual({});
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			await client.chat.completions.create(
				{ model: "claude-sonnet-4-6", messages: [] },
				{ headers: sessionHeaders() },
			);
			expect(onlyRequest(rec)[CONVERSATION_ID_HEADER]).toBeUndefined();
		} finally {
			await rec.close();
		}
	});
});

describe("wire proof — an instrumented Anthropic client", () => {
	it("sends x-conversation-id on the real HTTP request", async () => {
		const rec = await startRecorder(MESSAGE_RESPONSE);
		try {
			const client = new Anthropic({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentAnthropic(client as never);

			await withSession("sess-anthropic-1", () =>
				client.messages.create({
					model: "claude-sonnet-4-6",
					max_tokens: 16,
					messages: [{ role: "user", content: "Hello" }],
				}),
			);

			expect(onlyRequest(rec)[CONVERSATION_ID_HEADER]).toBe("sess-anthropic-1");
		} finally {
			await rec.close();
		}
	});

	it("sends NO session header when no session is active", async () => {
		const rec = await startRecorder(MESSAGE_RESPONSE);
		try {
			const client = new Anthropic({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentAnthropic(client as never);

			await client.messages.create({
				model: "claude-sonnet-4-6",
				max_tokens: 16,
				messages: [{ role: "user", content: "Hello" }],
			});

			expect(onlyRequest(rec)[CONVERSATION_ID_HEADER]).toBeUndefined();
		} finally {
			await rec.close();
		}
	});
});

describe("OTLP path — the same id lands on the span", () => {
	it("stamps gen_ai.conversation.id when a session is active", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentOpenAI(client as never);

			await withSession("sess-otlp-1", () =>
				client.chat.completions.create({
					model: "claude-sonnet-4-6",
					messages: [],
				}),
			);

			const spans = exporter.getFinishedSpans();
			expect(spans).toHaveLength(1);
			expect(spans[0]?.attributes[CONVERSATION_ID_ATTRIBUTE]).toBe(
				"sess-otlp-1",
			);
		} finally {
			await rec.close();
		}
	});

	it("omits the attribute entirely when no session is active", async () => {
		const rec = await startRecorder(CHAT_RESPONSE);
		try {
			const client = new OpenAI({
				baseURL: rec.baseURL,
				apiKey: "tlane_unit-test-key-do-not-use",
			});
			instrumentOpenAI(client as never);

			await client.chat.completions.create({
				model: "claude-sonnet-4-6",
				messages: [],
			});

			const spans = exporter.getFinishedSpans();
			expect(spans).toHaveLength(1);
			// Absent, never an empty string — an empty id would group traces wrongly.
			expect(spans[0]?.attributes[CONVERSATION_ID_ATTRIBUTE]).toBeUndefined();
		} finally {
			await rec.close();
		}
	});
});

describe("scope precedence", () => {
	it("withSession beats setSession, and the ambient value survives the scope", () => {
		setSession("sess-ambient");
		expect(getSession()).toBe("sess-ambient");
		withSession("sess-scoped", () => {
			expect(getSession()).toBe("sess-scoped");
		});
		expect(getSession()).toBe("sess-ambient");
		setSession(undefined);
		expect(getSession()).toBeUndefined();
	});
});
