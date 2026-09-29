/**
 * `EVL-03` §2 — `prefillFromSpan`, the ONLY place span attributes are mapped
 * into a playground draft. Fixtures mirror the spec's §2 table exactly:
 * `gen_ai_request_model` / `_temperature` / `_top_p` / `_max_tokens` / `_seed`
 * (span.rs:34,406,409,414,419), `tracelane_request_tool_choice_mode`/`_function`
 * (:424,427), `gen_ai_system_instructions` (:251, capture-ON only),
 * `gen_ai_input_messages` (:253, capture-ON only, a serialized `Vec<Message>`
 * — `{role, content}`, truncated with the `…[truncated]` marker), tool names
 * NOT gated by capture (`tracelane_request_tool_names`/`_count`, always
 * recorded when tools were offered — schemas never are).
 */
import { describe, expect, it } from "vitest";
import { prefillFromSpan } from "./playground-prefill";

const SPAN_ID = "9f3a0000-0000-0000-0000-000000000001";
const TRACE_ID = "1c2d0000-0000-0000-0000-000000000002";

function span(attributes: Record<string, unknown>) {
	return {
		span_id: SPAN_ID,
		parent_span_id: null,
		name: "gen_ai.chat",
		start_time: "2026-09-27T00:00:00",
		end_time: "2026-09-27T00:00:01",
		duration_us: 900_000,
		status_code: 0,
		status_message: "",
		attributes: JSON.stringify(attributes),
		aft_ids: [],
		intervention: 0,
	};
}

describe("prefillFromSpan — model + settings, always present regardless of capture", () => {
	it("restores model, temperature, top_p, max_tokens and seed when the caller sent them", () => {
		const { draft, missing } = prefillFromSpan(
			span({
				gen_ai_request_model: "claude-sonnet-4-6",
				gen_ai_request_temperature: 0.4,
				gen_ai_request_top_p: 0.9,
				gen_ai_request_max_tokens: 4096,
				gen_ai_request_seed: 42,
			}),
			TRACE_ID,
		);
		expect(draft.model).toBe("claude-sonnet-4-6");
		expect(draft.temperature).toBe(0.4);
		expect(draft.top_p).toBe(0.9);
		expect(draft.max_tokens).toBe(4096);
		expect(draft.seed).toBe(42);
		expect(draft.sourceSpanId).toBe(SPAN_ID);
		expect(draft.sourceTraceId).toBe(TRACE_ID);
		// Capture is off in this fixture — messages/system are absent, never
		// substituted with a default (span.rs:397-399's rule mirrored here).
		expect(missing).toContainEqual({
			field: "messages",
			reason: "capture_off",
		});
	});

	it("leaves an absent field undefined — never substitutes a default (0 is a real value, not absence)", () => {
		const { draft } = prefillFromSpan(
			span({ gen_ai_request_model: "gpt-4o", gen_ai_request_temperature: 0 }),
			TRACE_ID,
		);
		expect(draft.temperature).toBe(0);
		expect(draft.top_p).toBeUndefined();
		expect(draft.max_tokens).toBeUndefined();
	});
});

describe("prefillFromSpan — captured (content capture ON)", () => {
	it("restores system + messages verbatim, none marked truncated", () => {
		const { draft, missing } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				gen_ai_system_instructions: "You are a support agent for {{product}}.",
				gen_ai_input_messages: [
					{ role: "user", content: "My order {{order_id}} never arrived" },
				],
			}),
			TRACE_ID,
		);
		expect(draft.system).toBe("You are a support agent for {{product}}.");
		expect(draft.messages).toEqual([
			{
				role: "user",
				content: "My order {{order_id}} never arrived",
				truncated: false,
			},
		]);
		expect(missing.find((m) => m.field === "messages")).toBeUndefined();
		expect(missing.find((m) => m.field === "system")).toBeUndefined();
	});

	it("restores the read-only 'Original answer' column from gen_ai_output_messages", () => {
		const { draft } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				gen_ai_input_messages: [{ role: "user", content: "hi" }],
				gen_ai_output_messages: [{ role: "assistant", content: "hello there" }],
			}),
			TRACE_ID,
		);
		expect(draft.outputMessages).toEqual([
			{ role: "assistant", content: "hello there", truncated: false },
		]);
	});

	it("restores a multi-part text content array by joining its text parts", () => {
		const { draft } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				gen_ai_input_messages: [
					{
						role: "user",
						content: [
							{ type: "text", text: "part one" },
							{ type: "text", text: "part two" },
						],
					},
				],
			}),
			TRACE_ID,
		);
		expect(draft.messages[0]?.content).toBe("part one\n\npart two");
	});
});

describe("prefillFromSpan — uncaptured (content capture OFF, today's normal case)", () => {
	it("model + settings restored, messages/system absent — zero message text, both flagged capture_off", () => {
		const { draft, missing } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				gen_ai_request_max_tokens: 512,
			}),
			TRACE_ID,
		);
		expect(draft.model).toBe("gpt-4o");
		expect(draft.max_tokens).toBe(512);
		expect(draft.messages).toEqual([]);
		expect(draft.system).toBeUndefined();
		expect(missing).toContainEqual({
			field: "messages",
			reason: "capture_off",
		});
	});
});

describe("prefillFromSpan — truncated", () => {
	it("marks a message truncated when its content ends with the …[truncated] marker", () => {
		const { draft } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				gen_ai_input_messages: [
					{ role: "user", content: "a very long prompt…[truncated]" },
				],
			}),
			TRACE_ID,
		);
		expect(draft.messages[0]).toEqual({
			role: "user",
			content: "a very long prompt…[truncated]",
			truncated: true,
		});
	});

	it("marks the system field truncated the same way", () => {
		const { draft } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				gen_ai_system_instructions: "a very long system prompt…[truncated]",
			}),
			TRACE_ID,
		);
		expect(draft.systemTruncated).toBe(true);
	});
});

describe("prefillFromSpan — tool-names-only (tools are NEVER schema-recoverable)", () => {
	it("stubs one {type:function} definition per recorded name and flags schema_not_recorded", () => {
		const { draft, missing } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				tracelane_request_tool_names: ["get_weather", "get_time"],
				tracelane_request_tool_count: 2,
			}),
			TRACE_ID,
		);
		expect(draft.tools).toEqual([
			{ type: "function", function: { name: "get_weather", parameters: {} } },
			{ type: "function", function: { name: "get_time", parameters: {} } },
		]);
		expect(missing).toContainEqual({
			field: "tools",
			reason: "schema_not_recorded",
		});
	});

	it("tool names are recorded independent of content capture (no messages, tools still present)", () => {
		const { draft, missing } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				tracelane_request_tool_names: ["get_weather"],
				tracelane_request_tool_count: 1,
			}),
			TRACE_ID,
		);
		expect(draft.messages).toEqual([]);
		expect(draft.tools).toHaveLength(1);
		expect(missing).toContainEqual({
			field: "messages",
			reason: "capture_off",
		});
		expect(missing).toContainEqual({
			field: "tools",
			reason: "schema_not_recorded",
		});
	});

	it("no tools offered → no tools array entries and no tools missing[] entry", () => {
		const { draft, missing } = prefillFromSpan(
			span({ gen_ai_request_model: "gpt-4o" }),
			TRACE_ID,
		);
		expect(draft.tools).toEqual([]);
		expect(missing.find((m) => m.field === "tools")).toBeUndefined();
	});
});

describe("prefillFromSpan — the SDK/OTLP 'parts' shape this playground cannot import", () => {
	it("flags messages unrecognized_shape rather than mis-rendering the canonical OTel v1.37 parts shape", () => {
		const { draft, missing } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				// The canonical OTel GenAI v1.37 shape: {role, parts:[{type,content}]}
				// — no `content` key at all. `CapturedInput` never produces this
				// (spans.rs:200's doc comment); an SDK/OTLP span can.
				gen_ai_input_messages: [
					{ role: "user", parts: [{ type: "text", content: "hi" }] },
				],
			}),
			TRACE_ID,
		);
		expect(draft.messages).toEqual([]);
		expect(missing).toContainEqual({
			field: "messages",
			reason: "unrecognized_shape",
		});
		// Model/settings still restore — the button's behaviour is per-attribute,
		// not all-or-nothing.
		expect(draft.model).toBe("gpt-4o");
	});

	it("flags a non-array gen_ai_input_messages value the same way", () => {
		const { missing } = prefillFromSpan(
			span({
				gen_ai_request_model: "gpt-4o",
				gen_ai_input_messages: "a raw string, not an array",
			}),
			TRACE_ID,
		);
		expect(missing).toContainEqual({
			field: "messages",
			reason: "unrecognized_shape",
		});
	});
});

describe("prefillFromSpan — malformed attributes JSON", () => {
	it("does not throw on unparsable span.attributes — treats it as capture_off", () => {
		const malformed = span({ gen_ai_request_model: "gpt-4o" });
		malformed.attributes = "{not json";
		const { draft, missing } = prefillFromSpan(malformed, TRACE_ID);
		expect(draft.model).toBeUndefined();
		expect(missing).toContainEqual({
			field: "messages",
			reason: "capture_off",
		});
	});
});
