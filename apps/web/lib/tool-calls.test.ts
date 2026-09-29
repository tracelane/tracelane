/**
 * `OBS-50` — the extractor is the only logic behind the Tool calls section, so every
 * state in the spec's §4 is a case here: names only (content off), names + arguments
 * (content on), arguments without names (an SDK span), nothing, and garbage.
 */
import { describe, expect, it } from "vitest";
import { extractToolCalls, formatBytes } from "./tool-calls";

describe("extractToolCalls", () => {
	it("names only (content off): rows carry the name and byte size, no arguments", () => {
		const s = extractToolCalls(
			JSON.stringify({
				tracelane_response_tool_names: ["get_weather", "search"],
				tracelane_response_tool_arg_bytes: [16, 212],
				gen_ai_response_finish_reasons: ["tool_calls"],
			}),
		);
		expect(s.rows).toEqual([
			{
				name: "get_weather",
				argumentBytes: 16,
				arguments: undefined,
				captured: false,
			},
			{
				name: "search",
				argumentBytes: 212,
				arguments: undefined,
				captured: false,
			},
		]);
		expect(s.endedOnToolCall).toBe(true);
	});

	it("names + arguments (content on): the gateway's {id,name,input} shape attaches by index", () => {
		const s = extractToolCalls(
			JSON.stringify({
				tracelane_response_tool_names: ["get_weather"],
				tracelane_response_tool_arg_bytes: [16],
				gen_ai_output_messages: [
					{
						role: "assistant",
						content: "",
						tool_calls: [
							{ id: "call_1", name: "get_weather", input: { city: "Paris" } },
						],
					},
				],
				gen_ai_response_finish_reasons: ["tool_calls"],
			}),
		);
		expect(s.rows).toHaveLength(1);
		expect(s.rows[0]).toMatchObject({
			name: "get_weather",
			argumentBytes: 16,
			arguments: { city: "Paris" },
			captured: true,
		});
	});

	it("arguments without names (an SDK span): OpenAI wire and OTel parts shapes both read", () => {
		const s = extractToolCalls(
			JSON.stringify({
				"gen_ai.output.messages": [
					{
						role: "assistant",
						tool_calls: [
							{ id: "c", function: { name: "lookup", arguments: '{"id":7}' } },
						],
						parts: [
							{ type: "tool_call", name: "notify", arguments: { to: "ops" } },
						],
					},
				],
				"gen_ai.response.finish_reasons": ["stop"],
			}),
		);
		expect(s.rows.map((r) => r.name)).toEqual(["lookup", "notify"]);
		expect(s.rows[0]?.arguments).toBe('{"id":7}');
		expect(s.rows[1]?.captured).toBe(true);
		expect(s.endedOnToolCall).toBe(false);
	});

	it("no tool call: no rows (the inspector renders no section)", () => {
		const s = extractToolCalls(
			JSON.stringify({
				gen_ai_request_model: "claude-haiku-4-5",
				gen_ai_response_finish_reasons: ["stop"],
			}),
		);
		expect(s.rows).toEqual([]);
		expect(s.finishReasons).toEqual(["stop"]);
	});

	it("garbage never throws: malformed JSON, non-object, wrong-typed fields → no rows", () => {
		expect(extractToolCalls("{not json").rows).toEqual([]);
		expect(extractToolCalls("42").rows).toEqual([]);
		expect(
			extractToolCalls(
				JSON.stringify({
					tracelane_response_tool_names: "get_weather",
					tracelane_response_tool_arg_bytes: ["16"],
					gen_ai_output_messages: "nope",
				}),
			).rows,
		).toEqual([]);
	});
});

describe("formatBytes", () => {
	it("reads as KiB, MiB, or an em dash", () => {
		expect(formatBytes(undefined)).toBe("—");
		expect(formatBytes(212)).toBe("0.2 KiB");
		expect(formatBytes(4200)).toBe("4.1 KiB");
		expect(formatBytes(3 * 1024 * 1024)).toBe("3 MiB");
	});
});
