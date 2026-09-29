/**
 * tool-calls — pure extraction of per-tool-call detail from ONE span's attributes.
 *
 * `OBS-50` (specs/OBS-50-per-tool-call-detail-on-the-trace-page.md). Callers:
 * SpanInspector.tsx and the unit test. No DOM, no async, never throws — a span
 * with garbage attributes yields `[]`, and the inspector then renders no section
 * (never an empty one).
 *
 * Sources, joined by index:
 *  - `tracelane_response_tool_names`     — the CALLED tool names (ungated, RI-05 M19)
 *  - `tracelane_response_tool_arg_bytes` — argument byte sizes, index-aligned (ungated, OBS-50)
 *  - `gen_ai_output_messages`            — the assistant turn; `tool_calls[]` carries the
 *                                          ARGUMENTS only when the tenant's content capture
 *                                          is on (GWY-45 gate). Two shapes are accepted: the
 *                                          gateway's `{id, name, input}` and OpenAI's
 *                                          `{id, function:{name, arguments}}` (an SDK span
 *                                          replaying the wire form); OTel `parts[]` with
 *                                          `type: "tool_call"` too.
 *  - `gen_ai_response_finish_reasons`    — `["tool_calls"]` when the turn ENDED on the call
 */

export type ToolCallRow = {
	/** The function the MODEL asked for — not the tool the customer ran. */
	name: string;
	/** UTF-8 bytes of the raw arguments the model produced, before any truncation. */
	argumentBytes?: number;
	/** Parsed/raw arguments when content capture was on for the tenant; absent otherwise. */
	arguments?: unknown;
	/** `true` when `arguments` came from a captured message (content on). */
	captured: boolean;
};

export type ToolCallSummary = {
	rows: ToolCallRow[];
	/** `true` when the turn's finish reason was `tool_calls`. */
	endedOnToolCall: boolean;
	finishReasons: string[];
};

function asStringArray(v: unknown): string[] {
	return Array.isArray(v)
		? v.filter((x): x is string => typeof x === "string")
		: [];
}

function asNumberArray(v: unknown): number[] {
	return Array.isArray(v)
		? v.filter((x): x is number => typeof x === "number" && Number.isFinite(x))
		: [];
}

/** `{name, arguments}` pairs from an output-messages array, any accepted shape. */
function capturedCalls(
	messages: unknown,
): Array<{ name?: string; args: unknown }> {
	if (!Array.isArray(messages)) return [];
	const out: Array<{ name?: string; args: unknown }> = [];
	for (const m of messages) {
		if (!m || typeof m !== "object") continue;
		const msg = m as Record<string, unknown>;
		// gateway / OpenAI shapes: tool_calls[]
		if (Array.isArray(msg.tool_calls)) {
			for (const c of msg.tool_calls) {
				if (!c || typeof c !== "object") continue;
				const call = c as Record<string, unknown>;
				const fn = call.function as Record<string, unknown> | undefined;
				const name =
					typeof call.name === "string"
						? call.name
						: fn && typeof fn.name === "string"
							? fn.name
							: undefined;
				const args = "input" in call ? call.input : fn?.arguments;
				out.push({ name, args });
			}
		}
		// OTel GenAI parts[] shape (SDK spans)
		if (Array.isArray(msg.parts)) {
			for (const p of msg.parts) {
				if (!p || typeof p !== "object") continue;
				const part = p as Record<string, unknown>;
				if (part.type !== "tool_call") continue;
				out.push({
					name: typeof part.name === "string" ? part.name : undefined,
					args: part.arguments,
				});
			}
		}
	}
	return out;
}

/**
 * Extract the tool-call rows for one span. Empty when the span called no tool.
 *
 * @param attributesJson - `Span.attributes`, the JSON-encoded attribute map.
 */
export function extractToolCalls(attributesJson: string): ToolCallSummary {
	let attrs: Record<string, unknown>;
	try {
		const parsed: unknown = JSON.parse(attributesJson);
		if (!parsed || typeof parsed !== "object") return empty();
		attrs = parsed as Record<string, unknown>;
	} catch {
		return empty();
	}
	const names = asStringArray(attrs.tracelane_response_tool_names);
	const bytes = asNumberArray(attrs.tracelane_response_tool_arg_bytes);
	const captured = capturedCalls(
		attrs.gen_ai_output_messages ?? attrs["gen_ai.output.messages"],
	);
	const finishReasons = asStringArray(
		attrs.gen_ai_response_finish_reasons ??
			attrs["gen_ai.response.finish_reasons"],
	);

	const rows: ToolCallRow[] = [];
	if (names.length > 0) {
		// The names are the spine (ungated, always present when a tool was called);
		// sizes and captured arguments attach by index when they exist.
		names.forEach((name, i) => {
			const cap = captured[i];
			rows.push({
				name,
				argumentBytes: bytes[i],
				arguments: cap?.args,
				captured: cap !== undefined && cap.args !== undefined,
			});
		});
	} else {
		// An SDK span: arguments without the gateway's names row.
		for (const cap of captured) {
			if (cap.name === undefined && cap.args === undefined) continue;
			rows.push({
				name: cap.name ?? "(unnamed tool)",
				arguments: cap.args,
				captured: cap.args !== undefined,
			});
		}
	}
	return {
		rows,
		endedOnToolCall: finishReasons.includes("tool_calls"),
		finishReasons,
	};
}

function empty(): ToolCallSummary {
	return { rows: [], endedOnToolCall: false, finishReasons: [] };
}

export { fmtBytes as formatBytes } from "./metrics/format";
