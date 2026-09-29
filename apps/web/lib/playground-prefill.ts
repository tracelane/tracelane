/**
 * `EVL-03` §2 — `prefillFromSpan`, the ONLY place a span's attributes are
 * mapped into a playground draft. Pure: takes a `Span` (the gateway's
 * `GET /v1/traces/{id}/spans` row shape) plus the trace id already known from
 * the URL (a `SpanRow` carries no `trace_id` column of its own —
 * `crates/gateway/src/trace_reads.rs`'s `SPANS_SQL` binds it as a WHERE
 * parameter, never selects it), and returns a draft plus a `missing[]` list
 * naming what could not be restored and why.
 *
 * THE PREFILL CONTRACT (spec §2 table, `crates/shared/src/span.rs`):
 *   - model/temperature/top_p/max_tokens/seed/tool_choice — never gated by
 *     content capture, and an absent field stays `undefined` (never a
 *     substituted default: `0` is a real value, span.rs:397-399).
 *   - system/messages — `gen_ai_system_instructions` / `gen_ai_input_messages`,
 *     present ONLY when content capture is on for the tenant. Absence is the
 *     NORMAL case on prod today (every real customer tenant).
 *   - tools — NEVER schema-recoverable. Only `tracelane_request_tool_names` is
 *     stored (independent of capture — R3's precedent), so a stub
 *     `{type:"function",function:{name,parameters:{}}}` is built per name and
 *     `missing` always names the gap.
 *   - a message shape this playground cannot parse (the canonical OTel v1.37
 *     `parts` shape an SDK/OTLP span can carry, which `CapturedInput` never
 *     produces) is `unrecognized_shape`, distinct from `capture_off` — the
 *     span HAS content, just not in an importable shape.
 */
import type { Span } from "@/components/trace-viewer/types";

const TRUNCATION_MARKER = "…[truncated]";
const RECOGNIZED_ROLES = new Set(["system", "user", "assistant", "tool"]);

export type PlaygroundMissingField = "messages" | "system" | "tools";
export type PlaygroundMissingReason =
	| "capture_off"
	| "unrecognized_shape"
	| "schema_not_recorded";

export interface PlaygroundMissingEntry {
	field: PlaygroundMissingField;
	reason: PlaygroundMissingReason;
}

export interface PlaygroundDraftMessage {
	role: "system" | "user" | "assistant" | "tool";
	content: string;
	truncated: boolean;
}

export interface PlaygroundDraftToolStub {
	type: "function";
	function: { name: string; parameters: Record<string, never> };
}

export interface PlaygroundDraft {
	sourceSpanId: string;
	sourceTraceId: string;
	model?: string;
	temperature?: number;
	top_p?: number;
	max_tokens?: number;
	seed?: number;
	tool_choice_mode?: string;
	tool_choice_function?: string;
	system?: string;
	systemTruncated: boolean;
	messages: PlaygroundDraftMessage[];
	/** Read-only "Original answer" column — only present when output was
	 * ALSO captured (OBS-51 path). Empty when not. */
	outputMessages: PlaygroundDraftMessage[];
	tools: PlaygroundDraftToolStub[];
}

export interface PrefillResult {
	draft: PlaygroundDraft;
	missing: PlaygroundMissingEntry[];
}

function isFiniteNumber(v: unknown): v is number {
	return typeof v === "number" && Number.isFinite(v);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A single content PART, `{type:"text", text}` in our own `ContentPart`
 * shape (`crates/shared/src/model.rs`). Non-text parts (image_url/tool_use/
 * tool_result) are out of scope (spec §6: no image/audio inputs) and are
 * silently skipped rather than failing the whole message. */
function textOfPart(part: unknown): string | null {
	if (!isPlainObject(part)) return null;
	return part.type === "text" && typeof part.text === "string"
		? part.text
		: null;
}

/** Extract plain text from a `Message.content` value — a string (the common
 * case; every current playground run sends one) or our OWN `ContentPart[]`
 * array. Anything else (no recognizable text) is `null`. */
function textFromContent(
	content: unknown,
): { text: string; truncated: boolean } | null {
	if (typeof content === "string") {
		return { text: content, truncated: content.endsWith(TRUNCATION_MARKER) };
	}
	if (Array.isArray(content)) {
		const texts = content
			.map(textOfPart)
			.filter((t): t is string => t !== null);
		if (texts.length === 0) return null;
		return {
			text: texts.join("\n\n"),
			truncated: texts.some((t) => t.endsWith(TRUNCATION_MARKER)),
		};
	}
	return null;
}

/** A message is in OUR shape iff it is an object carrying a `content` key —
 * the canonical OTel v1.37 `parts` shape (`{role, parts:[...]}`) has none, so
 * it is rejected here rather than silently mis-rendered. */
function isRecognizedMessage(m: unknown): m is Record<string, unknown> {
	return isPlainObject(m) && "content" in m;
}

function toDraftMessage(raw: Record<string, unknown>): PlaygroundDraftMessage {
	const role =
		typeof raw.role === "string" && RECOGNIZED_ROLES.has(raw.role)
			? (raw.role as PlaygroundDraftMessage["role"])
			: "user";
	const extracted = textFromContent(raw.content);
	return {
		role,
		content: extracted?.text ?? "",
		truncated: extracted?.truncated ?? false,
	};
}

/** `gen_ai_input_messages` / `gen_ai_output_messages`: recognized only when it
 * is an array where EVERY element carries our own `content` key. One foreign
 * element makes the whole array unrecognized — a partially-parsed message
 * list would silently drop turns a human wrote. */
function parseMessageArray(
	raw: unknown,
): { messages: PlaygroundDraftMessage[] } | { unrecognized: true } {
	if (!Array.isArray(raw) || !raw.every(isRecognizedMessage)) {
		return { unrecognized: true };
	}
	return { messages: raw.map(toDraftMessage) };
}

export function prefillFromSpan(span: Span, traceId: string): PrefillResult {
	let attrs: Record<string, unknown> = {};
	try {
		const parsed: unknown = JSON.parse(span.attributes);
		if (isPlainObject(parsed)) attrs = parsed;
	} catch {
		attrs = {};
	}

	const missing: PlaygroundMissingEntry[] = [];

	const draft: PlaygroundDraft = {
		sourceSpanId: span.span_id,
		sourceTraceId: traceId,
		model:
			typeof attrs.gen_ai_request_model === "string"
				? attrs.gen_ai_request_model
				: undefined,
		temperature: isFiniteNumber(attrs.gen_ai_request_temperature)
			? attrs.gen_ai_request_temperature
			: undefined,
		top_p: isFiniteNumber(attrs.gen_ai_request_top_p)
			? attrs.gen_ai_request_top_p
			: undefined,
		max_tokens: isFiniteNumber(attrs.gen_ai_request_max_tokens)
			? attrs.gen_ai_request_max_tokens
			: undefined,
		seed: isFiniteNumber(attrs.gen_ai_request_seed)
			? attrs.gen_ai_request_seed
			: undefined,
		tool_choice_mode:
			typeof attrs.tracelane_request_tool_choice_mode === "string"
				? attrs.tracelane_request_tool_choice_mode
				: undefined,
		tool_choice_function:
			typeof attrs.tracelane_request_tool_choice_function === "string"
				? attrs.tracelane_request_tool_choice_function
				: undefined,
		system: undefined,
		systemTruncated: false,
		messages: [],
		outputMessages: [],
		tools: [],
	};

	// System instructions — capture-ON only; a JSON string per `CapturedInput`.
	if (typeof attrs.gen_ai_system_instructions === "string") {
		draft.system = attrs.gen_ai_system_instructions;
		draft.systemTruncated = draft.system.endsWith(TRUNCATION_MARKER);
	}

	// Messages — the field this button exists for.
	if (attrs.gen_ai_input_messages === undefined) {
		missing.push({ field: "messages", reason: "capture_off" });
	} else {
		const parsed = parseMessageArray(attrs.gen_ai_input_messages);
		if ("unrecognized" in parsed) {
			missing.push({ field: "messages", reason: "unrecognized_shape" });
		} else {
			draft.messages = parsed.messages;
		}
	}

	// "Original answer" — read-only, only when output was ALSO captured
	// (OBS-51). No `missing[]` entry: an absent read-only column is not a gap
	// the user needs to fix, it is simply not shown (spec §4 state table).
	if (attrs.gen_ai_output_messages !== undefined) {
		const parsedOutput = parseMessageArray(attrs.gen_ai_output_messages);
		if (!("unrecognized" in parsedOutput)) {
			draft.outputMessages = parsedOutput.messages;
		}
	}

	// Tools — NEVER schema-recoverable, independent of content capture.
	if (
		Array.isArray(attrs.tracelane_request_tool_names) &&
		attrs.tracelane_request_tool_names.length > 0
	) {
		draft.tools = attrs.tracelane_request_tool_names
			.filter((n): n is string => typeof n === "string")
			.map((name) => ({
				type: "function" as const,
				function: { name, parameters: {} as Record<string, never> },
			}));
		if (draft.tools.length > 0) {
			missing.push({ field: "tools", reason: "schema_not_recorded" });
		}
	}

	return { draft, missing };
}
