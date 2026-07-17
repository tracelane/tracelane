import type { SpanKind } from "@tracelanedev/ui";

/**
 * Infer the span kind from a span's attributes JSON, CONSERVATIVELY.
 *
 * There is no authoritative `span_kind` field at ingest yet (tech debt — see
 * OpenInference span-kind column at ingest). Until then we infer — but a
 * misattributed kind is worse than less detail (and error attribution is
 * status-driven, independent of kind), so we assign a kind ONLY on a strong
 * attribute signal and return "unknown" otherwise. We never guess from a
 * generic span name.
 *
 * Precedence (strongest first):
 *   1. embeddings / vector            → retrieval
 *   2. an LLM call (gen_ai/llm keys)  → llm   (even if it lists tools — that's the
 *                                              LLM *requesting* tools, not a tool span)
 *   3. agent orchestration            → agent
 *   4. tool execution                 → tool
 *   5. anything else / unparseable    → unknown
 */
export function inferSpanKind(attributesJson: string): SpanKind {
	let attrs: Record<string, unknown>;
	try {
		const parsed: unknown = JSON.parse(attributesJson);
		attrs =
			parsed && typeof parsed === "object"
				? (parsed as Record<string, unknown>)
				: {};
	} catch {
		return "unknown";
	}

	const keys = Object.keys(attrs);
	// The STORED form is underscore-flattened (`gen_ai_*`, ADR-043; ingest
	// normalises dotted OTLP keys to underscore), so every probe must match BOTH
	// the dotted OTel form and its underscore equivalent — exactly as
	// `extractGenAi` does. Reading only dotted keys returned "unknown" for all
	// real spans (the stopgap was green-in-tests, gray-on-real-data). The
	const has = (p: string) => {
		const u = p.replaceAll(".", "_");
		return keys.some(
			(k) => k === p || k.startsWith(p) || k === u || k.startsWith(u),
		);
	};
	const op = String(
		attrs["gen_ai.operation.name"] ?? attrs.gen_ai_operation_name ?? "",
	).toLowerCase();

	if (
		op === "embeddings" ||
		has("embedding") ||
		has("retrieval") ||
		has("vector.")
	) {
		return "retrieval";
	}
	if (
		has("gen_ai.request.model") ||
		has("gen_ai.response.model") ||
		has("gen_ai.system") ||
		has("gen_ai.provider.name") ||
		has("gen_ai.usage.") ||
		has("llm.token_count.") ||
		has("llm.output_messages") ||
		has("gen_ai.output.messages") ||
		op === "chat" ||
		op === "text_completion" ||
		op === "generate_content"
	) {
		return "llm";
	}
	if (
		op === "invoke_agent" ||
		op === "create_agent" ||
		(has("gen_ai.agent.name") && !has("gen_ai.request.model"))
	) {
		return "agent";
	}
	if (
		op === "execute_tool" ||
		has("gen_ai.tool.name") ||
		has("tool_name") ||
		has("tool_result") ||
		has("tool_output") ||
		has("tool_use") ||
		has("mcp_tools") ||
		has("mcp_server_name") ||
		has("tool.schema_violation") ||
		has("tool.definition_drift")
	) {
		return "tool";
	}
	return "unknown";
}
