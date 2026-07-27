import { describe, expect, it } from "vitest";
import { inferSpanKind } from "./span-kind";

const J = (o: unknown) => JSON.stringify(o);

// Fixtures use the REAL attribute-key vocabulary emitted by the gateway/ingest
// (gen_ai.* / llm.token_count.* / tool_* / mcp_* / gen_ai.operation.name) — see
// crates/ingest/src/otlp_decode.rs + the predictive detectors. ≥2 real trace
// shapes, plus the edge cases that matter most for honesty.
describe("inferSpanKind — conservative span-kind inference", () => {
	it("real shape #1 — an LLM chat call (gen_ai.*) → llm", () => {
		expect(
			inferSpanKind(
				J({
					"gen_ai.system": "openai",
					"gen_ai.request.model": "gpt-4o",
					"gen_ai.operation.name": "chat",
					"gen_ai.usage.input_tokens": 120,
					"gen_ai.usage.output_tokens": 64,
				}),
			),
		).toBe("llm");
		expect(
			inferSpanKind(
				J({ "llm.token_count.prompt": 80, "llm.output_messages": "[…]" }),
			),
		).toBe("llm");
	});

	it("real shape #2 — a tool execution (tool_name + mcp) → tool", () => {
		expect(
			inferSpanKind(
				J({
					tool_name: "web_search",
					tool_result: "…",
					mcp_server_name: "web",
				}),
			),
		).toBe("tool");
	});

	it("an LLM span that REQUESTS tools stays llm, not tool", () => {
		expect(
			inferSpanKind(
				J({
					"gen_ai.request.model": "claude-opus",
					tool_calls: [{ name: "x" }],
					tools: ["x"],
				}),
			),
		).toBe("llm");
	});

	it("embeddings → retrieval", () => {
		expect(
			inferSpanKind(
				J({
					"gen_ai.operation.name": "embeddings",
					"gen_ai.request.model": "text-embedding-3-small",
				}),
			),
		).toBe("retrieval");
	});

	it("agent orchestration (agent name, no llm call) → agent", () => {
		expect(
			inferSpanKind(
				J({
					"gen_ai.agent.name": "researcher",
					"gen_ai.operation.name": "invoke_agent",
				}),
			),
		).toBe("agent");
	});

	it("ambiguous / no signal → unknown (never a confident wrong guess)", () => {
		expect(
			inferSpanKind(J({ "http.method": "POST", "http.route": "/run" })),
		).toBe("unknown");
		expect(inferSpanKind(J({}))).toBe("unknown");
		expect(inferSpanKind("not json")).toBe("unknown");
		// a generic name/service alone is NOT enough to claim a kind
		expect(inferSpanKind(J({ "service.name": "agent-runner" }))).toBe(
			"unknown",
		);
	});
});

// The ACTUAL stored form is underscore-flattened `gen_ai_*` (ADR-043 — ingest
// normalises dotted OTLP keys to underscore). Inference MUST work on it; when it
// only matched dotted keys, every real span fell through to "unknown" (gray),
// while the dotted fixtures above stayed green — a green-while-broken trap.
describe("inferSpanKind — underscore stored form (ADR-043)", () => {
	it("an LLM chat call (gen_ai_*) → llm", () => {
		expect(
			inferSpanKind(
				J({
					gen_ai_system: "openai",
					gen_ai_response_model: "gpt-4o",
					gen_ai_operation_name: "chat",
					gen_ai_usage_input_tokens: 120,
					gen_ai_usage_output_tokens: 64,
				}),
			),
		).toBe("llm");
	});

	it("an agent run (gen_ai_operation_name=invoke_agent, no model) → agent", () => {
		expect(
			inferSpanKind(
				J({
					gen_ai_agent_name: "researcher",
					gen_ai_operation_name: "invoke_agent",
				}),
			),
		).toBe("agent");
	});

	it("a tool execution (execute_tool + gen_ai.tool.name) → tool", () => {
		expect(
			inferSpanKind(
				J({
					gen_ai_operation_name: "execute_tool",
					"gen_ai.tool.name": "web_search",
				}),
			),
		).toBe("tool");
	});
});
