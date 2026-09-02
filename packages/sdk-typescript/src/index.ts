/**
 * Tracelane TypeScript SDK.
 *
 * Auto-instruments AI agent frameworks by wrapping their HTTP clients.
 * Spans are emitted via OTLP/HTTP to the endpoint you configure. This SDK uses
 * the OTLP **JSON** exporter; Tracelane accepts JSON and protobuf alike.
 *
 * On Tracelane Cloud that endpoint is the gateway itself —
 * `https://gateway.tracelane.dev` — with a `tlane_…` key carrying the `ingest`
 * scope. Self-hosting, it is the ingest receiver you run, or any OTLP collector.
 *
 * The gateway's chat path records ONE span per model call on its own, with no
 * SDK. This SDK is what records the shape AROUND those calls — the planner step,
 * each tool call, the retry — as a nested trace.
 *
 * @example
 * ```ts
 * import { init } from "@tracelanedev/sdk";
 *
 * // Call once at application startup
 * init({
 *   endpoint: "https://gateway.tracelane.dev", // or your own receiver
 *   apiKey: process.env.TRACELANE_API_KEY!,
 * });
 * ```
 */

export { init, shutdown } from "./tracer.js";
export type { TracelaneConfig } from "./tracer.js";

// Session (conversation) correlation — what /sessions groups traces by.
export {
	CONVERSATION_ID_ATTRIBUTE,
	CONVERSATION_ID_HEADER,
	getSession,
	MAX_SESSION_ID_LENGTH,
	SESSION_ID_HEADER,
	sessionHeaders,
	setSession,
	withSession,
} from "./session.js";

// Individual instrument* exports for explicit single-library usage
export { instrumentAnthropic } from "./instrumentations/anthropic.js";
export {
	instrumentOpenAI,
	instrumentOpenAIAsync,
} from "./instrumentations/openai.js";
export { instrumentLiteLLM } from "./instrumentations/litellm.js";
export { instrumentOpenRouter } from "./instrumentations/openrouter.js";
export { instrumentLangGraph } from "./instrumentations/langgraph.js";
export { instrumentOpenAIAgents } from "./instrumentations/openai_agents.js";
// B-313: `tracelaneTelemetry` is the working integration — the AI SDK is not
// OTel-native, so it needs `registerTelemetry()`, not a module patch.
// `instrumentVercelAI` is kept as a throwing stub that names the replacement,
// because silently dropping an export is worse than a loud, actionable error.
export {
	tracelaneTelemetry,
	instrumentVercelAI,
} from "./instrumentations/vercel_ai.js";
export { instrumentMCP } from "./instrumentations/mcp.js";
export { instrumentClaudeCode } from "./instrumentations/claude_code.js";
export { instrumentCursor } from "./instrumentations/cursor.js";
export { instrumentPinecone } from "./instrumentations/pinecone.js";
export { instrumentQdrant } from "./instrumentations/qdrant.js";
export { instrumentComposio } from "./instrumentations/composio.js";
export { instrumentBrowserbase } from "./instrumentations/browserbase.js";
export { instrumentE2B } from "./instrumentations/e2b.js";
export { instrumentMem0 } from "./instrumentations/mem0.js";
export { instrumentLetta } from "./instrumentations/letta.js";
export { instrumentFirecrawl } from "./instrumentations/firecrawl.js";

// Zero-config auto-instrumentation
export { autoInstrument } from "./auto_instrument.js";
