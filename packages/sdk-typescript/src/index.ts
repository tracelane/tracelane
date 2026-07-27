/**
 * Tracelane TypeScript SDK.
 *
 * Auto-instruments AI agent frameworks by wrapping their HTTP clients.
 * Spans are emitted via OTLP to the Tracelane gateway's OTLP receiver.
 *
 * @example
 * ```ts
 * import { init } from "@tracelanedev/sdk";
 *
 * // Call once at application startup
 * init({
 *   endpoint: "https://ingest.tracelane.dev",
 *   apiKey: process.env.TRACELANE_API_KEY!,
 * });
 * ```
 */

export { init, shutdown } from "./tracer.js";
export type { TracelaneConfig } from "./tracer.js";

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
export { instrumentVercelAI } from "./instrumentations/vercel_ai.js";
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
