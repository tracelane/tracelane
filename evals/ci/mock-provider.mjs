#!/usr/bin/env node
/**
 * Mock upstream-provider server for the L2 live eval gate.
 *
 * The live-eval CI stack runs a REAL gateway → NATS → ingest → ClickHouse, but
 * the one thing that must NOT be real is the upstream LLM provider (no network,
 * no keys, deterministic). The gateway is pointed here via `OPENAI_BASE_URL`
 * (and friends), so this server stands in for OpenAI/Anthropic and returns a
 * canned streaming completion. ONLY the provider is faked; everything the
 * gateway does with the response (span build → publish → ingest → CH) is real.
 *
 * The OpenAI SSE body mirrors the known-parseable fixture in
 * crates/gateway/src/providers/smoke_tests.rs (OPENAI_SSE_BODY): a content
 * chunk, then a usage chunk (stream_options.include_usage=true), then [DONE].
 *
 * Usage: MOCK_PROVIDER_PORT=7070 node evals/ci/mock-provider.mjs
 * Health: GET /__health → 200 "ok"
 */
import http from "node:http";

const PORT = Number(process.env["MOCK_PROVIDER_PORT"] ?? 7070);
const MODEL = process.env["MOCK_PROVIDER_MODEL"] ?? "gpt-4o-mini";

// OpenAI-style streaming SSE. Matches the gateway's parser (parse_openai_sse):
// a delta chunk with content, a final chunk carrying usage, then [DONE].
const openAiSse = (model) =>
 [
 `data: {"id":"mock-1","object":"chat.completion.chunk","model":"${model}","choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":null}]}`,
 `data: {"id":"mock-1","object":"chat.completion.chunk","model":"${model}","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`,
 "data: [DONE]",
 "",
 "",
 ].join("\n\n");

const server = http.createServer((req, res) => {
 const url = req.url ?? "/";

 if (req.method === "GET" && url.startsWith("/__health")) {
 res.writeHead(200, { "content-type": "text/plain" });
 res.end("ok");
 return;
 }

 // Drain the request body (we don't need it, but must consume it).
 req.on("data", () => {});
 req.on("end", () => {
 if (req.method !== "POST") {
 res.writeHead(405, { "content-type": "text/plain" });
 res.end("method not allowed");
 return;
 }
 // Two scenarios, split by provider endpoint:
 // - OpenAI `/v1/chat/completions` → 200 + valid SSE (the happy-path loop;
 // GC-TRACE-LOOP).
 // - Anthropic `/v1/messages` → 401 (a REJECTED key) so the live FT eval can
 // prove the gateway answers `provider_key_rejected`, not an opaque
 // 502. The body echoes a fake key to also exercise the redaction path —
 // it must never reach the client.
 if (url.includes("/v1/messages")) {
 res.writeHead(401, { "content-type": "application/json" });
 res.end(
 '{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key sk-ant-leaked-secret"}}',
 );
 return;
 }
 res.writeHead(200, {
 "content-type": "text/event-stream",
 "cache-control": "no-cache",
 });
 res.end(openAiSse(MODEL));
 });
});

server.listen(PORT, "127.0.0.1", () => {
 // eslint-disable-next-line no-console
 process.stdout.write(`mock-provider listening on http://127.0.0.1:${PORT} (model=${MODEL})\n`);
});

for (const sig of ["SIGINT", "SIGTERM"]) {
 process.on(sig, () => server.close(() => process.exit(0)));
}
