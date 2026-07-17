# Tracelane — public spec claims (eval fixture)

Public, CC0-style fixture for the pain-point and fault-tolerance evals. It
replaces the eval reads that previously pointed at private strategy docs, so the
public eval set passes at a clean export (where those docs are absent) **without**
leaking any pricing, margin, or competitor-positioning content. Every line below is a public, feature-level
claim. Roadmap items are marked as such.

## Gateway & providers

- 30+-provider Rust gateway with BYOK envelope encryption.
- Migration tooling: `tlane import-helicone` and `tlane import-litellm` import
  existing Helicone / LiteLLM trace history into Tracelane via OTLP.
- Cloudflare R2 is the batched cold-storage tier (1MB batches); ClickHouse is
  the hot tier.

## Ingest & wire format

- OTLP over the OTel GenAI semantic conventions is the wire format; the ingest
  path is OpenInference-compatible and supports full trace export.
- NATS JetStream is the durable consumer between the OTLP receiver and the
  ClickHouse writer; the schema is schema-evolution safe.
- R2 cold-tier writes are 1MB-batched to keep egress and request cost low; you
  can export your data at any time (no egress lock-in).

## Observability surface

- The Predictive alerts feed and the live trace stream to the dashboard over
  real-time SSE.
- The transcript-spine trace viewer (in-house, SVG/DOM) renders the span tree.

## Predictive guardrails (8 inline rails)

- Trajectory Guard is the trajectory-anomaly predictor; its ONNX model artifact
  is on the roadmap (fails open to the heuristic layer until deployed).
- The MCP argument-drift detector emits the `AFT-MCP-ARGDRIFT-001` failure code.
- The SLM judge (1B encoder, post-call) is on the roadmap; until it ships the
  output-policy rail runs regex-only.

## Storage tiering (roadmap)

- Tracelane Lite — a DuckDB single binary local mode — is on the roadmap for
  zero-dependency local development.

## Fault tolerance

- Circuit breakers per (provider, region) guard every upstream call; quality
  rails are fail-open-loud (the request proceeds, a fail_open verdict is
  recorded) while security rails are fail-closed.
- R2 writes batch and retry; an R2 outage degrades to local buffering rather
  than dropping data.

## Replay & time-travel

- Time-travel debugging: `tlane replay <traceId>` steps through a recorded
  trace. Counterfactual shadow-fork prediction and LangGraph-checkpoint
  branching are on the roadmap.
