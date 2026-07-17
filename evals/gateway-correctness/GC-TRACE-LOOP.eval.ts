import { afterAll, beforeAll, describe, it } from "vitest";
import { expect, isLiveGatewayConfigured } from "../src/harness.js";
import { type LiveGatewayContext, spawnLiveGateway } from "../src/live-harness.js";

/**
 * GC-TRACE-LOOP (live) — the canonical core-trace-loop merge gate (L2).
 *
 * span-drop on day one. It exercises the WHOLE loop against a real ephemeral
 * stack (gateway → NATS → ingest → ClickHouse → gateway read), with ONLY the
 * upstream provider faked (a wiremock the gateway is pointed at via
 * `OPENAI_BASE_URL`). The internal data path is real on purpose: that is the
 * half that broke silently.
 *
 * It guards BOTH halves in one test:
 *   1. WRITE — a real `/v1/chat/completions` lands a span row in ClickHouse
 *   2. READ  — that trace is queryable THROUGH the gateway's tenant-resolved
 *      `/v1/traces` read path. This is the half that was independently broken
 *
 * Auth/secrets: the CI stack runs a DEBUG gateway with `WORKOS_CLIENT_ID`
 * unset, so any non-`tlane_` Bearer token resolves the fixed dev-stub tenant
 * (`DEV_TENANT`, crates/gateway/src/auth/mod.rs::DEV_TENANT_UUID). The provider
 * key falls back to `OPENAI_API_KEY` (env) and the upstream is the wiremock —
 * no prod secrets, no gateway code change.
 *
 * Skips (never fabricates a pass) unless a live gateway is configured
 * (`TRACELANE_EVAL_LIVE_GATEWAY_URL` / `TRACELANE_EVAL_SPAWN_GATEWAY=1`). In CI
 * the `live-eval-gate` job stands up the stack and sets the URL; on a plain
 * `pnpm eval:run` (mock CI) this stays skipped, by design.
 */

/** The fixed dev-stub tenant the debug gateway resolves (auth/mod.rs:DEV_TENANT_UUID). */
const DEV_TENANT = "00000000-0000-0000-0000-000000000001";

/** Direct ClickHouse HTTP endpoint for the WRITE-half assertion (dev: default user, no password). */
const CH_URL = process.env["CLICKHOUSE_URL"] ?? "http://localhost:8123";

/** Any non-`tlane_` Bearer token → dev-stub claims → DEV_TENANT, for both write and read. */
const AUTH = "Bearer eval-dev-token";

/** OpenAI-routed model so the request uses `OPENAI_BASE_URL` (the wiremock). */
const MODEL = "gpt-4o-mini";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Count spans in ClickHouse for a tenant. Returns 0 on any error (treated as not-yet-present). */
async function clickhouseSpanCount(tenant: string): Promise<number> {
  const query = `SELECT count() FROM tracelane.spans WHERE tenant_id = '${tenant}'`;
  try {
    const res = await fetch(`${CH_URL.replace(/\/$/, "")}/?query=${encodeURIComponent(query)}`);
    if (!res.ok) return 0;
    const text = (await res.text()).trim();
    const n = Number.parseInt(text, 10);
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

/** The persisted span ROW shape (the columns we assert on). */
interface SpanRowData {
  tenant_id: string;
  trace_id: string;
  span_id: string;
  name: string;
  status_code: number;
  attributes: string;
}

/**
 * Fetch the most-recent persisted span ROWS for a tenant — the row-level proof
 * the CORRECT tenant_id, rather than relying on a count delta or a JetStream
 * sequence advance (which can advance while the row silently never persists).
 * Returns [] on any error or no rows.
 */
async function clickhouseRowData(tenant: string, limit = 5): Promise<SpanRowData[]> {
  const query =
    `SELECT tenant_id, trace_id, span_id, name, status_code, attributes ` +
    `FROM tracelane.spans WHERE tenant_id = '${tenant}' ` +
    `ORDER BY start_time DESC LIMIT ${limit} FORMAT JSONEachRow`;
  try {
    const res = await fetch(`${CH_URL.replace(/\/$/, "")}/?query=${encodeURIComponent(query)}`);
    if (!res.ok) return [];
    const text = (await res.text()).trim();
    if (!text) return [];
    return text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as SpanRowData);
  } catch {
    return [];
  }
}

/**
 * Poll until a queryable span row appears for `tenant`, then assert the
 * row-level proof: the row carries the correct `tenant_id`, the span carrying
 * `MODEL` exists with intact structure (non-empty trace/span ids, valid
 * attributes JSON), and the span is NOT visible under a different tenant id
 */
async function assertSpanRowForTenant(tenant: string): Promise<void> {
  let rows: SpanRowData[] = [];
  for (let i = 0; i < 20; i++) {
    rows = await clickhouseRowData(tenant);
    if (rows.length > 0) break;
    await sleep(500);
  }
  expect(rows.length, "no span row queryable in ClickHouse for the tenant").toBeGreaterThan(0);

  // Every persisted row must carry the resolved tenant_id — any org_id→tenant
  // seam bug writes a different/empty value and trips here.
  expect(rows.every((r) => r.tenant_id === tenant)).toBe(true);

  // The span carrying THIS request's model must exist with intact structure —
  // proving the emitted LLM span survived the full write path, not a stale or
  // empty row. (The before/after count delta already proved the row is new.)
  const llm = rows.find((r) => r.attributes.includes(MODEL));
  expect(llm, "no persisted span row carries the request model").toBeDefined();
  const row = llm as SpanRowData;
  expect(row.trace_id.length).toBeGreaterThan(0);
  expect(row.span_id.length).toBeGreaterThan(0);
  // Attributes survived serialization as valid JSON (not a corrupt/empty blob).
  let parsedAttrs: unknown;
  try {
    parsedAttrs = JSON.parse(row.attributes);
  } catch {
    parsedAttrs = undefined;
  }
  expect(parsedAttrs, "persisted span attributes are not valid JSON").toBeDefined();

  // Cross-tenant negative: the span is bound to `tenant`, never globally
  // visible. A query for a DIFFERENT tenant id must return zero rows.
  const otherTenant = "00000000-0000-0000-0000-0000000000ff";
  expect(otherTenant).not.toBe(tenant);
  expect(await clickhouseRowData(otherTenant)).toHaveLength(0);
}

interface TraceRow {
  trace_id: string;
  model: string;
  span_count: number;
}

/** Fetch the tenant-resolved trace list THROUGH the gateway read path. */
async function gatewayTraces(gatewayUrl: string): Promise<TraceRow[]> {
  try {
    const res = await fetch(`${gatewayUrl.replace(/\/$/, "")}/v1/traces`, {
      headers: { authorization: AUTH },
    });
    if (!res.ok) return [];
    const body = (await res.json()) as { traces?: TraceRow[] };
    return Array.isArray(body.traces) ? body.traces : [];
  } catch {
    return [];
  }
}

let live: LiveGatewayContext;

beforeAll(async () => {
  // The gateway serves `/health` (NOT the harness default `/healthz`). Probe the
  // right path so a healthy gateway is detected as live — otherwise the probe
  // 404s, `live.skip` becomes true, and the test would silently skip, defeating
  // the entire point of the gate.
  live = await spawnLiveGateway({ healthPath: "/health" });
});

afterAll(async () => {
  if (live) await live.stop();
});

describe("GC-TRACE-LOOP (live): real chat request → ClickHouse → gateway /v1/traces", () => {
  it.skipIf(!isLiveGatewayConfigured())(
    "a real /v1/chat/completions span is written to ClickHouse AND is queryable through the gateway /v1/traces read",
    async () => {
      // We only reach here when isLiveGatewayConfigured() is true (the outer
      // skipIf handles mock-mode). So a gateway that is NOT reachable here is a
      // REAL gate failure — never a silent skip. A green-but-skipped core loop is
      expect(live.skip, `live gateway unreachable: ${live.skipReason ?? "unknown"}`).toBe(false);

      const before = await clickhouseSpanCount(DEV_TENANT);

      // 1. Drive a REAL chat request. The wiremock upstream returns a canned
      //    completion; the gateway builds + publishes the span on the real path.
      const chat = await fetch(`${live.url.replace(/\/$/, "")}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: AUTH },
        body: JSON.stringify({
          model: MODEL,
          messages: [{ role: "user", content: "L2 live trace-loop probe" }],
          max_tokens: 16,
        }),
      });
      expect(chat.status).toBe(200);

      // 2. WRITE half — the span must reach ClickHouse (ingest is async-batched,
      let after = before;
      for (let i = 0; i < 40; i++) {
        after = await clickhouseSpanCount(DEV_TENANT);
        if (after > before) break;
        await sleep(500);
      }
      expect(after).toBeGreaterThan(before);

      //     this asserts the ACTUAL row is queryable with the CORRECT tenant_id and
      //     intact span structure, the proof a JetStream seq advance can never give.
      await assertSpanRowForTenant(DEV_TENANT);

      // 3. READ half — the trace must be queryable THROUGH the gateway's
      let traces: TraceRow[] = [];
      for (let i = 0; i < 20; i++) {
        traces = await gatewayTraces(live.url);
        if (traces.length > 0) break;
        await sleep(500);
      }
      expect(traces.length > 0).toBe(true);

      // The rendered trace must carry the gen_ai model — proving the span's
      // attributes survived the full write→read round-trip (not an empty row).
      const sawModel = traces.some((t) => typeof t.model === "string" && t.model.includes(MODEL));
      expect(sawModel).toBe(true);
    },
    60_000,
  );

  it.skipIf(!isLiveGatewayConfigured())(
    "a STREAMING (stream:true) chat span is written to ClickHouse — #81 streaming-path span-drop",
    async () => {
      // Reached only when a live gateway is configured (the outer skipIf handles
      // mock-mode, matching the buffered test). Unreachable here = a REAL gate
      // failure, never a silent skip.
      expect(live.skip, `live gateway unreachable: ${live.skipReason ?? "unknown"}`).toBe(
        false,
      );

      const before = await clickhouseSpanCount(DEV_TENANT);

      // stream:true drives the SSE path (provider_stream_to_sse). The span is
      // published AFTER the stream loop terminates; #81 dropped it on the
      // streaming path (only the Done happy-path published), so a blocked or
      // aborted stream lost its span. Draining the body runs the loop to the
      // end so the post-loop publish fires.
      const chat = await fetch(`${live.url.replace(/\/$/, "")}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: AUTH },
        body: JSON.stringify({
          model: MODEL,
          messages: [{ role: "user", content: "L2 live streaming trace-loop probe" }],
          max_tokens: 16,
          stream: true,
        }),
      });
      expect(chat.status).toBe(200);
      const sse = await chat.text();
      expect(sse).toContain("[DONE]");

      let after = before;
      for (let i = 0; i < 40; i++) {
        after = await clickhouseSpanCount(DEV_TENANT);
        if (after > before) break;
        await sleep(500);
      }
      expect(after).toBeGreaterThan(before);

      // must land as a queryable ClickHouse row with the correct tenant_id — the
      // streaming path is exactly where #81 dropped the span post-loop.
      await assertSpanRowForTenant(DEV_TENANT);

      let traces: TraceRow[] = [];
      for (let i = 0; i < 20; i++) {
        traces = await gatewayTraces(live.url);
        if (traces.length > 0) break;
        await sleep(500);
      }
      const sawModel = traces.some(
        (t) => typeof t.model === "string" && t.model.includes(MODEL),
      );
      expect(sawModel).toBe(true);
    },
    60_000,
  );
});
