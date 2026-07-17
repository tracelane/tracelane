import { afterAll, beforeAll, describe, it } from "vitest";
import { expect, isLiveGatewayConfigured } from "../src/harness.js";
import { type LiveGatewayContext, spawnLiveGateway } from "../src/live-harness.js";

/**
 * GC-DISPATCH-ERROR (live) — fault-tolerance gate for the dispatch-error surface
 *
 * When an upstream provider rejects the tenant's key (HTTP 401/403), the gateway
 * used to collapse it into an opaque **502 "provider unavailable"** — the user
 * got no signal the *key* was wrong (this cost two debugging cycles on the
 * **401 `provider_key_rejected`**.
 *
 * The live stack points the Anthropic upstream at the mock provider, whose
 * `/v1/messages` endpoint returns 401 (a rejected key). A `claude-*` request
 * therefore exercises the real dispatch-failure path end-to-end:
 *   gateway → anthropic adapter → mock 401 → typed ProviderHttpError(401) →
 *   handler → `provider_key_rejected`.
 *
 * Also a redaction guard: the mock's 401 body echoes a fake key; it must never
 *
 * Skips in mock mode (no live gateway); runs in the `live-eval-gate` CI job.
 */

const AUTH = "Bearer eval-dev-token";

let live: LiveGatewayContext;

beforeAll(async () => {
  live = await spawnLiveGateway({ healthPath: "/health" });
});

afterAll(async () => {
  if (live) await live.stop();
});

describe("GC-DISPATCH-ERROR (live): upstream 401 → provider_key_rejected, not opaque 502", () => {
  it.skipIf(!isLiveGatewayConfigured())(
    "a rejected provider key (upstream 401) returns 401 provider_key_rejected and never echoes the upstream body",
    async () => {
      // Live but unreachable = hard failure, never a silent skip (see GC-TRACE-LOOP).
      expect(live.skip, `live gateway unreachable: ${live.skipReason ?? "unknown"}`).toBe(false);

      // claude-* routes to the Anthropic adapter, whose mock upstream returns 401.
      const res = await fetch(`${live.url.replace(/\/$/, "")}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: AUTH },
        body: JSON.stringify({
          model: "claude-haiku-4-5",
          messages: [{ role: "user", content: "L2 dispatch-error probe" }],
          max_tokens: 16,
        }),
      });

      expect(res.status).toBe(401);
      const body = (await res.json()) as { error?: string; provider?: string };
      expect(body.error).toBe("provider_key_rejected");

      // Redaction: the upstream 401 body echoed a fake key — it must not leak.
      expect(JSON.stringify(body).includes("sk-ant-leaked-secret")).toBe(false);
    },
    30_000,
  );
});
