/**
 * Tests for lib/sessions — session gateway reads (regression).
 *
 * The deliverable: tenant A's session fetch never returns tenant B's sessions
 * or traces. We mock `requireGatewayToken` to mint a per-tenant JWT and a
 * tenant-aware `global.fetch` that returns data keyed ONLY by the forwarded
 * Bearer token (modelling the gateway's `WHERE tenant_id = ?` resolution of
 * the JWT). The SAME session id requested under two sessions yields only the
 * owning tenant's data — proving reads are scoped by the per-user JWT, not a
 * shared operator bearer. Negative-first per `.claude/rules/testing.md`.
 * No real network.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

// Mutable per-tenant token the mocked auth helper hands to gatewayGet.
const h = vi.hoisted(() => ({ token: "jwt-tenant-a", tenantId: "org_A" }));

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({
		token: h.token,
		tenantId: h.tenantId,
	})),
}));

import { fetchSessionsFor } from "@/lib/metrics/fetch";
import { fetchSessionTraces } from "./sessions";

// The list window every read is asked for — the shared grammar (DSH-11).
const WIN = {
	sinceMs: Date.parse("2026-06-01T00:00:00Z"),
	untilMs: Date.parse("2026-07-01T00:00:00Z"),
	bucketMs: 3_600_000,
};

// Fake session data scoped to each tenant (keyed by Bearer token).
const STORE = {
	"jwt-tenant-a": {
		sessions: [
			{
				session_id: "sess-A-001",
				turns: 3,
				started_at: "2026-06-10 00:05:00.000000",
				last_activity: "2026-06-10 00:12:00.000000",
				duration_us: 420_000_000,
				error_count: 0,
				status: "ok" as const,
				cost_usd: 0.0015,
				total_tokens: 1500,
				model: "gpt-4o-mini",
			},
		],
		traces: {
			"sess-A-001": {
				session_id: "sess-A-001",
				traces: [
					{
						trace_id: "trace-A-001",
						root_name: "call_llm",
						start_time: "2026-06-10 00:05:00.000000",
						start_time_us: 1_749_514_800_000_000,
						duration_us: 100_000_000,
						span_count: 5,
						error_count: 0,
						model: "gpt-4o-mini",
					},
				],
			},
		} as Record<
			string,
			{
				session_id: string;
				traces: {
					trace_id: string;
					root_name: string;
					start_time: string;
					start_time_us: number;
					duration_us: number;
					span_count: number;
					error_count: number;
					model: string;
				}[];
			}
		>,
	},
	"jwt-tenant-b": {
		sessions: [
			{
				session_id: "sess-001",
				turns: 1,
				started_at: "2026-06-10 01:00:00.000000",
				last_activity: "2026-06-10 01:05:00.000000",
				duration_us: 300_000_000,
				error_count: 1,
				status: "error" as const,
				cost_usd: 0,
				total_tokens: 500,
				model: "claude-3-5-haiku",
			},
		],
		traces: {} as Record<string, { session_id: string; traces: unknown[] }>,
	},
} as const;

type StoreKey = keyof typeof STORE;

const fetchMock = vi.fn();

function bearerOf(callIndex = 0): string | undefined {
	const init = fetchMock.mock.calls[callIndex]?.[1] as
		| { headers?: Record<string, string> }
		| undefined;
	return init?.headers?.authorization;
}

beforeEach(() => {
	h.token = "jwt-tenant-a";
	h.tenantId = "org_A";
	global.fetch = fetchMock as unknown as typeof fetch;
	fetchMock.mockReset();

	// Tenant-aware fake gateway: the Bearer token alone selects the store.
	// Returns 401 for unknown tokens, 404 for unknown session ids.
	fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
		const auth = (init?.headers as Record<string, string> | undefined)
			?.authorization;
		const token = auth?.replace(/^Bearer /, "") as StoreKey | undefined;
		const store = token !== undefined ? STORE[token] : undefined;
		if (store === undefined) {
			return {
				ok: false,
				status: 401,
				json: async () => ({}),
			} as Response;
		}

		// Detect /v1/sessions/:id/traces
		const tracesMatch = /\/v1\/sessions\/([^/]+)\/traces/.exec(url);
		if (tracesMatch !== null) {
			const sid = decodeURIComponent(tracesMatch[1] ?? "");
			// A sentinel id forcing a real upstream failure (B-335d) — distinct from
			// "no such session" (404), which the store lookup below covers.
			if (sid === "sess-upstream-502") {
				return {
					ok: false,
					status: 502,
					json: async () => ({ error: "bad_gateway" }),
				} as Response;
			}
			const sessionData = store.traces[sid as keyof typeof store.traces];
			if (sessionData === undefined) {
				return {
					ok: false,
					status: 404,
					json: async () => ({}),
				} as Response;
			}
			return {
				ok: true,
				status: 200,
				json: async () => sessionData,
			} as Response;
		}

		// /v1/sessions list
		return {
			ok: true,
			status: 200,
			json: async () => ({ sessions: store.sessions }),
		} as Response;
	});
});

describe("fetchSessionsFor — per-user JWT tenant isolation", () => {
	it("ignores GATEWAY_BEARER_TOKEN and forwards the per-user JWT, not the static operator token", async () => {
		vi.stubEnv("GATEWAY_BEARER_TOKEN", "static-operator-POISON");
		try {
			await fetchSessionsFor(WIN);
			expect(bearerOf()).toBe("Bearer jwt-tenant-a");
			expect(bearerOf()).not.toContain("POISON");
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("returns ONLY tenant A's sessions — never tenant B's", async () => {
		h.token = "jwt-tenant-a";
		const sessions = await fetchSessionsFor(WIN);
		expect(sessions).toHaveLength(1);
		expect(sessions?.[0]?.session_id).toBe("sess-A-001");
		const serialized = JSON.stringify(sessions ?? []);
		expect(serialized).not.toContain("sess-001");
		expect(serialized).not.toContain("claude-3-5-haiku");
	});

	it("returns ONLY tenant B's sessions under tenant B's JWT", async () => {
		h.token = "jwt-tenant-b";
		const sessions = await fetchSessionsFor(WIN);
		expect(sessions?.[0]?.session_id).toBe("sess-001");
		const serialized = JSON.stringify(sessions ?? []);
		expect(serialized).not.toContain("sess-A-001");
		expect(serialized).not.toContain("gpt-4o-mini");
	});

	it("returns null on a gateway non-2xx — unreachable, never an empty list (B-334)", async () => {
		h.token = "unknown-tenant-xyz" as StoreKey;
		expect(await fetchSessionsFor(WIN)).toBeNull();
	});

	it("propagates NEXT_REDIRECT rather than swallowing it", async () => {
		const { requireGatewayToken } = await import("@/lib/auth");
		vi.mocked(requireGatewayToken).mockRejectedValueOnce(
			new Error("NEXT_REDIRECT"),
		);
		await expect(fetchSessionsFor(WIN)).rejects.toThrow("NEXT_REDIRECT");
	});

	it("forwards the window as since/until (RFC3339) plus limit — never days=", async () => {
		await fetchSessionsFor(WIN, { limit: 20 });
		const calledUrl = fetchMock.mock.calls[0]?.[0] as string | undefined;
		expect(calledUrl).toContain("since=2026-06-01T00%3A00%3A00.000Z");
		expect(calledUrl).toContain("until=2026-07-01T00%3A00%3A00.000Z");
		expect(calledUrl).toContain("limit=20");
		expect(calledUrl).not.toContain("days=");
	});
});

describe("fetchSessionTraces — per-user JWT tenant isolation", () => {
	it("returns ONLY tenant A's traces — never tenant B's", async () => {
		h.token = "jwt-tenant-a";
		const result = await fetchSessionTraces("sess-A-001");
		expect(result).not.toBeNull();
		expect(result?.traces).toHaveLength(1);
		expect(result?.traces[0]?.trace_id).toBe("trace-A-001");
		// Cross-tenant guarantee: no tenant B identifiers bleed through.
		const serialized = JSON.stringify(result);
		expect(serialized).not.toContain("sess-B");
	});

	it("returns null on 404 — same 404 for 'not found' and 'not this tenant's'", async () => {
		h.token = "jwt-tenant-a";
		// sess-001 is in tenant B's store but tenant A has no such session.
		const result = await fetchSessionTraces("sess-001");
		expect(result).toBeNull();
	});

	it("throws (never null) on a non-404 GatewayError — a 401 is a real failure, not 'not found'", async () => {
		h.token = "unknown-tenant-xyz" as StoreKey;
		await expect(fetchSessionTraces("sess-A-001")).rejects.toMatchObject({
			status: 401,
		});
	});

	it("throws on a 502 upstream failure — must not read as 'not found' (B-335d)", async () => {
		h.token = "jwt-tenant-a";
		await expect(fetchSessionTraces("sess-upstream-502")).rejects.toMatchObject(
			{ status: 502 },
		);
	});

	it("forwards the per-user JWT as Bearer", async () => {
		h.token = "jwt-tenant-a";
		await fetchSessionTraces("sess-A-001");
		expect(bearerOf()).toBe("Bearer jwt-tenant-a");
	});

	it("URL-encodes the session id in the gateway path", async () => {
		h.token = "jwt-tenant-a";
		await fetchSessionTraces("conv/slash");
		const calledUrl = fetchMock.mock.calls[0]?.[0] as string | undefined;
		// encodeURIComponent("conv/slash") = "conv%2Fslash"
		expect(calledUrl).toContain("conv%2Fslash");
	});

	it("propagates NEXT_REDIRECT rather than swallowing it", async () => {
		const { requireGatewayToken } = await import("@/lib/auth");
		vi.mocked(requireGatewayToken).mockRejectedValueOnce(
			new Error("NEXT_REDIRECT"),
		);
		await expect(fetchSessionTraces("sess-A-001")).rejects.toThrow(
			"NEXT_REDIRECT",
		);
	});
});
