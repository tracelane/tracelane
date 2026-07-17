/**
 *
 * The deliverable: tenant A's prompt fetch never returns tenant B's versions or
 * history. We mock `requireGatewayToken` to mint a per-tenant JWT and a
 * tenant-aware `global.fetch` that returns data keyed ONLY by the forwarded
 * Bearer token (modelling the gateway's `WHERE tenant_id = ?` resolution of the
 * JWT). The SAME prompt name requested under two sessions yields two tenants'
 * data — proving the read is scoped by the per-user JWT, not a shared operator
 * bearer. Negative-first per `.claude/rules/testing.md`. No real network.
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

import { fetchHistory, fetchVersion } from "./prompts";

// A fake gateway: returns a tenant's prompt store keyed by the Bearer token.
// Two distinct tenants, the SAME prompt name — isolation must come from the JWT.
const STORE: Record<
	string,
	{ version: Record<string, unknown>; history: Array<Record<string, unknown>> }
> = {
	"jwt-tenant-a": {
		version: {
			prompt_version_id: "ver-A",
			prompt_id: "prompt-A",
			version_number: 7,
			content: "tenant A content",
			model_pin: null,
			sha256_hex: "aaaaaaaaaaaaaaaa",
		},
		history: [
			{
				kind: "promotion",
				promotion_id: "promo-A",
				from_env: "staging",
				to_env: "production",
				from_version_id: null,
				to_version_id: "ver-A",
				decision: "promoted",
				notes: "",
				at_micros: 1,
			},
		],
	},
	"jwt-tenant-b": {
		version: {
			prompt_version_id: "ver-B",
			prompt_id: "prompt-B",
			version_number: 99,
			content: "tenant B content",
			model_pin: null,
			sha256_hex: "bbbbbbbbbbbbbbbb",
		},
		history: [
			{
				kind: "rollback",
				rollback_id: "rollback-B",
				from_version_id: "ver-B0",
				to_version_id: "ver-B",
				trigger_metric: "error_rate",
				trigger_value: 0.4,
				sigma_drift: 3.2,
				rollback_mode: "auto",
				at_micros: 2,
			},
		],
	},
};

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
	// Tenant-aware fake gateway: the Bearer token alone selects the tenant store.
	fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
		const auth = (init?.headers as Record<string, string> | undefined)
			?.authorization;
		const token = auth?.replace(/^Bearer /, "");
		const store = token ? STORE[token] : undefined;
		if (!store) {
			return { ok: false, status: 401, json: async () => ({}) } as Response;
		}
		const body = url.includes("/history") ? store.history : store.version;
		return { ok: true, status: 200, json: async () => body } as Response;
	});
});

describe("fetchVersion — per-user JWT tenant isolation", () => {
	it("ignores GATEWAY_BEARER_TOKEN and forwards the per-user JWT, not the static operator token", async () => {
		// Even with a poison static operator token present in the env, the read
		// must carry the user's JWT — proving the removed static seam is dead.
		vi.stubEnv("GATEWAY_BEARER_TOKEN", "static-operator-POISON");
		try {
			await fetchVersion("shared-prompt", "production");
			expect(bearerOf()).toBe("Bearer jwt-tenant-a");
			expect(bearerOf()).not.toContain("POISON");
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("returns ONLY tenant A's version — never tenant B's — for a shared prompt name", async () => {
		h.token = "jwt-tenant-a";
		const res = await fetchVersion("shared-prompt", "production");
		expect("error" in res).toBe(false);
		const v = res as { prompt_version_id: string; version_number: number };
		expect(v.prompt_version_id).toBe("ver-A");
		expect(v.version_number).toBe(7);
		// The cross-tenant guarantee: tenant B's data is never returned.
		expect(v.prompt_version_id).not.toBe("ver-B");
		expect(v.version_number).not.toBe(99);
	});

	it("returns ONLY tenant B's version under tenant B's session", async () => {
		h.token = "jwt-tenant-b";
		const res = await fetchVersion("shared-prompt", "production");
		const v = res as { prompt_version_id: string; version_number: number };
		expect(v.prompt_version_id).toBe("ver-B");
		expect(v.version_number).toBe(99);
		expect(v.prompt_version_id).not.toBe("ver-A");
	});

	it("maps a gateway non-2xx to an { error } card (existence never leaks)", async () => {
		h.token = "unknown-tenant-token"; // not in STORE → fake gateway 401
		const res = await fetchVersion("shared-prompt", "production");
		expect(res).toEqual({ error: "gateway responded 401" });
	});

	it("propagates a non-GatewayError (NEXT_REDIRECT) rather than swallowing it", async () => {
		const { requireGatewayToken } = await import("@/lib/auth");
		vi.mocked(requireGatewayToken).mockRejectedValueOnce(
			new Error("NEXT_REDIRECT"),
		);
		await expect(fetchVersion("shared-prompt", "production")).rejects.toThrow(
			"NEXT_REDIRECT",
		);
	});
});

describe("fetchHistory — per-user JWT tenant isolation", () => {
	it("returns ONLY tenant A's history — never tenant B's events", async () => {
		h.token = "jwt-tenant-a";
		const hist = await fetchHistory("shared-prompt", 50);
		expect(hist).toHaveLength(1);
		expect(hist[0]).toMatchObject({
			kind: "promotion",
			promotion_id: "promo-A",
		});
		// None of tenant B's events bleed through.
		const serialized = JSON.stringify(hist);
		expect(serialized).not.toContain("rollback-B");
		expect(serialized).not.toContain("ver-B");
	});

	it("returns ONLY tenant B's history under tenant B's session", async () => {
		h.token = "jwt-tenant-b";
		const hist = await fetchHistory("shared-prompt", 50);
		expect(hist).toHaveLength(1);
		expect(hist[0]).toMatchObject({
			kind: "rollback",
			rollback_id: "rollback-B",
		});
		expect(JSON.stringify(hist)).not.toContain("promo-A");
	});

	it("forwards the per-user JWT as Bearer", async () => {
		h.token = "jwt-tenant-b";
		await fetchHistory("shared-prompt", 50);
		expect(bearerOf()).toBe("Bearer jwt-tenant-b");
	});

	it("returns [] on a gateway non-2xx (best-effort empty state)", async () => {
		h.token = "unknown-tenant-token";
		expect(await fetchHistory("shared-prompt", 50)).toEqual([]);
	});

	it("propagates a non-GatewayError (NEXT_REDIRECT) rather than swallowing it", async () => {
		const { requireGatewayToken } = await import("@/lib/auth");
		vi.mocked(requireGatewayToken).mockRejectedValueOnce(
			new Error("NEXT_REDIRECT"),
		);
		await expect(fetchHistory("shared-prompt", 50)).rejects.toThrow(
			"NEXT_REDIRECT",
		);
	});
});
