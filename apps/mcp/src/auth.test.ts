/**
 * Tenant-isolation + bearer-resolution tests for the MCP auth layer.
 *
 * Tenant isolation (AsyncLocalStorage) is the security boundary: a tool call
 * MUST see only its own request's tenant, must fail CLOSED when no tenant is
 * established, and must not leak across concurrent async chains. The bearer
 * resolver must never re-query the gateway on a cache hit and must
 * negative-cache failures (anti credential-stuffing amplification).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
	bootstrapStdioTenant,
	getTenantId,
	resolveBearerViaGateway,
	runWithTenant,
	setStdioTenantId,
} from "./auth.js";

describe("MCP tenant isolation", () => {
	// `vi.stubEnv(name, "")` makes getTenantId see a falsy value (treated as
	// unset); unstubAllEnvs restores the real environment. Avoids `delete`.
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.restoreAllMocks();
	});

	it("returns the tenant bound by runWithTenant", async () => {
		vi.stubEnv("TRACELANE_TENANT_ID", "");
		const got = await runWithTenant("tenant-A", async () => getTenantId());
		expect(got).toBe("tenant-A");
	});

	it("fails CLOSED (throws) with no context and no env", () => {
		vi.stubEnv("TRACELANE_TENANT_ID", "");
		expect(() => getTenantId()).toThrow(/No tenant context/);
	});

	it("falls back to TRACELANE_TENANT_ID outside a context (Stdio mode)", () => {
		vi.stubEnv("TRACELANE_TENANT_ID", "env-tenant");
		expect(getTenantId()).toBe("env-tenant");
	});

	it("isolates tenants across interleaved concurrent requests (no leakage)", async () => {
		vi.stubEnv("TRACELANE_TENANT_ID", "");
		const observe = (t: string, delayMs: number) =>
			runWithTenant(t, async () => {
				await new Promise((r) => setTimeout(r, delayMs));
				// Read AFTER the await — proves the context survived the suspension
				// and did not get clobbered by the other concurrent request.
				return getTenantId();
			});
		const [x, y] = await Promise.all([
			observe("tenant-X", 20),
			observe("tenant-Y", 5),
		]);
		expect(x).toBe("tenant-X");
		expect(y).toBe("tenant-Y");
	});
});

function mockResponse(opts: {
	ok: boolean;
	status: number;
	body?: unknown;
}): Response {
	return {
		ok: opts.ok,
		status: opts.status,
		headers: { get: () => null },
		json: async () => opts.body ?? {},
	} as unknown as Response;
}

describe("resolveBearerViaGateway", () => {
	afterEach(() => vi.restoreAllMocks());

	it("returns null for an empty bearer without hitting the gateway", async () => {
		const f = vi.fn();
		vi.stubGlobal("fetch", f);
		expect(await resolveBearerViaGateway("")).toBeNull();
		expect(f).not.toHaveBeenCalled();
	});

	it("resolves the tenant from whoami and caches it (one fetch only)", async () => {
		const f = vi.fn(async () =>
			mockResponse({ ok: true, status: 200, body: { tenant_id: "t-123" } }),
		);
		vi.stubGlobal("fetch", f as unknown as typeof fetch);
		const bearer = "unit-test-bearer-ok-001";
		expect(await resolveBearerViaGateway(bearer)).toBe("t-123");
		expect(await resolveBearerViaGateway(bearer)).toBe("t-123"); // cache hit
		expect(f).toHaveBeenCalledTimes(1);
	});

	it("returns null and negative-caches a 401 (anti-amplification)", async () => {
		const f = vi.fn(async () => mockResponse({ ok: false, status: 401 }));
		vi.stubGlobal("fetch", f as unknown as typeof fetch);
		const bearer = "unit-test-bearer-bad-002";
		expect(await resolveBearerViaGateway(bearer)).toBeNull();
		expect(await resolveBearerViaGateway(bearer)).toBeNull(); // negative cache
		expect(f).toHaveBeenCalledTimes(1);
	});

	it("returns null when whoami omits tenant_id", async () => {
		const f = vi.fn(async () =>
			mockResponse({ ok: true, status: 200, body: { not_a_tenant: true } }),
		);
		vi.stubGlobal("fetch", f as unknown as typeof fetch);
		expect(
			await resolveBearerViaGateway("unit-test-bearer-empty-003"),
		).toBeNull();
	});
});

describe("bootstrapStdioTenant (stdio API-key auth — L3 sweep)", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.restoreAllMocks();
		setStdioTenantId(null);
	});

	it("no TRACELANE_API_KEY → null, env fallback still works", async () => {
		vi.stubEnv("TRACELANE_API_KEY", "");
		vi.stubEnv("TRACELANE_TENANT_ID", "env-tenant");
		expect(await bootstrapStdioTenant()).toBeNull();
		expect(getTenantId()).toBe("env-tenant");
	});

	it("a set key resolves via the gateway and BEATS the raw env id", async () => {
		vi.stubEnv("TRACELANE_API_KEY", "tlane_bootstrap_test_key");
		vi.stubEnv("TRACELANE_TENANT_ID", "stale-env-tenant");
		vi.stubEnv("TRACELANE_GATEWAY_URL", "https://gateway.tracelane.dev");
		vi.spyOn(globalThis, "fetch").mockResolvedValue(
			mockResponse({
				ok: true,
				status: 200,
				body: { tenant_id: "validated-tenant-uuid" },
			}),
		);
		expect(await bootstrapStdioTenant()).toBe("validated-tenant-uuid");
		// The gateway-VALIDATED tenant wins over the unvalidated env id.
		expect(getTenantId()).toBe("validated-tenant-uuid");
	});

	it("FAIL CLOSED: a set-but-rejected key throws (never falls back to env)", async () => {
		vi.stubEnv("TRACELANE_API_KEY", "tlane_rejected_key_98765432109876");
		vi.stubEnv("TRACELANE_TENANT_ID", "must-not-be-used");
		vi.stubEnv("TRACELANE_GATEWAY_URL", "https://gateway.tracelane.dev");
		vi.spyOn(globalThis, "fetch").mockResolvedValue(
			mockResponse({ ok: false, status: 401 }),
		);
		await expect(bootstrapStdioTenant()).rejects.toThrow(
			/could not be validated/,
		);
	});
});
