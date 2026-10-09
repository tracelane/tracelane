import { afterEach, expect, it, vi } from "vitest";
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({ token: "test-session-token" })),
}));
import { gatewayResponse } from "./gateway";
afterEach(() => {
	vi.unstubAllGlobals();
	vi.unstubAllEnvs();
});
it("forwards the session credential and preserves refusal body and Retry-After", async () => {
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "http://fixture.test");
	const upstream = new Response(
		JSON.stringify({ code: "outcome_rate_limited" }),
		{
			status: 429,
			headers: { "retry-after": "9", "content-type": "application/json" },
		},
	);
	const fetchMock = vi.fn(async () => upstream);
	vi.stubGlobal("fetch", fetchMock);
	const response = await gatewayResponse("/v1/outcomes", {
		method: "POST",
		body: "{}",
		headers: {
			"content-type": "application/json",
			"idempotency-key": "test-retry",
		},
	});
	expect(response.status).toBe(429);
	expect(response.headers.get("retry-after")).toBe("9");
	expect(await response.json()).toEqual({ code: "outcome_rate_limited" });
	const [url, init] = fetchMock.mock.calls[0] as unknown as [
		string,
		RequestInit,
	];
	expect(url).toBe("http://fixture.test/v1/outcomes");
	expect(new Headers(init.headers).get("authorization")).toBe(
		"Bearer test-session-token",
	);
	expect(new Headers(init.headers).get("idempotency-key")).toBe("test-retry");
});
it("returns a stable transport error without leaking upstream details", async () => {
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "http://fixture.test");
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => {
			throw new Error("sensitive upstream context");
		}),
	);
	const response = await gatewayResponse("/v1/outcomes?subject=trace");
	expect(response.status).toBe(502);
	expect(await response.json()).toEqual({ code: "gateway_unreachable" });
});
it("passes only explicitly allowed response headers for downloads and refusals", async () => {
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "http://fixture.test");
	const allowed = {
		"content-type": "application/x-ndjson",
		"content-disposition": 'attachment; filename="regression.jsonl"',
		"retry-after": "5",
		"idempotency-key": "retry-1",
		"x-truncated": "true",
		"x-regression-mode": "recorded",
		"x-regression-limits": "recorded content only",
	};
	for (const status of [200, 429]) {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response("fixture", {
						status,
						headers: {
							...allowed,
							"set-cookie": "session=attacker",
							connection: "keep-alive",
							"x-internal-secret": "private",
							location: "https://untrusted.test",
							"x-regressionevil": "private",
						},
					}),
			),
		);
		const response = await gatewayResponse("/v1/traces/t/regression");
		expect(response.status).toBe(status);
		expect(await response.text()).toBe("fixture");
		expect(Object.fromEntries(response.headers)).toEqual(allowed);
	}
});
// Prod regression 2026-10-04: workerd rejects `redirect: "error"` with a TypeError, which the
// catch masked as 502 gateway_unreachable, so EVERY gatewayResponse route (incident packet,
// outcomes, agent loops, spend, provider keys, content capture) failed on Cloudflare while
// node/vitest fetch accepted it. This stub throws exactly as workerd does.
function workerdLikeFetch(respond: () => Response) {
	return vi.fn(async (_url: unknown, init?: RequestInit) => {
		if (init?.redirect === "error") {
			throw new TypeError(
				'Invalid redirect value, must be one of "follow" or "manual"',
			);
		}
		return respond();
	});
}
it("never asks fetch for redirect:error, which workerd rejects (prod 502 on every proxied route)", async () => {
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "http://fixture.test");
	vi.stubGlobal(
		"fetch",
		workerdLikeFetch(
			() =>
				new Response(JSON.stringify({ ok: true }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
		),
	);
	const response = await gatewayResponse("/v1/outcomes?subject=trace");
	expect(response.status).toBe(200);
	expect(await response.json()).toEqual({ ok: true });
});
it("still refuses to follow an upstream redirect: a 3xx becomes gateway_unreachable, never forwarded", async () => {
	vi.stubEnv("NEXT_PUBLIC_GATEWAY_URL", "http://fixture.test");
	const fetchMock = workerdLikeFetch(
		() =>
			new Response(null, {
				status: 302,
				headers: { location: "https://untrusted.test/steal" },
			}),
	);
	vi.stubGlobal("fetch", fetchMock);
	const response = await gatewayResponse("/v1/outcomes?subject=trace");
	expect(response.status).toBe(502);
	expect(await response.json()).toEqual({ code: "gateway_unreachable" });
	expect(response.headers.get("location")).toBeNull();
	expect(fetchMock).toHaveBeenCalledTimes(1);
});
