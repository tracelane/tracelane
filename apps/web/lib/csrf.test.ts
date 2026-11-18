/**
 * 2026-10-29 SRE review: every cookie-authenticated, state-changing route needs positive
 * proof the request came from this app's own pages. Before this, only the gateway-control
 * relay checked; `/settings/account/email`, `/api/settings/team/invite`,
 * `/api/settings/api-keys` … accepted a `text/plain` form POST from any same-SITE origin
 * (the marketing site, the docs host), because a SameSite=Lax cookie rides same-site
 * requests and those handlers parse JSON whatever the Content-Type.
 */
import { describe, expect, it } from "vitest";
import { refuseCrossOriginMutation } from "./csrf";

const APP = "https://app.tracelane.dev";

function req(
	method: string,
	path: string,
	headers: Record<string, string> = {},
): { method: string; url: string; headers: Headers } {
	return { method, url: `${APP}${path}`, headers: new Headers(headers) };
}

describe("refuseCrossOriginMutation — must reject", () => {
	it("a same-site form POST from the marketing site", () => {
		expect(
			refuseCrossOriginMutation(
				req("POST", "/settings/account/email", {
					"sec-fetch-site": "same-site",
					origin: "https://tracelane.dev",
				}),
			),
		).toBe(true);
	});
	it("a same-site POST from the docs host", () => {
		expect(
			refuseCrossOriginMutation(
				req("POST", "/api/settings/team/invite", {
					origin: "https://docs.tracelane.dev",
				}),
			),
		).toBe(true);
	});
	it("a cross-site DELETE", () => {
		expect(
			refuseCrossOriginMutation(
				req("DELETE", "/api/settings/api-keys/k1", {
					"sec-fetch-site": "cross-site",
					origin: "https://evil.example",
				}),
			),
		).toBe(true);
	});
	it("a mutation carrying neither Sec-Fetch-Site nor Origin (no positive proof)", () => {
		expect(refuseCrossOriginMutation(req("PATCH", "/api/dashboards/d1"))).toBe(
			true,
		);
	});
	it("an Origin of `null` (sandboxed frame / data: URL)", () => {
		expect(
			refuseCrossOriginMutation(
				req("PUT", "/api/settings/workspace", { origin: "null" }),
			),
		).toBe(true);
	});
	it("an Origin that only shares a prefix with the app", () => {
		expect(
			refuseCrossOriginMutation(
				req("POST", "/api/checkout", {
					origin: "https://app.tracelane.dev.evil.example",
				}),
			),
		).toBe(true);
	});
	it("a lookalike webhook path is not exempt", () => {
		expect(
			refuseCrossOriginMutation(
				req("POST", "/api/webhooksx/polar", { origin: "https://evil.example" }),
			),
		).toBe(true);
	});
});

describe("refuseCrossOriginMutation — must accept", () => {
	it("a same-origin fetch from the app (Sec-Fetch-Site)", () => {
		expect(
			refuseCrossOriginMutation(
				req("POST", "/api/settings/api-keys", {
					"sec-fetch-site": "same-origin",
				}),
			),
		).toBe(false);
	});
	it("a same-origin request proven only by Origin (older browser)", () => {
		expect(
			refuseCrossOriginMutation(
				req("DELETE", "/api/dashboards/d1", { origin: APP }),
			),
		).toBe(false);
	});
	it("safe methods are never refused", () => {
		for (const m of ["GET", "HEAD", "OPTIONS"]) {
			expect(
				refuseCrossOriginMutation(
					req(m, "/api/settings/api-keys", { origin: "https://evil.example" }),
				),
			).toBe(false);
		}
	});
	it("the Polar webhook (server-to-server, HMAC-verified) is exempt", () => {
		expect(refuseCrossOriginMutation(req("POST", "/api/webhooks/polar"))).toBe(
			false,
		);
	});
	it("method case does not matter", () => {
		expect(
			refuseCrossOriginMutation(
				req("post", "/api/support", { "sec-fetch-site": "same-origin" }),
			),
		).toBe(false);
	});
});
