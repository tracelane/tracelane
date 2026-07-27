/**
 * next.config.test.ts — regression guard for the checkout CSP fix.
 *
 * Bug: `form-action 'self'` silently killed every "Upgrade to <tier>" button on
 * /settings/billing. The button is a native <form method="post"> → /api/checkout,
 * which 302-redirects to Polar's cross-origin hosted checkout
 * (https://polar.sh/checkout/…). Chrome enforces `form-action` across the whole
 * redirect chain, so the browser refused the hop to polar.sh — no navigation, no
 * user-visible error, only a console CSP violation. The dead-button E2E gate
 * missed it because a fired network request counts as "wired" (green-while-broken).
 *
 * This asserts the CSP keeps Polar in `form-action` so the redirect completes.
 */

import { describe, expect, it } from "vitest";
import nextConfig from "./next.config";

describe("CSP form-action allows Polar checkout redirect", () => {
	it("form-action lists polar.sh so /api/checkout → Polar completes", async () => {
		const headers = await nextConfig.headers?.();
		expect(headers, "next.config must define headers()").toBeTruthy();

		const csp = headers
			?.flatMap((h) => h.headers)
			.find((h) => h.key === "Content-Security-Policy")?.value;
		expect(csp, "CSP header must be present").toBeTruthy();

		const formAction = csp
			?.split(";")
			.map((d) => d.trim())
			.find((d) => d.startsWith("form-action"));
		expect(formAction, "CSP must have a form-action directive").toBeTruthy();

		// Both the apex (polar.sh) and subdomains (sandbox./buy.polar.sh) — a
		// wildcard alone does not match the apex host.
		expect(formAction).toContain("https://polar.sh");
		expect(formAction).toContain("https://*.polar.sh");
		// Still self-scoped for our own routes — we widened, did not open up.
		expect(formAction).toContain("'self'");
	});
});
