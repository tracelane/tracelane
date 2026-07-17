/**
 * POST /api/checkout — start an in-app Polar checkout for a plan upgrade.
 *
 * Mirrors `/api/billing/portal`: authenticates the session, forwards the
 * per-user WorkOS JWT as the Bearer (the gateway resolves the tenant from it —
 * never from the request body), and proxies to the gateway's
 * `POST /v1/billing/checkout`, which calls Polar.sh and returns the hosted
 * checkout URL. We 302-redirect the browser straight to that Polar URL. Stripe
 * direct calls are banned post Phase-2 (`.claude/rules/billing.md`); the
 * dashboard never holds a Polar access token, only the user's JWT.
 *
 * The desired tier is selected via `?tier=` (builder | team | business |
 * enterprise) and mapped to the Polar product UUID through deployment env
 * (`POLAR_PRODUCT_ID_<TIER>`). Real product ids stay in config, never in code.
 * A valid tier with no configured product id fails loud (501) rather than
 * starting a broken checkout.
 */

import { requireGatewayToken, requireSession } from "@/lib/auth";
import { type NextRequest, NextResponse } from "next/server";

/** Tier → the env var holding its Polar product UUID. */
const PRODUCT_ENV: Record<string, string> = {
	builder: "POLAR_PRODUCT_ID_BUILDER",
	team: "POLAR_PRODUCT_ID_TEAM",
	business: "POLAR_PRODUCT_ID_BUSINESS",
	enterprise: "POLAR_PRODUCT_ID_ENTERPRISE",
};

export async function POST(req: NextRequest): Promise<NextResponse> {
	// Auth first: mint the per-user JWT (the gateway derives the tenant from it)
	// and read the customer email the gateway checkout endpoint requires. Both
	// redirect (NEXT_REDIRECT) when there is no session — never swallowed.
	const { token } = await requireGatewayToken();
	const { email } = await requireSession();

	const tier = (req.nextUrl.searchParams.get("tier") ?? "").toLowerCase();
	const envName = PRODUCT_ENV[tier];
	if (!envName) {
		return NextResponse.json({ error: "unknown tier" }, { status: 400 });
	}
	const productId = process.env[envName];
	if (!productId) {
		// Valid tier, but this deployment has no Polar product id for it. Fail
		// loud instead of POSTing an empty product_id (the gateway 400s anyway).
		return NextResponse.json(
			{ error: "checkout not configured for this tier" },
			{ status: 501 },
		);
	}

	const base = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";
	const upstream = await fetch(`${base}/v1/billing/checkout`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${token}`,
		},
		body: JSON.stringify({ product_id: productId, customer_email: email }),
	});

	if (!upstream.ok) {
		// Never propagate the upstream body — Polar/gateway error JSON can carry
		// request ids hinting at the org-scoped access token (mirror the portal
		// route's A3/A27 redaction).
		return NextResponse.json(
			{ error: "checkout unavailable" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	const data = (await upstream.json()) as { url: string };
	// 302 to the Polar-hosted checkout; the browser follows to Polar's page.
	return NextResponse.redirect(data.url, 302);
}
