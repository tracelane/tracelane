/**
 * POST /api/billing/portal — proxy to the gateway's `/v1/billing/portal`
 * which calls Polar.sh. Stripe direct calls are banned post Phase-2
 * (`.claude/rules/billing.md`); the dashboard now never holds a Polar
 * access token, only the user's JWT.
 *
 * Returns { url } — the client redirects to the Polar-hosted portal.
 *
 * browser calls it with a SESSION COOKIE, not a Bearer — so the header was
 * always null and every gateway call 401'd ("Manage billing" was dead). We now
 * MINT the per-user WorkOS JWT via `requireGatewayToken()` and forward it,
 * mirroring `/api/checkout`. The gateway resolves the Polar customer from the
 * JWT-bound tenant (never the body).
 */

import { requireGatewayToken } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function POST(): Promise<NextResponse> {
	const { token } = await requireGatewayToken();

	const base = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";
	const upstream = await fetch(`${base}/v1/billing/portal`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${token}`,
		},
		// The gateway resolves the Polar customer ID from the JWT-bound
		// tenant; the dashboard sends an empty body to keep the surface minimal.
		body: JSON.stringify({}),
	});

	if (!upstream.ok) {
		// A3 / A27: never propagate the upstream body (Polar error JSON can
		// include request IDs that hint at the org-scoped access token). The
		// gateway already redacts its own logs; return a generic message.
		return NextResponse.json(
			{ error: "billing portal unavailable" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	const data = (await upstream.json()) as { url: string };
	return NextResponse.json({ url: data.url });
}
