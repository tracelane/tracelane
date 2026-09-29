/**
 * POST /api/checkout — start an in-app Polar checkout for a FREE → PAID
 * upgrade, or a REAL PRICE CHANGE for an existing subscriber (B-140).
 *
 * Authenticates the session, forwards the per-user WorkOS JWT as the Bearer
 * (the gateway resolves the tenant from it — never from the request body),
 * and proxies to the gateway's `POST /v1/billing/checkout`, which calls
 * Polar.sh and returns the hosted checkout URL. We 302-redirect the browser
 * straight to that Polar URL. Stripe direct calls are banned post Phase-2
 * (`.claude/rules/billing.md`); the dashboard never holds a Polar access
 * token, only the user's JWT.
 *
 * The desired tier is selected via `?tier=` (builder | team | business) and
 * `?interval=` (month | year, default month) and mapped to the Polar product
 * UUID by reading `plan_entitlements.polar_product_id_month/year` — NOT an
 * env var (`POLAR_PRODUCT_ID_<TIER>` is retired: an env-var product map is
 * exactly the class ADR-076 removes, and it is why annual products could
 * never be added without a Worker redeploy). A valid tier with no configured
 * product id for the deployment fails loud (501) rather than starting a
 * broken checkout.
 *
 * Enterprise is sales-led — never a self-serve checkout target (B-134/B-132:
 * there has never been, and still is not, an Audit-SKU or Enterprise
 * // pricing-guard: allow "Audit SKU" — stating it is NOT sold
 * checkout of any kind; the Audit SKU is not sold at all, spec `BILL-01`
 * §10.4).
 *
 * B-140: a tenant that ALREADY holds an active Polar subscription
 * (`tenants.polar_subscription_id` set) is sent to the customer portal for
 * ANY plan change — Polar rejects a second concurrent subscription in the
 * same group, so a second checkout would just fail at Polar. `/api/checkout`
 * is reserved for the free → paid transition.
 */

import { db } from "@/db";
import { planEntitlements, tenants } from "@/db/schema";
import { requireGatewayToken, requireSession } from "@/lib/auth";
import { PLANS_V3 } from "@/lib/entitlements";
import { gatewayBaseUrl } from "@/lib/gateway";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

/** Self-serve tiers. Enterprise is sales-led (mailto CTA only, no checkout). */
const SELF_SERVE_LOOKUP_KEY: Record<string, string> = {
	builder: "builder_v1",
	team: "team_v1",
	business: "business_v1",
};

/**
 * True when the caller wants a JSON error body rather than a browser
 * navigation — an explicit `Accept: application/json`, the shape every
 * fetch-based caller sends when it wants to branch on the body. Every
 * caller of this route today (`PlanCard.tsx`, `PlanLadder.tsx`) is a native
 * `<form method="post">`, which never sends this header, so they all take
 * the redirect branch.
 */
function wantsJson(req: NextRequest): boolean {
	return (req.headers.get("accept") ?? "").includes("application/json");
}

/**
 * A failure response that a native `<form method="post">` can actually show
 * the customer. Before this, every failure returned raw JSON, which the
 * browser renders as an unstyled page of `{"error":"..."}` — the ONLY thing
 * a form POST's non-2xx JSON response can do. A 303 (not 302: this always
 * follows as a GET, matching a form POST's own semantics) sends the browser
 * back to the billing page with a `checkout_error` code it knows how to
 * render as a sentence. `Accept: application/json` callers keep the JSON
 * body unchanged, in case a future fetch-based caller needs to branch on it.
 */
function failure(
	req: NextRequest,
	status: number,
	code: string,
	message: string,
): NextResponse {
	if (wantsJson(req)) {
		return NextResponse.json({ error: message }, { status });
	}
	return NextResponse.redirect(
		new URL(`/settings/billing?checkout_error=${code}`, req.nextUrl.origin),
		303,
	);
}

async function portalRedirect(
	req: NextRequest,
	token: string,
): Promise<NextResponse> {
	const base = gatewayBaseUrl();
	const upstream = await fetch(`${base}/v1/billing/portal`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${token}`,
		},
		body: JSON.stringify({}),
	});
	if (!upstream.ok) {
		return failure(
			req,
			upstream.status >= 500 ? 502 : upstream.status,
			"portal_unavailable",
			"billing portal unavailable",
		);
	}
	const data = (await upstream.json()) as { url: string };
	let dest: URL;
	try {
		dest = new URL(data.url);
	} catch {
		return failure(
			req,
			502,
			"portal_unavailable",
			"billing portal unavailable",
		);
	}
	if (dest.hostname !== "polar.sh" && !dest.hostname.endsWith(".polar.sh")) {
		return failure(
			req,
			502,
			"portal_unavailable",
			"billing portal unavailable",
		);
	}
	return NextResponse.redirect(dest, 302);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	// Auth first: mint the per-user JWT (the gateway derives the tenant from it)
	// and read the customer email the gateway checkout endpoint requires. Both
	// redirect (NEXT_REDIRECT) when there is no session — never swallowed.
	const { token } = await requireGatewayToken();
	const session = await requireSession();
	const { email } = session;

	const tier = (req.nextUrl.searchParams.get("tier") ?? "").toLowerCase();
	const lookupKey = SELF_SERVE_LOOKUP_KEY[tier];
	if (!lookupKey) {
		return failure(req, 400, "unknown_tier", "unknown tier");
	}
	const interval =
		req.nextUrl.searchParams.get("interval") === "year" ? "year" : "month";
	if (interval === "year" && !PLANS_V3.policy.annual_available) {
		// B14: a yearly Polar product grants its meter credits ONCE per year
		// (B-411); nothing annual is sold until the founder rules the shape.
		// Refused here, before any Neon read, with the reason from the table.
		if (wantsJson(req)) {
			return NextResponse.json(
				{
					error: "annual billing is not available yet",
					reason: "annual_unavailable",
				},
				{ status: 400 },
			);
		}
		return failure(
			req,
			400,
			"annual_unavailable",
			"annual billing is not available yet",
		);
	}

	// B-140: an existing subscriber changes plans through the Polar customer
	// portal, never a second checkout.
	const [tenantRow] = await db
		.select({
			polarSubscriptionId: tenants.polarSubscriptionId,
			polarBaseSubscriptionId: tenants.polarBaseSubscriptionId,
		})
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	if (tenantRow?.polarSubscriptionId || tenantRow?.polarBaseSubscriptionId) {
		return portalRedirect(req, token);
	}

	// BILL-02 (B14 → option (c)): an annual plan is bought as its yearly BASE
	// product; the $0 monthly USAGE subscription is created on the same Polar
	// customer by the reconciler once the base's webhook lands (spec §2.5).
	// The retired one-object `_year` product (credits once a YEAR, B-411) is
	// never read here again.
	const [planRow] = await db
		.select({
			polarProductIdMonth: planEntitlements.polarProductIdMonth,
			polarProductIdBaseYear: planEntitlements.polarProductIdBaseYear,
		})
		.from(planEntitlements)
		.where(eq(planEntitlements.planLookupKey, lookupKey))
		.limit(1);
	const productId =
		interval === "year"
			? planRow?.polarProductIdBaseYear
			: planRow?.polarProductIdMonth;
	if (!productId) {
		// Valid tier, but this deployment has no Polar product id for it/this
		// interval yet (`scripts/ops/polar-sync.mjs` has not run, or Enterprise
		// has no annual product by design). Fail loud instead of POSTing an
		// empty product_id (the gateway 400s anyway).
		return failure(
			req,
			501,
			"checkout_unconfigured",
			"checkout not configured for this tier",
		);
	}

	// Reuse the fail-loud resolver (throws in prod when NEXT_PUBLIC_GATEWAY_URL is
	// unset) instead of a silent `?? localhost` fallback — the localhost fallback
	// is what let a dropped env var reach Cloudflare as a `localhost` subrequest
	// (error 1003) instead of failing loud. Same helper the read path uses.
	const base = gatewayBaseUrl();
	// Pass explicit redirect targets. The gateway's own defaults point at
	// `/billing` (checkout.rs), but that route does not exist in this app — the
	// billing page is `/settings/billing`, so the gateway default would 404 the
	// customer AFTER a successful purchase. Derive from the request origin so
	// prod (app.tracelane.dev) and any *.tracelane.dev host resolve correctly and
	// pass the gateway's host allowlist.
	const origin = req.nextUrl.origin;
	const upstream = await fetch(`${base}/v1/billing/checkout`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${token}`,
		},
		body: JSON.stringify({
			product_id: productId,
			customer_email: email,
			success_url: `${origin}/settings/billing?status=success`,
			cancel_url: `${origin}/settings/billing?status=cancelled`,
		}),
	});

	if (!upstream.ok) {
		// Never propagate the upstream body — Polar/gateway error JSON can carry
		// request ids hinting at the org-scoped access token (mirror the portal
		// route's A3/A27 redaction).
		return failure(
			req,
			upstream.status >= 500 ? 502 : upstream.status,
			"checkout_unavailable",
			"checkout unavailable",
		);
	}

	const data = (await upstream.json()) as { url: string };
	// Defense-in-depth: only ever 302 to a Polar-hosted checkout page. The
	// gateway is trusted, but a regression there must not become an open
	// redirect here (2026-07-22 audit).
	let dest: URL;
	try {
		dest = new URL(data.url);
	} catch {
		return failure(req, 502, "checkout_unavailable", "checkout unavailable");
	}
	if (dest.hostname !== "polar.sh" && !dest.hostname.endsWith(".polar.sh")) {
		return failure(req, 502, "checkout_unavailable", "checkout unavailable");
	}
	// 302 to the Polar-hosted checkout; the browser follows to Polar's page.
	return NextResponse.redirect(dest, 302);
}
