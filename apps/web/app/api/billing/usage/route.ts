/**
 * GET /api/billing/usage — current plan + Polar meter totals for the
 * authenticated tenant.
 *
 * Stripe direct calls are banned post Phase-2 (`.claude/rules/billing.md`).
 * The dashboard proxies through the Rust gateway, which holds the
 * `POLAR_ACCESS_TOKEN`. Meter readings come from
 * `crates/gateway/src/billing/polar_client.rs`'s `meter_events_summary`
 * endpoint (Polar's `/v1/meters/{id}/quantities`).
 *
 * If the gateway responds with no usage data (e.g. meter not configured
 * for the tenant), `usage` is null rather than failing the request.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

interface GatewayUsageResponse {
	tokens_processed?: number | null;
	audit_anchors?: number | null;
}

async function fetchMeterUsage(
	gatewayBase: string,
	authHeader: string | null,
): Promise<{
	tokens_processed: number | null;
	audit_anchors: number | null;
} | null> {
	try {
		const res = await fetch(`${gatewayBase}/v1/billing/usage`, {
			headers: authHeader ? { authorization: authHeader } : undefined,
		});
		if (!res.ok) return null;
		const body = (await res.json()) as GatewayUsageResponse;
		return {
			tokens_processed: body.tokens_processed ?? null,
			audit_anchors: body.audit_anchors ?? null,
		};
	} catch {
		return null;
	}
}

export async function GET(req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();

	const tenant = await db
		.select({
			plan: tenants.plan,
			auditEnabled: tenants.auditEnabled,
			polarCustomerId: tenants.polarCustomerId,
		})
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	if (!tenant[0]) {
		// No tenant row → treat as the unbilled default (A5): a missing tenant is
		// not a paying Builder. Consistent with tenants.plan DEFAULT 'free'.
		return NextResponse.json({
			plan: "free",
			auditEnabled: false,
			usage: null,
		});
	}

	const { plan, auditEnabled, polarCustomerId } = tenant[0];
	const gatewayBase =
		process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

	let usage: {
		tokens_processed: number | null;
		audit_anchors: number | null;
	} | null = null;
	if (polarCustomerId) {
		usage = await fetchMeterUsage(
			gatewayBase,
			req.headers.get("authorization"),
		);
	}

	return NextResponse.json({ plan, auditEnabled, usage });
}
