/**
 * Proxy for the observed-tools list (/B).
 *
 * The gateway owns the tenant-scoped read — the tenant comes from the WorkOS
 * JWT we forward, never from anything the browser sends.
 *
 * Status mapping is deliberate: a 403 from the gateway means the caller's role
 * cannot manage tool pins, and it is surfaced AS a 403 with a typed body.
 * Collapsing every non-ok upstream into one generic message is how an
 * owner-only surface previously showed "Failed to load" to a viewer, which
 * reads as a bug rather than a permission.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
	try {
		const rows = await gatewayGet<unknown[]>("/v1/guardrails/observed-tools");
		return NextResponse.json(rows);
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 403) {
				return NextResponse.json(
					{ error: "role_forbidden", required_role: "owner" },
					{ status: 403 },
				);
			}
			if (err.status === 503) {
				return NextResponse.json(
					{ error: "gateway_unavailable" },
					{ status: 503 },
				);
			}
			return NextResponse.json(
				{ error: "upstream_error", status: err.status },
				{ status: err.status },
			);
		}
		return NextResponse.json({ error: "unexpected" }, { status: 500 });
	}
}
