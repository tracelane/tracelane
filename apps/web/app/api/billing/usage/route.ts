/**
 * GET /api/billing/usage — a PURE PASSTHROUGH to `GET /v1/billing/usage`
 * (spec `BILL-01-metering-and-tiers.md` §2.6; gateway:
 * `crates/gateway/src/billing/usage.rs:110-181`).
 *
 * ONE gateway call per page load (§2.5b — "the usage page is ONE gateway
 * call per load"): this route makes exactly one upstream fetch and forwards
 * its body and status verbatim — no re-shaping, no `{plan, usage}` wrapper.
 * `lib/billing-usage.ts`'s `GatewayUsageResponse` is the pinned contract the
 * client parses; this route does not need to know its shape at all.
 *
 * The gateway itself resolves the tenant from the JWT and fails closed to
 * the Free-tier defaults for an unseeded tenant (`.claude/rules/
 * tenancy.md`), so this route does not pre-check Postgres for a tenant row —
 * that would be a second, redundant source of the same answer.
 *
 * A network failure (gateway unreachable) is the ONLY case this route
 * itself decides: it returns 502, which the client's `deriveUsageState`
 * reads as `httpOk: false` → the `"error"` state (the recorder never stops
 * on a metering outage — spec §4).
 */

import { requireGatewayToken } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { NextResponse } from "next/server";

export async function GET(): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();

	try {
		const upstream = await fetch(`${base}/v1/billing/usage`, {
			headers: { authorization: `Bearer ${token}` },
		});
		const body = await upstream.text();
		return new NextResponse(body, {
			status: upstream.status,
			headers: { "content-type": "application/json" },
		});
	} catch {
		// The recorder never stops on a metering outage — say so, don't 5xx.
		return NextResponse.json(
			{ error: "usage metering unavailable" },
			{ status: 502 },
		);
	}
}
