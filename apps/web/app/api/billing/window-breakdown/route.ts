/**
 * GET /api/billing/window-breakdown?by=project|service|capture|shape —
 * proxies `GET /v1/billing/window-breakdown` (spec `BILL-01` §2.6) — the
 * "what's using your window" panel. A SEPARATE on-demand call from
 * `/api/billing/usage` (spec §2.5b lists it as its own gateway round trip):
 * it only fires when the customer opens/changes the breakdown, never on the
 * page's initial load.
 */

import { requireGatewayToken } from "@/lib/auth";
import type { GatewayWindowBreakdownResponse } from "@/lib/billing-usage";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

const VALID_BY = new Set(["project", "service", "capture", "shape"]);

export async function GET(req: NextRequest): Promise<NextResponse> {
	const by = req.nextUrl.searchParams.get("by") ?? "project";
	if (!VALID_BY.has(by)) {
		return NextResponse.json(
			{ error: "invalid 'by' dimension" },
			{ status: 400 },
		);
	}

	const { token } = await requireGatewayToken();
	const base = gatewayBaseUrl();

	try {
		const upstream = await fetch(
			`${base}/v1/billing/window-breakdown?by=${encodeURIComponent(by)}`,
			{ headers: { authorization: `Bearer ${token}` } },
		);
		if (!upstream.ok) {
			return NextResponse.json(
				{ error: "window breakdown unavailable" },
				{ status: upstream.status >= 500 ? 502 : upstream.status },
			);
		}
		const body = (await upstream.json()) as GatewayWindowBreakdownResponse;
		return NextResponse.json(body);
	} catch {
		return NextResponse.json(
			{ error: "window breakdown unavailable" },
			{ status: 502 },
		);
	}
}
