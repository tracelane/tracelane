/**
 * OBS-48 — trace share links. Thin proxy to the gateway.
 *
 * POST /api/traces/[traceId]/shares → mint a new public share link
 * GET  /api/traces/[traceId]/shares → list this trace's active links (owner view)
 *
 * The gateway owns the store, the tenant resolution, the mint/list logic, the
 * content denylist and the 10-active-links-per-trace cap. This route validates
 * NOTHING beyond the request shape — one validator, at the enforcement point.
 *
 * Gateway status + body pass through VERBATIM (spec §4): a 403 (role lacks
 * `read`) must read as "your role can't do this", not a generic failure, and a
 * 409 (over the 10-link cap) must carry the gateway's own message rather than
 * an invented one. Mirrors `app/api/traces/[traceId]/annotations/route.ts`.
 */

import { GatewayError, gatewayGet, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/** Owner-facing list row — no token (`GET /v1/traces/{id}/shares`). */
export type ShareLink = {
	id: string;
	created_at: string;
	expires_at: string;
	view_count: number;
};

/** Mint response — the RAW token is returned exactly once, here. */
export type ShareMintResult = {
	id: string;
	token: string;
	url: string;
	expires_at: string;
};

const ALLOWED_EXPIRY_DAYS = [7, 30, 90] as const;

/** Pass a gateway error through with its status AND body intact. */
function passthrough(err: unknown): NextResponse {
	if (err instanceof GatewayError) {
		return NextResponse.json(
			err.body ?? { error: err.message || "request_failed" },
			{ status: err.status },
		);
	}
	throw err;
}

export async function POST(
	req: NextRequest,
	ctx: { params: Promise<{ traceId: string }> },
): Promise<NextResponse> {
	const { traceId } = await ctx.params;

	let body: { expires_in_days?: number };
	try {
		body = await req.json();
	} catch {
		// No body at all is fine — the gateway default (30 days) applies.
		body = {};
	}

	// Default 30, per spec §2. Validated here so an invalid value never reaches
	// the gateway as a request the caller cannot make sense of.
	const expiresInDays = body.expires_in_days ?? 30;
	if (
		!ALLOWED_EXPIRY_DAYS.includes(
			expiresInDays as (typeof ALLOWED_EXPIRY_DAYS)[number],
		)
	) {
		return NextResponse.json(
			{ error: "expires_in_days must be 7, 30 or 90" },
			{ status: 400 },
		);
	}

	try {
		return NextResponse.json(
			await gatewayPost<ShareMintResult>(
				`/v1/traces/${encodeURIComponent(traceId)}/share`,
				{ expires_in_days: expiresInDays },
			),
		);
	} catch (err) {
		return passthrough(err);
	}
}

export async function GET(
	_req: NextRequest,
	ctx: { params: Promise<{ traceId: string }> },
): Promise<NextResponse> {
	const { traceId } = await ctx.params;
	try {
		return NextResponse.json(
			await gatewayGet<ShareLink[]>(
				`/v1/traces/${encodeURIComponent(traceId)}/shares`,
			),
		);
	} catch (err) {
		return passthrough(err);
	}
}
