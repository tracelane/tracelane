/** DSH-01 — mark one notification read. Proxy to the gateway. */

import { GatewayError, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export async function POST(
	_req: NextRequest,
	ctx: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
	const { id } = await ctx.params;
	try {
		await gatewayPost(`/v1/notifications/${encodeURIComponent(id)}/read`, {});
		return new NextResponse(null, { status: 204 });
	} catch (err) {
		if (err instanceof GatewayError) {
			// The gateway answers 404 for "no such id", "already read" and
			// "another tenant's" alike — one answer on purpose, so this cannot
			// become an existence oracle. Passed through unchanged.
			return NextResponse.json(
				{ error: "not_marked" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}
