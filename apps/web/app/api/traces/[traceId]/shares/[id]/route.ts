/**
 * OBS-48 — DELETE /api/traces/[traceId]/shares/[id] → revoke one share link.
 *
 * Thin proxy: the gateway sets `revoked_at` (soft; the row and its view_count
 * survive — see `db/migrations/0036_trace_shares.sql`) and answers 204. A 404
 * here means "not yours or already gone" and is preserved rather than
 * flattened, the same shape as the tool-pins unpin proxy.
 */

import { GatewayError, gatewayDelete } from "@/lib/gateway";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function DELETE(
	_req: Request,
	{ params }: { params: Promise<{ traceId: string; id: string }> },
): Promise<NextResponse> {
	const { traceId, id } = await params;

	try {
		await gatewayDelete(
			`/v1/traces/${encodeURIComponent(traceId)}/shares/${encodeURIComponent(id)}`,
		);
		return new NextResponse(null, { status: 204 });
	} catch (err) {
		if (err instanceof GatewayError) {
			return NextResponse.json(
				err.body ?? { error: err.message || "request_failed" },
				{ status: err.status },
			);
		}
		throw err;
	}
}
