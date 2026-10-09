import { forwardParams, gatewayResponse } from "@/lib/gateway";
import type { NextRequest } from "next/server";
export async function GET(
	req: NextRequest,
	ctx: { params: Promise<{ traceId: string }> },
) {
	const { traceId } = await ctx.params;
	const query = forwardParams(req.nextUrl.searchParams, ["format", "mode"]);
	return gatewayResponse(
		`/v1/traces/${encodeURIComponent(traceId)}/regression?${query}`,
	);
}
