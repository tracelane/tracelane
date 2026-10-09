import { forwardParams, gatewayResponse } from "@/lib/gateway";
import type { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
	return gatewayResponse(
		`/v1/spend/spike-causes?${forwardParams(req.nextUrl.searchParams, ["bucket_start", "granularity", "by"])}`,
	);
}
