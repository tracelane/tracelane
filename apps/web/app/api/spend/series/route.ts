import { forwardParams, gatewayResponse } from "@/lib/gateway";
import type { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
	return gatewayResponse(
		`/v1/spend/series?${forwardParams(req.nextUrl.searchParams, ["since", "until", "granularity"])}`,
	);
}
