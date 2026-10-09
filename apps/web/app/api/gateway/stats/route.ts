import { gatewayResponse } from "@/lib/gateway";
import { gatewayStatsProxyUrl } from "@/lib/metrics/gateway-stats-url";
import type { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
	return gatewayResponse(gatewayStatsProxyUrl(req.nextUrl.searchParams));
}
