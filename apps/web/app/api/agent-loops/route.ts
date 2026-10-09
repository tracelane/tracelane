import { forwardParams, gatewayResponse } from "@/lib/gateway";
import type { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
	const qs = forwardParams(req.nextUrl.searchParams, [
		"trace_id",
		"session_id",
		"since",
		"until",
		"limit",
	]);
	return gatewayResponse(`/v1/agent-loops?${qs.toString()}`);
}
