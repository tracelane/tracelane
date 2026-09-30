import { GatewayError, forwardParams, gatewayGet } from "@/lib/gateway";
import type { IssueRollup } from "@/lib/generation-issues";
import { type NextRequest, NextResponse } from "next/server";
export async function GET(req: NextRequest) {
	const qs = forwardParams(req.nextUrl.searchParams, ["trace_ids"]);
	try {
		return NextResponse.json(
			await gatewayGet<IssueRollup>(`/v1/traces/issues/rollup?${qs}`),
		);
	} catch (error) {
		if (error instanceof GatewayError)
			return NextResponse.json(
				{ error: "generation_issues_unavailable" },
				{ status: error.status >= 500 ? 502 : error.status },
			);
		throw error;
	}
}
