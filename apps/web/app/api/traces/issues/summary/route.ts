import { GatewayError, gatewayGet } from "@/lib/gateway";
import type { IssueSummary } from "@/lib/generation-issues";
import { NextResponse } from "next/server";

export async function GET() {
	try {
		return NextResponse.json(
			await gatewayGet<IssueSummary>("/v1/traces/issues/summary"),
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
