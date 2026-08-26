/**
 * `GET /api/experiments/{id}/compare?a=&b=` — EVL-02's deliverable, proxied.
 *
 * Same thin shape as `/api/traces/compare`. The gateway owns the alignment, the
 * verdicts and the thresholds; this route forwards and passes the status
 * through. A 404 (unknown experiment, or another tenant's — deliberately
 * identical) and a 409 (an arm is still running) are different answers and the
 * page renders each differently.
 */

import { GatewayError, forwardParams, gatewayGet } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import type { ExperimentCompareResponse } from "../../route";

export async function GET(
	req: NextRequest,
	{ params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
	const { id } = await params;
	const qs = forwardParams(req.nextUrl.searchParams, ["a", "b"]);
	if (!qs.get("a") || !qs.get("b")) {
		return NextResponse.json(
			{ error: "both a and b are required" },
			{ status: 400 },
		);
	}
	try {
		const data = await gatewayGet<ExperimentCompareResponse>(
			`/v1/experiments/${encodeURIComponent(id)}/compare?${qs.toString()}`,
		);
		return NextResponse.json(data);
	} catch (err) {
		if (err instanceof GatewayError) {
			return NextResponse.json(
				err.status >= 500
					? { error: "unavailable", reason: "gateway_unreachable" }
					: { error: "compare_failed", status: err.status },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}
