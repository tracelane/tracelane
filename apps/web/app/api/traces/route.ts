/**
 * GET /api/traces — list recent traces for the authenticated tenant.
 *
 * The gateway owns the ClickHouse read and resolves the tenant from the
 * forwarded Bearer token's claims — the dashboard never touches ClickHouse and
 * never binds a tenant id into a query.
 *
 * Query params (forwarded verbatim):
 *   limit, model, has_error ("true" | "false"), min_latency_ms, signature_id,
 *   cursor, since, until
 *
 * Returns JSON: { traces: TraceSummary[], next_cursor: string | null }
 */

import { GatewayError, forwardParams, gatewayGet } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

type TraceRow = {
	trace_id: string;
	root_name: string;
	start_time: string;
	duration_us: number;
	span_count: number;
	error_count: number;
	intervention: number;
	model: string;
};

type TraceListResponse = {
	traces: TraceRow[];
	next_cursor: string | null;
};

export async function GET(req: NextRequest): Promise<NextResponse> {
	const qs = forwardParams(req.nextUrl.searchParams, [
		"limit",
		"model",
		"has_error",
		"min_latency_ms",
		"signature_id",
		"cursor",
		"since",
		"until",
	]);

	try {
		const data = await gatewayGet<TraceListResponse>(
			`/v1/traces?${qs.toString()}`,
		);
		return NextResponse.json(data);
	} catch (err) {
		if (err instanceof GatewayError) {
			// 5xx / transport → 502 "unavailable"; pass through 4xx (e.g. 400).
			return NextResponse.json(
				{ error: "unavailable", reason: "gateway_unreachable" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}
