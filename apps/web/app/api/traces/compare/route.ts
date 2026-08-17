/**
 * GET /api/traces/compare?a=&b= — OBS-10 side-by-side trace diff.
 *
 * Thin server-side proxy to the gateway `GET /v1/traces/compare`. As everywhere
 * else in this app, the gateway owns the ClickHouse read and resolves the tenant
 * from the forwarded Bearer token — the dashboard never touches ClickHouse and
 * never binds a tenant id into a query (apps/web/CLAUDE.md).
 *
 * A cross-tenant or unknown id comes back from the gateway as 404 with the SAME
 * body either way, and this route passes that through unchanged: telling the
 * caller WHICH side was missing would confirm the other id exists.
 */

import { GatewayError, forwardParams, gatewayGet } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export type ComparedSpan = {
	name: string;
	depth: number;
	ordinal: number;
	side: "both" | "only_a" | "only_b";
	a_span_id: string | null;
	b_span_id: string | null;
	a_duration_us: number | null;
	b_duration_us: number | null;
	delta_us: number | null;
	/** null when the A-side duration is 0 — never rendered as ∞ or a fake 0%. */
	delta_pct: number | null;
	slower: boolean;
};

export type ComparedTrace = {
	trace_id: string;
	span_count: number;
	/** Wall-clock extent, not the sum of span durations. */
	total_us: number;
};

export type TraceCompareResponse = {
	a: ComparedTrace;
	b: ComparedTrace;
	rows: ComparedSpan[];
	only_in_a: number;
	only_in_b: number;
	slower_count: number;
	threshold_us: number;
	threshold_pct: number;
};

export async function GET(req: NextRequest): Promise<NextResponse> {
	const qs = forwardParams(req.nextUrl.searchParams, ["a", "b"]);
	if (!qs.get("a") || !qs.get("b")) {
		return NextResponse.json(
			{ error: "both a and b are required" },
			{ status: 400 },
		);
	}

	try {
		const data = await gatewayGet<TraceCompareResponse>(
			`/v1/traces/compare?${qs.toString()}`,
		);
		return NextResponse.json(data);
	} catch (err) {
		if (err instanceof GatewayError) {
			// Pass 4xx through with its status — a 404 (unknown/cross-tenant id)
			// and a 403 (key lacks the `read` scope) are different answers and the
			// UI renders them differently. Collapsing every non-ok into one message
			// is the B-“role 403 as generic failure” shape.
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
