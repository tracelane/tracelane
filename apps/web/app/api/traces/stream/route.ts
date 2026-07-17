/**
 * GET /api/traces/stream — FT-07 deadline-bounded trace summaries over SSE.
 *
 * Streams recent trace summaries for the authenticated tenant with the
 * dashboard's 500ms degradation contract:
 *   - an immediate `partial` SSE frame (last-known-good / empty) so the UI
 *     paints inside the p95 budget even when the upstream is slow, then
 *   - a `full` frame with fresh rows when the read completes (budget 3s),
 *   - or an `error` frame if the read fails.
 *
 * `GET /v1/traces` — NOT a direct ClickHouse query from the edge. The gateway
 * resolves the tenant from the forwarded Bearer token; this route never binds a
 * tenant id into a query. The cache key is the WorkOS org id (a stable
 * per-tenant discriminator, not a query filter).
 */

import { requireGatewayToken } from "@/lib/auth";
import { forwardParams, gatewayGet } from "@/lib/gateway";
import { streamQueryWithDeadline } from "@/lib/query-deadline";
import type { NextRequest } from "next/server";

// SSE must not be statically cached or buffered.
export const dynamic = "force-dynamic";

type TraceSummary = {
	trace_id: string;
	root_name: string;
	start_time: string;
	duration_us: number;
	span_count: number;
	error_count: number;
	intervention: number;
	model: string;
};

export async function GET(req: NextRequest): Promise<Response> {
	// Mint the session token (and get the org id for the cache key). The actual
	// read re-mints inside gatewayGet — withAuth is request-scoped so this is
	// cheap.
	const { tenantId } = await requireGatewayToken();

	// Forward the active dashboard filters so the live feed matches the filtered
	// list the user is looking at — never a silent filter mismatch. The gateway
	// owns the WHERE clause; we only pass the same allow-listed params the
	// `/api/traces` proxy does (limit is fixed at 100 for the live tail).
	const qs = forwardParams(req.nextUrl.searchParams, [
		"model",
		"has_error",
		"since",
		"until",
	]);
	qs.set("limit", "100");
	// Filters discriminate the last-known-good cache so a filtered stream never
	// serves another filter's cached rows.
	const filterSig = qs.toString();

	const stream = streamQueryWithDeadline<TraceSummary>(
		async () => {
			const data = await gatewayGet<{ traces: TraceSummary[] }>(
				`/v1/traces?${filterSig}`,
			);
			return data.traces;
		},
		{ cacheKey: `traces:${tenantId}:${filterSig}` },
	);

	return new Response(stream, {
		headers: {
			"Content-Type": "text/event-stream",
			"Cache-Control": "no-cache, no-transform",
			Connection: "keep-alive",
		},
	});
}
