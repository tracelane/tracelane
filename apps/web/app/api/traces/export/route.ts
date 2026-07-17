/**
 * GET /api/traces/export — download the current filtered trace list as CSV/JSON.
 *
 * Proxies GET /v1/traces/export on the gateway with the per-user WorkOS JWT (the
 * tenant is resolved from the token, never the request). Receives the SAME page
 * filter params as /traces (status / model / range / min_latency_ms /
 * signature_id / sort / order) and translates them to the gateway's params — the
 * same mapping as `app/traces/page.tsx::buildQuery` — then streams the file back
 * with a
 * Content-Disposition so the browser downloads it.
 *
 * Defense-in-depth: requireSession() makes the route unreachable anonymously.
 */

import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

/**
 * range preset → RFC3339 lower bound (mirrors /traces buildQuery / rangeSince).
 * No range param defaults to 24h (the list's default window), so the export
 * matches what the user sees; explicit "all"/"" scans everything.
 */
function rangeSince(range: string | null): string | null {
	const r = range ?? "24h";
	const ms =
		r === "1h"
			? 3_600_000
			: r === "24h"
				? 86_400_000
				: r === "7d"
					? 604_800_000
					: r === "30d"
						? 2_592_000_000
						: 0; // "all" / "" / unknown → no lower bound
	return ms ? new Date(Date.now() - ms).toISOString() : null;
}

export async function GET(req: NextRequest) {
	await requireSession();
	const { token } = await requireGatewayToken();

	const sp = req.nextUrl.searchParams;
	const format = sp.get("format") === "json" ? "json" : "csv";

	// Page filters → gateway /v1/traces/export params (same mapping as the list).
	const g = new URLSearchParams();
	g.set("format", format);
	const model = sp.get("model");
	if (model) g.set("model", model);
	const minLat = sp.get("min_latency_ms");
	if (minLat) g.set("min_latency_ms", minLat);
	const sig = sp.get("signature_id");
	if (sig) g.set("signature_id", sig);
	const status = sp.get("status");
	if (status === "error") g.set("has_error", "true");
	else if (status === "ok") g.set("has_error", "false");
	const since = rangeSince(sp.get("range"));
	if (since) g.set("since", since);
	// Forward the active sort so the CSV matches what the user sees on /traces
	// (without this the gateway defaults to start_time DESC — a different set).
	const sort = sp.get("sort");
	if (sort) g.set("sort", sort);
	const order = sp.get("order");
	if (order) g.set("order", order);

	const url = `${gatewayBaseUrl()}/v1/traces/export?${g.toString()}`;
	let upstream: Response;
	try {
		upstream = await fetch(url, {
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
		});
	} catch (_err) {
		return NextResponse.json({ error: "gateway_unreachable" }, { status: 503 });
	}
	if (!upstream.ok) {
		return NextResponse.json(
			{ error: "export_failed" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	const body = await upstream.text();
	const filename = format === "json" ? "traces.json" : "traces.csv";
	const contentType =
		format === "json" ? "application/json" : "text/csv; charset=utf-8";
	return new NextResponse(body, {
		status: 200,
		headers: {
			"content-type": contentType,
			"content-disposition": `attachment; filename="${filename}"`,
		},
	});
}
