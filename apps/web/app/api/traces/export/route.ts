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

import { copyGatewayTraceFilters } from "@/app/traces/filter-registry";
import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { parseOptionalTimeRange, windowParams } from "@/lib/metrics/time-range";
import { type NextRequest, NextResponse } from "next/server";

/**
 * The export covers the SAME window the list shows — the shared grammar via
 * `tracesWindow` (`range=` preset, a custom `since/until` pair, or `all`). It used
 * to default to 24h while the list defaulted to 1h, so a default export covered
 * 24× the rows on screen (DSH-11 §3.1).
 */

export async function GET(req: NextRequest) {
	await requireSession();
	const { token } = await requireGatewayToken();

	const sp = req.nextUrl.searchParams;
	const format = sp.get("format") === "json" ? "json" : "csv";

	// Page filters → gateway /v1/traces/export params (same mapping as the list).
	const g = new URLSearchParams();
	g.set("format", format);
	copyGatewayTraceFilters(g, sp, "export");
	const w = parseOptionalTimeRange(
		{
			range: sp.get("range") ?? undefined,
			since: sp.get("since") ?? undefined,
			until: sp.get("until") ?? undefined,
		},
		{ defaultPreset: "1h", nowMs: Date.now() },
	);
	if (w) for (const [k, v] of windowParams(w)) g.set(k, v);

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
	const headers = new Headers({
		"content-type": contentType,
		"content-disposition": `attachment; filename="${filename}"`,
	});
	for (const name of [
		"x-tracelane-truncated",
		"x-tracelane-row-count",
		"x-tracelane-next-cursor",
	]) {
		const value = upstream.headers?.get(name);
		if (value) headers.set(name, value);
	}
	return new NextResponse(body, { status: 200, headers });
}
