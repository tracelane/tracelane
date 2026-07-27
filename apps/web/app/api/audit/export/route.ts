/**
 * GET /api/audit/export — download the COMPLETE audit ledger as NDJSON.
 *
 * Proxies GET /v1/audit/export on the gateway with the per-user WorkOS JWT (the
 * tenant is resolved from the token, never the request) and forwards NO `limit`,
 * so the gateway streams the ENTIRE chain uncapped (the in-browser render fetch
 * in `app/audit/page.tsx` caps separately at 1000 — this download does not). The
 * gateway response body is streamed straight through, so a million-row ledger
 * downloads without buffering the whole file in the worker.
 *
 * The Audit-SKU (f_audit_addon) entitlement is enforced by the gateway; a
 * non-entitled tenant gets the gateway's 403 here. `requireSession()` makes the
 * route unreachable anonymously.
 */

import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
	await requireSession();
	const { token } = await requireGatewayToken();

	const sp = req.nextUrl.searchParams;
	const g = new URLSearchParams();
	const since = sp.get("since");
	const until = sp.get("until");
	if (since) g.set("since", since);
	if (until) g.set("until", until);
	// Deliberately NO `limit` → the gateway streams the complete, uncapped ledger.

	const qs = g.toString();
	const url = `${gatewayBaseUrl()}/v1/audit/export${qs ? `?${qs}` : ""}`;
	let upstream: Response;
	try {
		upstream = await fetch(url, {
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
		});
	} catch {
		return NextResponse.json({ error: "gateway_unreachable" }, { status: 503 });
	}
	if (!upstream.ok || !upstream.body) {
		return NextResponse.json(
			{ error: "export_failed" },
			{ status: upstream.status >= 500 ? 502 : upstream.status || 502 },
		);
	}

	// Stream the gateway's NDJSON straight through — no `.text()` materialization,
	// so the complete ledger downloads without buffering it all in memory.
	return new NextResponse(upstream.body, {
		status: 200,
		headers: {
			"content-type": "application/x-ndjson",
			"content-disposition":
				'attachment; filename="tracelane-audit-evidence.ndjson"',
			"cache-control": "no-store",
		},
	});
}
