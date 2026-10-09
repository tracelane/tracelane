/**
 * DELETE /api/alerts/rules/[id] — delete an alert rule.
 *
 * Proxies to the gateway `DELETE /v1/alerts/rules/:id`. The WorkOS JWT is
 * forwarded as Bearer; the gateway resolves tenant from the JWT and returns
 * 404 if the rule does not belong to this tenant (never cross-tenant leaks).
 * Upstream error bodies are never echoed.
 */

import { gatewayResponse } from "@/lib/gateway";
import { NextResponse } from "next/server";

export async function DELETE(
	_req: Request,
	{ params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
	const { id } = await params;

	const upstream = await gatewayResponse(
		`/v1/alerts/rules/${encodeURIComponent(id)}`,
		{ method: "DELETE" },
	);

	if (!upstream.ok) {
		return NextResponse.json(
			{ error: "failed to delete alert rule" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	return new NextResponse(null, { status: 204 });
}
