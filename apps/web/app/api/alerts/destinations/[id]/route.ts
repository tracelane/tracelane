/**
 * DELETE /api/alerts/destinations/[id] — delete an alert destination.
 *
 * Proxies to the gateway `DELETE /v1/alerts/destinations/:id`. Bearer JWT
 * forwarded; the gateway derives tenant from the JWT and returns 404 if the
 * destination does not belong to this tenant. Upstream error bodies are not
 * echoed.
 */

import { requireGatewayToken } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { NextResponse } from "next/server";

export async function DELETE(
	_req: Request,
	{ params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	const { id } = await params;
	const base = gatewayBaseUrl();

	const upstream = await fetch(
		`${base}/v1/alerts/destinations/${encodeURIComponent(id)}`,
		{
			method: "DELETE",
			headers: { authorization: `Bearer ${token}` },
		},
	);

	if (!upstream.ok) {
		return NextResponse.json(
			{ error: "failed to delete alert destination" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	return new NextResponse(null, { status: 204 });
}
