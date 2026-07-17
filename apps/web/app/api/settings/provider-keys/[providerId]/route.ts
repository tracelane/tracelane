/**
 * DELETE /api/settings/provider-keys/[providerId] — revoke (delete) the
 * tenant's stored LLM provider key for one provider.
 *
 * Proxies to the gateway's `DELETE /v1/byok/provider-keys/:provider_id`. The
 * WorkOS access token is forwarded as Bearer; the gateway derives the tenant
 * from the JWT (never the URL) and bridges `org_id` → tenant UUID. Upstream
 * error bodies are not echoed.
 */

import { requireGatewayToken } from "@/lib/auth";
import { NextResponse } from "next/server";

const GATEWAY = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";

export async function DELETE(
	_req: Request,
	{ params }: { params: Promise<{ providerId: string }> },
): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	const { providerId } = await params;

	const upstream = await fetch(
		`${GATEWAY}/v1/byok/provider-keys/${encodeURIComponent(providerId)}`,
		{
			method: "DELETE",
			headers: { authorization: `Bearer ${token}` },
		},
	);

	if (!upstream.ok) {
		return NextResponse.json(
			{ error: "failed to revoke provider key" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	return new NextResponse(null, { status: 204 });
}
