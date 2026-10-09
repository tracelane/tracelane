/**
 * DELETE /api/settings/provider-keys/[providerId] — revoke (delete) the
 * tenant's stored LLM provider key for one provider.
 *
 * Proxies to the gateway's `DELETE /v1/byok/provider-keys/:provider_id`. The
 * WorkOS access token is forwarded as Bearer; the gateway derives the tenant
 * from the JWT (never the URL) and bridges `org_id` → tenant UUID. Upstream
 * error bodies are not echoed.
 */

import { gatewayResponse } from "@/lib/gateway";
import { NextResponse } from "next/server";

export async function DELETE(
	req: Request,
	{ params }: { params: Promise<{ providerId: string }> },
): Promise<NextResponse> {
	const { providerId } = await params;
	// OG-11: `?label=` names one key of the provider's pool; absent = `default`.
	const label = new URL(req.url).searchParams.get("label");
	const query = label ? `?label=${encodeURIComponent(label)}` : "";

	const upstream = await gatewayResponse(
		`/v1/byok/provider-keys/${encodeURIComponent(providerId)}${query}`,
		{ method: "DELETE" },
	);

	if (!upstream.ok) {
		// Owner-only gate (see the GET/POST route) — typed, not a generic failure.
		if (upstream.status === 403) {
			return NextResponse.json(
				{ error: "role_forbidden", required_role: "owner" },
				{ status: 403 },
			);
		}
		return NextResponse.json(
			{ error: "failed to revoke provider key" },
			{ status: upstream.status >= 500 ? 502 : upstream.status },
		);
	}

	return new NextResponse(null, { status: 204 });
}
