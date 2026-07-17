/**
 *
 * Proxies DELETE /v1/prompts/{name} on the gateway, forwarding the per-user
 * WorkOS JWT so the gateway resolves the tenant from the token (never the body).
 * Deleting is Builder-allowed (the inverse of authoring); the gateway archives
 * the prompt and stops serving it. Returns the gateway status (204 on success).
 *
 * Defense-in-depth: requireSession() ensures this route is unreachable
 * anonymously even if the gateway JWT check is misconfigured.
 */

import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

interface Params {
	params: Promise<{ name: string }>;
}

export async function DELETE(_req: NextRequest, { params }: Params) {
	await requireSession();
	const { token } = await requireGatewayToken();

	const { name } = await params;
	const base = gatewayBaseUrl();
	const url = `${base}/v1/prompts/${encodeURIComponent(name)}`;

	let upstream: Response;
	try {
		upstream = await fetch(url, {
			method: "DELETE",
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
		});
	} catch (_err) {
		return new NextResponse(JSON.stringify({ error: "gateway_unreachable" }), {
			status: 503,
			headers: { "content-type": "application/json" },
		});
	}

	// 204 No Content has no body — pass the status straight through. On any other
	// status forward the gateway's (already safe/scrubbed) typed JSON body.
	if (upstream.status === 204) {
		return new NextResponse(null, { status: 204 });
	}
	const data = await upstream.text();
	return new NextResponse(data, {
		status: upstream.status,
		headers: { "content-type": "application/json" },
	});
}
