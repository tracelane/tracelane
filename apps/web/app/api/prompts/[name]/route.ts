/**
 * DELETE /api/prompts/[name] — soft-delete (archive) a prompt.
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

/**
 * GET /api/prompts/[name]?env=production|staging — the version currently routed
 * to that environment (EVL-02).
 *
 * Proxies `GET /v1/prompts/{name}` with `env` forwarded. The gateway resolves the
 * tenant from the token and answers **404 when nothing is routed to that env**,
 * which is a real answer and not an error: the create dialog turns it into
 * "promote a version to staging first", which is the action. Collapsing it into a
 * generic failure would send the user to debug the wrong thing.
 */
export async function GET(req: NextRequest, { params }: Params) {
	await requireSession();
	const { token } = await requireGatewayToken();

	const { name } = await params;
	const env = req.nextUrl.searchParams.get("env") ?? "production";
	const base = gatewayBaseUrl();
	const url = `${base}/v1/prompts/${encodeURIComponent(name)}?env=${encodeURIComponent(env)}`;

	let upstream: Response;
	try {
		upstream = await fetch(url, {
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
		});
	} catch (_err) {
		return new NextResponse(JSON.stringify({ error: "gateway_unreachable" }), {
			status: 503,
			headers: { "content-type": "application/json" },
		});
	}

	const data = await upstream.text();
	return new NextResponse(data, {
		status: upstream.status,
		headers: { "content-type": "application/json" },
	});
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
