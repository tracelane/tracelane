/**
 * POST /api/prompts/[name]/versions — author a new prompt version.
 *
 * Proxies `POST /v1/prompts/{name}/versions` on the gateway, forwarding the
 * per-user WorkOS JWT so the gateway resolves the tenant from the token (never
 * the body). Creating a new version is allowed for any authenticated tenant
 * (Builder and above); entitlement enforcement lives in the gateway.
 *
 * Request body forwarded to gateway:
 *   { content: string, model_pin?: string, template_variables?: string[] }
 *
 * Gateway returns 201:
 *   { prompt_version_id, prompt_id, version_number, content, model_pin, sha256_hex }
 *
 * Defense-in-depth: `requireSession()` ensures this route is unreachable
 * anonymously even if the gateway JWT check is misconfigured.
 */

import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

interface Params {
	params: Promise<{ name: string }>;
}

export async function POST(req: NextRequest, { params }: Params) {
	await requireSession();
	const { token } = await requireGatewayToken();

	const { name } = await params;
	const base = gatewayBaseUrl();
	const url = `${base}/v1/prompts/${encodeURIComponent(name)}/versions`;

	const body = await req.text();

	let upstream: Response;
	try {
		upstream = await fetch(url, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: `Bearer ${token}`,
			},
			body,
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
