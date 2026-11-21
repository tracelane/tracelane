/**
 * GET /api/settings/config-export — the workspace's control configuration as a JSON file.
 * A thin relay to the gateway's `GET /v1/config/export` with the signed-in user's token
 * (ADR-042: the dashboard reads only through gateway `/v1/*`). The tenant is the token's.
 *
 * Success keeps the document byte-for-byte (the button names the file); a refusal keeps its
 * status and the typed fields the button needs to word it — a 403 stays a 403, any other
 * upstream failure is masked as 502 (503 is kept: the gateway uses it for "try again").
 */
import { requireGatewayToken } from "@/lib/auth";
import { gatewayResponse } from "@/lib/gateway";
import { NextResponse } from "next/server";

const noStore = { "cache-control": "no-store" };

export async function GET(): Promise<NextResponse> {
	// Auth first: an unauthenticated caller is redirected before any gateway call.
	await requireGatewayToken();
	const upstream = await gatewayResponse("/v1/config/export");
	if (upstream.ok) {
		return new NextResponse(upstream.body, {
			status: 200,
			headers: { ...noStore, "content-type": "application/json" },
		});
	}
	const body = (await upstream.json().catch(() => ({}))) as {
		error?: unknown;
		message?: unknown;
	};
	if (upstream.status === 403 || upstream.status === 413) {
		return NextResponse.json(
			{ error: typeof body.error === "string" ? body.error : "forbidden" },
			{ status: upstream.status, headers: noStore },
		);
	}
	return NextResponse.json(
		{
			error:
				upstream.status === 503 && typeof body.error === "string"
					? body.error
					: "gateway_unavailable",
		},
		{ status: upstream.status === 503 ? 503 : 502, headers: noStore },
	);
}
