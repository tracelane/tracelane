import { ipFromRequest, recordAdminAction } from "@/lib/admin-audit";
import { requireGatewayToken, requireSession } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
type Params = { params: Promise<{ name: string }> };
async function mutate(req: NextRequest, { params }: Params) {
	const session = await requireSession();
	const { token } = await requireGatewayToken();
	const { name } = await params;
	let upstream: Response;
	try {
		upstream = await fetch(
			`${gatewayBaseUrl()}/v1/prompts/${encodeURIComponent(name)}/canary`,
			{
				method: req.method,
				headers: {
					authorization: `Bearer ${token}`,
					"content-type": "application/json",
				},
				body: req.method === "DELETE" ? undefined : await req.text(),
				cache: "no-store",
			},
		);
	} catch {
		return NextResponse.json(
			{
				error:
					"Gateway unavailable. Reload to check the saved state before retrying.",
			},
			{ status: 503 },
		);
	}
	const body = await upstream.text();
	if (upstream.status < 500)
		await recordAdminAction({
			actorUserId: session.userId,
			actorWorkspaceId: null,
			action: "prompt.canary",
			targetType: "prompt",
			targetId: name,
			afterJson: { method: req.method, status: upstream.status },
			ipAddr: ipFromRequest(req),
			userAgent: req.headers.get("user-agent"),
		});
	return new NextResponse(upstream.status === 204 ? null : body, {
		status: upstream.status,
		headers: { "content-type": "application/json" },
	});
}
export const PUT = mutate;
export const DELETE = mutate;
