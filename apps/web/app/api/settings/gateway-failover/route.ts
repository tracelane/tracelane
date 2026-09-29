/**
 * GWY-52 — the workspace's own failover (`specs/GWY-52-workspace-failover.md`).
 * GET → {enabled, models:[{model, provider}], max, can_edit} · PUT {enabled, models}.
 * Thin proxy to the gateway's owner-gated `/v1/gateway/failover`; our own typed refusal
 * codes pass through for the form, everything else is masked.
 */
import { requireGatewayToken } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

const PASS_THROUGH = new Set([400, 404, 409, 503]);

async function relay(upstream: Response): Promise<NextResponse> {
	if (upstream.ok) return NextResponse.json(await upstream.json());
	const body = (await upstream.json().catch(() => ({}))) as {
		error?: unknown;
		message?: unknown;
		required_role?: unknown;
	};
	if (upstream.status === 403) {
		return NextResponse.json(
			{
				error: "role_forbidden",
				required_role:
					typeof body.required_role === "string" ? body.required_role : "owner",
			},
			{ status: 403 },
		);
	}
	if (PASS_THROUGH.has(upstream.status)) {
		return NextResponse.json(
			{
				error: typeof body.error === "string" ? body.error : "request_failed",
				message: typeof body.message === "string" ? body.message : undefined,
			},
			{ status: upstream.status },
		);
	}
	return NextResponse.json(
		{ error: "failover settings unavailable" },
		{ status: upstream.status >= 500 ? 502 : upstream.status },
	);
}

export async function GET(): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	return relay(
		await fetch(`${gatewayBaseUrl()}/v1/gateway/failover`, {
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
		}),
	);
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	let body: { enabled?: unknown; models?: unknown };
	try {
		body = (await req.json()) as typeof body;
	} catch {
		return NextResponse.json({ error: "invalid_body" }, { status: 400 });
	}
	if (typeof body.enabled !== "boolean") {
		return NextResponse.json({ error: "invalid_body" }, { status: 400 });
	}
	const models = Array.isArray(body.models)
		? body.models.filter((m): m is string => typeof m === "string")
		: [];
	return relay(
		await fetch(`${gatewayBaseUrl()}/v1/gateway/failover`, {
			method: "PUT",
			headers: {
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
			},
			body: JSON.stringify({ enabled: body.enabled, models }),
			cache: "no-store",
		}),
	);
}
