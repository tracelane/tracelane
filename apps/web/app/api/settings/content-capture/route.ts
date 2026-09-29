/**
 * GWY-53 — the workspace's content-capture opt-in
 * (`specs/GWY-53-self-serve-content-capture.md` §2.4).
 * GET → {input, output, operator_allowlisted, effective, queryable_days,
 *        max_field_bytes, updated_at, can_edit} · PUT {input, output} → the same + changed.
 * Thin proxy to the gateway's `/v1/workspace/capture`: the gateway owns the owner gate
 * and writes the change to the tamper-evident ledger. The tenant is the token's, never
 * the body's — only `input` and `output` are forwarded. Our own typed refusal codes
 * pass through (the toggle shows `audit_unavailable` by name); everything else is masked.
 */
import { requireGatewayToken } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

const PASS_THROUGH = new Set([400, 503]);

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
		{ error: "content capture setting unavailable" },
		{ status: upstream.status >= 500 ? 502 : upstream.status },
	);
}

export async function GET(): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	return relay(
		await fetch(`${gatewayBaseUrl()}/v1/workspace/capture`, {
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
		}),
	);
}

export async function PUT(req: NextRequest): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	let body: { input?: unknown; output?: unknown };
	try {
		body = (await req.json()) as typeof body;
	} catch {
		return NextResponse.json({ error: "invalid_body" }, { status: 400 });
	}
	if (typeof body.input !== "boolean" || typeof body.output !== "boolean") {
		return NextResponse.json({ error: "invalid_body" }, { status: 400 });
	}
	return relay(
		await fetch(`${gatewayBaseUrl()}/v1/workspace/capture`, {
			method: "PUT",
			headers: {
				authorization: `Bearer ${token}`,
				"content-type": "application/json",
			},
			body: JSON.stringify({ input: body.input, output: body.output }),
			cache: "no-store",
		}),
	);
}
