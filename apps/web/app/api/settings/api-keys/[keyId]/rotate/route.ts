import { requireOrgAdmin } from "@/lib/admin-gate";
import { requireSession } from "@/lib/auth";
import { GatewayError, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

/** Rotate as the session's owner; the gateway owns the transaction and audit row. */
export async function POST(
	request: NextRequest,
	{ params }: { params: Promise<{ keyId: string }> },
): Promise<NextResponse> {
	const denied = await requireOrgAdmin(await requireSession());
	if (denied) return denied;
	const { keyId } = await params;
	let body: unknown;
	try {
		body = await request.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	if (
		!body ||
		typeof body !== "object" ||
		Array.isArray(body) ||
		Object.keys(body).some((k) => k !== "graceHours")
	) {
		return NextResponse.json(
			{ error: "expected only graceHours" },
			{ status: 400 },
		);
	}
	const graceHours = (body as { graceHours?: unknown }).graceHours;
	if (
		graceHours !== undefined &&
		(typeof graceHours !== "number" ||
			!Number.isSafeInteger(graceHours) ||
			graceHours < 0)
	) {
		return NextResponse.json(
			{ error: "graceHours must be a non-negative whole number" },
			{ status: 400 },
		);
	}
	try {
		const result = await gatewayPost(
			`/v1/keys/${encodeURIComponent(keyId)}/rotate`,
			graceHours === undefined ? {} : { grace_hours: graceHours },
		);
		return NextResponse.json(result, {
			status: 201,
			headers: { "Cache-Control": "no-store" },
		});
	} catch (error) {
		if (!(error instanceof GatewayError)) throw error;
		const clientError = error.status >= 400 && error.status < 500;
		return NextResponse.json(
			{ error: clientError ? error.message : "Could not rotate API key" },
			{ status: clientError ? error.status : 502 },
		);
	}
}
