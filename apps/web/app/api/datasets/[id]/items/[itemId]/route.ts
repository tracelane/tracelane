import { gatewayDelete, gatewayPatch } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { datasetError } from "../../../shared";

/**
 * `EVL-31` slice 1. `expected_output` and `metadata` only — `input` is
 * immutable at the gateway (`deny_unknown_fields` refuses an attempt to PATCH
 * it), so this proxy forwards the body verbatim and lets the gateway's own
 * refusal carry the reason.
 */
export async function PATCH(
	req: NextRequest,
	context: { params: Promise<{ id: string; itemId: string }> },
) {
	const { id, itemId } = await context.params;
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	try {
		await gatewayPatch(
			`/v1/datasets/${encodeURIComponent(id)}/items/${encodeURIComponent(itemId)}`,
			body,
		);
		return new NextResponse(null, { status: 204 });
	} catch (err) {
		return datasetError(err);
	}
}

/** Tombstone. Never touches a frozen snapshot copy — the gateway's own invariant. */
export async function DELETE(
	_req: NextRequest,
	context: { params: Promise<{ id: string; itemId: string }> },
) {
	const { id, itemId } = await context.params;
	try {
		await gatewayDelete(
			`/v1/datasets/${encodeURIComponent(id)}/items/${encodeURIComponent(itemId)}`,
		);
		return new NextResponse(null, { status: 204 });
	} catch (err) {
		return datasetError(err);
	}
}
