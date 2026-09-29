import { gatewayDelete, gatewayGet } from "@/lib/gateway";
import { NextResponse } from "next/server";
import { datasetError } from "../shared";

/**
 * `EVL-31` slice 1. Tombstone — snapshots and past experiment results survive
 * (the gateway's own invariant; nothing here changes it). There is no undelete
 * route, so the caller (the Codex-built confirm dialog, spec §4) is the only
 * place this is guarded before it fires.
 */
export async function DELETE(
	_req: Request,
	context: { params: Promise<{ id: string }> },
) {
	const { id } = await context.params;
	try {
		await gatewayDelete(`/v1/datasets/${encodeURIComponent(id)}`);
		return new NextResponse(null, { status: 204 });
	} catch (err) {
		return datasetError(err);
	}
}

export async function GET(
	_req: Request,
	context: { params: Promise<{ id: string }> },
) {
	const { id } = await context.params;
	try {
		return NextResponse.json(
			await gatewayGet(`/v1/datasets/${encodeURIComponent(id)}`),
			{ headers: { "cache-control": "no-store" } },
		);
	} catch (err) {
		return datasetError(err);
	}
}
