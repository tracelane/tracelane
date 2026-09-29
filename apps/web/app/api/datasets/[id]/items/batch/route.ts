import { gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { datasetError } from "../../../shared";

/**
 * `OBS-56` slice 4. Thin proxy — the gateway does the set-based span
 * resolution, the dedupe and the write; this re-validates nothing (spec §2).
 */
export async function POST(
	req: NextRequest,
	context: { params: Promise<{ id: string }> },
) {
	const { id } = await context.params;
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	try {
		return NextResponse.json(
			await gatewayPost(
				`/v1/datasets/${encodeURIComponent(id)}/items/batch`,
				body,
			),
		);
	} catch (err) {
		return datasetError(err);
	}
}
