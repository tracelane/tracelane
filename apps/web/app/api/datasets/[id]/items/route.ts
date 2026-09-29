import { gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { datasetError } from "../../shared";
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
		const data = await gatewayPost<{ deduped?: boolean }>(
			`/v1/datasets/${encodeURIComponent(id)}/items`,
			body,
		);
		return NextResponse.json(data, { status: data.deduped ? 200 : 201 });
	} catch (err) {
		return datasetError(err);
	}
}
