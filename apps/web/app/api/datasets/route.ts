import { forwardParams, gatewayGet, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { datasetError } from "./shared";
export async function GET(req: NextRequest) {
	const qs = forwardParams(req.nextUrl.searchParams, ["limit", "cursor"]);
	try {
		return NextResponse.json(await gatewayGet(`/v1/datasets?${qs}`));
	} catch (err) {
		return datasetError(err);
	}
}
export async function POST(req: NextRequest) {
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid_json" }, { status: 400 });
	}
	try {
		return NextResponse.json(await gatewayPost("/v1/datasets", body), {
			status: 201,
		});
	} catch (err) {
		return datasetError(err);
	}
}
