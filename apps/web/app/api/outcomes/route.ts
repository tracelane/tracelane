import { forwardParams, gatewayResponse } from "@/lib/gateway";
import type { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
	const query = forwardParams(req.nextUrl.searchParams, [
		"subject",
		"subject_kind",
	]);
	return gatewayResponse(`/v1/outcomes?${query}`);
}
export async function POST(req: NextRequest) {
	const headers = new Headers({ "content-type": "application/json" });
	const key = req.headers.get("idempotency-key");
	if (key) headers.set("idempotency-key", key);
	return gatewayResponse("/v1/outcomes", {
		method: "POST",
		headers,
		body: await req.text(),
	});
}
