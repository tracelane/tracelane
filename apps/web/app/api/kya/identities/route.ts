import { forwardParams } from "@/lib/gateway";
import { readActivity } from "@/lib/kya/proxy";
import type { NextRequest } from "next/server";
export async function GET(req: NextRequest) {
	const qs = forwardParams(req.nextUrl.searchParams, ["kind", "window"]);
	return readActivity(`/v1/kya/identities?${qs}`);
}
