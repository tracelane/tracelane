import { forwardParams } from "@/lib/gateway";
import { readActivity } from "@/lib/kya/proxy";
import { type NextRequest, NextResponse } from "next/server";
export async function GET(
	req: NextRequest,
	{ params }: { params: Promise<{ kind: string; key: string }> },
) {
	const { kind, key } = await params;
	if (kind !== "agent" && kind !== "model")
		return NextResponse.json({ error: "invalid_kind" }, { status: 400 });
	const qs = forwardParams(req.nextUrl.searchParams, ["window"]);
	return readActivity(
		`/v1/kya/identities/${kind}/${encodeURIComponent(key)}?${qs}`,
	);
}
