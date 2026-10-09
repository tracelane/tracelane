import { gatewayResponse } from "@/lib/gateway";
export async function GET(
	_req: Request,
	ctx: { params: Promise<{ traceId: string }> },
) {
	const { traceId } = await ctx.params;
	return gatewayResponse(`/v1/traces/${encodeURIComponent(traceId)}/spans`);
}
