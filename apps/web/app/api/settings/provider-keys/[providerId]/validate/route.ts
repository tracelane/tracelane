import { requireGatewayToken } from "@/lib/auth";
import { gatewayBaseUrl } from "@/lib/gateway";
import { NextResponse } from "next/server";

export async function POST(
	_req: Request,
	{ params }: { params: Promise<{ providerId: string }> },
): Promise<NextResponse> {
	const { token } = await requireGatewayToken();
	const { providerId } = await params;
	const response = await fetch(
		`${gatewayBaseUrl()}/v1/provider-keys/${encodeURIComponent(providerId)}/validate`,
		{
			method: "POST",
			headers: { authorization: `Bearer ${token}` },
			cache: "no-store",
		},
	);
	if (!response.ok) {
		const error =
			response.status === 403
				? "A workspace owner must validate this key"
				: response.status === 404
					? "Provider key not found"
					: response.status === 409
						? "The key changed during validation. Try again."
						: "Could not validate this key";
		return NextResponse.json(
			{ error },
			{ status: response.status >= 500 ? 502 : response.status },
		);
	}
	return NextResponse.json(await response.json(), {
		headers: { "Cache-Control": "no-store" },
	});
}
