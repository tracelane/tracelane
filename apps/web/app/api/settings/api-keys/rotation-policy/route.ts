import { requireSession } from "@/lib/auth";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { NextResponse } from "next/server";

export async function GET(): Promise<NextResponse> {
	await requireSession();
	try {
		return NextResponse.json(await gatewayGet("/v1/keys/rotation-policy"), {
			headers: { "Cache-Control": "no-store" },
		});
	} catch (error) {
		if (!(error instanceof GatewayError)) throw error;
		const clientError = error.status >= 400 && error.status < 500;
		return NextResponse.json(
			{ error: clientError ? error.message : "Rotation policy is unavailable" },
			{ status: clientError ? error.status : 502 },
		);
	}
}
