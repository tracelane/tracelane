import { GatewayError } from "@/lib/gateway";
import { NextResponse } from "next/server";
export function datasetError(err: unknown): NextResponse {
	if (err instanceof GatewayError) {
		if (err.status >= 400 && err.status < 500)
			return NextResponse.json(
				err.body ?? { error: "request_refused", status: err.status },
				{ status: err.status },
			);
		return NextResponse.json(
			{
				error: "unavailable",
				message: "The gateway could not be reached. Try again.",
			},
			{ status: 502 },
		);
	}
	throw err;
}
