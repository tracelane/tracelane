/**
 * POST /api/alerts/test — send a test alert to a webhook destination.
 *
 * Proxies to the gateway `POST /v1/alerts/test`, which fires a test payload
 * to the destination's webhook URL and returns `{status: "sent"}` on 202.
 * The gateway returns 404 if the destination does not belong to this tenant.
 * Bearer JWT forwarded; tenant is never taken from the request body.
 */

import { GatewayError, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

interface TestBody {
	destination_id: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	let body: TestBody;
	try {
		body = (await req.json()) as TestBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (!body.destination_id) {
		return NextResponse.json(
			{ error: "destination_id is required" },
			{ status: 422 },
		);
	}

	try {
		const result = await gatewayPost<{ status: string }>("/v1/alerts/test", {
			destination_id: body.destination_id,
		});
		return NextResponse.json(result, { status: 202 });
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 403) {
				return NextResponse.json(
					{ error: "alerts not enabled for this workspace" },
					{ status: 403 },
				);
			}
			if (err.status === 404) {
				return NextResponse.json(
					{ error: "destination not found" },
					{ status: 404 },
				);
			}
			return NextResponse.json(
				{ error: "test alert could not be sent" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}
