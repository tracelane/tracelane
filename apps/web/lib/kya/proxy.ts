import { GatewayError, gatewayGet } from "@/lib/gateway";
import { NextResponse } from "next/server";
import type { ActivityResponse } from "./types";
/** The gateway resolves tenancy and enforces the query window. */
export async function readActivity(path: string) {
	try {
		return NextResponse.json(await gatewayGet<ActivityResponse>(path));
	} catch (error) {
		if (!(error instanceof GatewayError)) throw error;
		return NextResponse.json(
			{ error: "activity_unavailable" },
			{ status: error.status >= 500 ? 502 : error.status },
		);
	}
}
