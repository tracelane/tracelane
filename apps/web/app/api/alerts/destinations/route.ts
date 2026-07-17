/**
 * GET  /api/alerts/destinations  — list alert destinations for the tenant.
 * POST /api/alerts/destinations  — create a new webhook destination.
 *
 * Proxies to the Rust gateway `/v1/alerts/destinations`. Bearer JWT forwarded;
 * gateway derives tenant from it (ADR-042). URL must be https:// as enforced
 * by the gateway; we validate at the proxy layer too so the client gets an
 * immediately actionable 422 rather than waiting for the upstream round-trip.
 */

import { GatewayError, gatewayGet, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

const VALID_KINDS = new Set(["slack", "discord", "webhook"]);

export interface AlertDestination {
	id: string;
	name: string;
	kind: string;
	url: string;
}

interface AlertDestinationsResponse {
	destinations: AlertDestination[];
}

export async function GET(): Promise<NextResponse> {
	try {
		const data = await gatewayGet<AlertDestinationsResponse>(
			"/v1/alerts/destinations",
		);
		return NextResponse.json(data);
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 403) {
				return NextResponse.json(
					{ error: "alerts not enabled for this workspace" },
					{ status: 403 },
				);
			}
			return NextResponse.json(
				{ error: "failed to load alert destinations" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}

interface CreateDestinationBody {
	name: string;
	kind?: string;
	url: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	let body: CreateDestinationBody;
	try {
		body = (await req.json()) as CreateDestinationBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	const name = body.name?.trim();
	if (!name) {
		return NextResponse.json({ error: "name is required" }, { status: 422 });
	}
	if (body.kind !== undefined && !VALID_KINDS.has(body.kind)) {
		return NextResponse.json(
			{
				error: `kind must be one of: ${[...VALID_KINDS].join(", ")}`,
			},
			{ status: 422 },
		);
	}
	const url = body.url?.trim();
	if (!url || !url.startsWith("https://")) {
		return NextResponse.json(
			{ error: "url is required and must begin with https://" },
			{ status: 422 },
		);
	}

	try {
		const result = await gatewayPost<{ id: string }>(
			"/v1/alerts/destinations",
			{ name, kind: body.kind, url },
		);
		return NextResponse.json(result, { status: 201 });
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status === 403) {
				return NextResponse.json(
					{ error: "alerts not enabled for this workspace" },
					{ status: 403 },
				);
			}
			if (err.status === 422) {
				return NextResponse.json(
					{ error: "invalid destination parameters" },
					{ status: 422 },
				);
			}
			return NextResponse.json(
				{ error: "failed to create alert destination" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}
