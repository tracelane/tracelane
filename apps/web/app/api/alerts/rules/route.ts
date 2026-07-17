/**
 * GET  /api/alerts/rules  — list alert rules for the authenticated tenant.
 * POST /api/alerts/rules  — create a new alert rule.
 *
 * Thin proxy to the Rust gateway `/v1/alerts/rules`. The WorkOS JWT is
 * forwarded as Bearer; the gateway resolves org_id → internal tenant UUID
 * (ADR-042). Tenant identity comes exclusively from the JWT — never from
 * the request body or URL. The gateway returns 403 if the `f_alerts`
 * entitlement is not granted for the workspace.
 */

import { GatewayError, gatewayGet, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

const VALID_METRICS = new Set([
	"error_rate",
	"burn_rate",
	"latency_p95",
	"cost_usd",
	"quota_pct",
]);

const VALID_COMPARATORS = new Set(["gt", "lt"]);

export interface AlertRule {
	id: string;
	metric: string;
	comparator: string;
	threshold: number;
	window_minutes: number;
	destination_id: string;
	enabled: boolean;
	last_state: string | null;
}

interface AlertRulesResponse {
	rules: AlertRule[];
}

export async function GET(): Promise<NextResponse> {
	try {
		const data = await gatewayGet<AlertRulesResponse>("/v1/alerts/rules");
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
				{ error: "failed to load alert rules" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		// NEXT_REDIRECT from requireGatewayToken must propagate untouched.
		throw err;
	}
}

interface CreateRuleBody {
	metric: string;
	comparator?: string;
	threshold: number;
	window_minutes?: number;
	destination_id: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	let body: CreateRuleBody;
	try {
		body = (await req.json()) as CreateRuleBody;
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (!body.metric || !VALID_METRICS.has(body.metric)) {
		return NextResponse.json(
			{
				error: `metric must be one of: ${[...VALID_METRICS].join(", ")}`,
			},
			{ status: 422 },
		);
	}
	if (
		body.comparator !== undefined &&
		!VALID_COMPARATORS.has(body.comparator)
	) {
		return NextResponse.json(
			{ error: "comparator must be gt or lt" },
			{ status: 422 },
		);
	}
	if (typeof body.threshold !== "number") {
		return NextResponse.json(
			{ error: "threshold is required and must be a number" },
			{ status: 422 },
		);
	}
	if (!body.destination_id) {
		return NextResponse.json(
			{ error: "destination_id is required" },
			{ status: 422 },
		);
	}
	if (
		body.window_minutes !== undefined &&
		(body.window_minutes < 1 || body.window_minutes > 44640)
	) {
		return NextResponse.json(
			{ error: "window_minutes must be between 1 and 44640" },
			{ status: 422 },
		);
	}

	try {
		const result = await gatewayPost<{ id: string }>("/v1/alerts/rules", body);
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
					{ error: "invalid rule parameters" },
					{ status: 422 },
				);
			}
			return NextResponse.json(
				{ error: "failed to create alert rule" },
				{ status: err.status >= 500 ? 502 : err.status },
			);
		}
		throw err;
	}
}
