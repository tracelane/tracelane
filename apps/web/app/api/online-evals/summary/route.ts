/**
 * GET /api/online-evals/summary?hours=24 — the numbers the settings surface
 * renders. Thin proxy to the gateway `/v1/online-evals/summary`.
 *
 * Every field is passed through UNCHANGED, and the `null`s are the point: the
 * gateway distinguishes "we measured zero" from "we could not measure", and a
 * proxy that coalesced a `null` to `0` here would destroy exactly that
 * distinction one hop before the surface that exists to show it.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export interface OnlineEvalSummary {
	window_hours: number;
	configured_sample_rate: number | null;
	enabled: boolean;
	/** `null` = nothing was eligible, so there is no rate to state. NEVER 0. */
	achieved_sample_rate: number | null;
	eligible_spans: number;
	sampled_traces: number;
	scored: number;
	errored: number;
	mean_score: number | null;
	judge_cost_usd: number | null;
	judge_budget_usd_monthly: number | null;
}

export async function GET(req: NextRequest): Promise<NextResponse> {
	const hours = req.nextUrl.searchParams.get("hours") ?? "24";
	try {
		return NextResponse.json(
			await gatewayGet<OnlineEvalSummary>(
				`/v1/online-evals/summary?hours=${encodeURIComponent(hours)}`,
			),
		);
	} catch (err) {
		if (err instanceof GatewayError) {
			if (err.status >= 400 && err.status < 500) {
				return NextResponse.json(
					err.body ?? { error: "request_refused", message: err.message },
					{ status: err.status },
				);
			}
			return NextResponse.json(
				{ error: "failed to load the online-eval summary" },
				{ status: 502 },
			);
		}
		throw err;
	}
}
