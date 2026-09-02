/**
 * GET /api/online-evals/scores?hours=24&limit=50[&trace_id=…] — recent scores.
 *
 * Thin proxy to the gateway `/v1/online-evals/scores`. `score` and `cost_usd`
 * arrive nullable and stay nullable: a judge whose response failed validation
 * has NO score, and an unpriced model has NO cost. Substituting 0 for either
 * would render a fabricated number in the one place a customer looks to decide
 * whether the judge is working.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export interface OnlineEvalScore {
	trace_id: string;
	span_id: string;
	rubric: string;
	judge_model: string;
	/** `scored` | `errored`. */
	status: string;
	score: number | null;
	verdict: string;
	reason: string;
	error: string | null;
	cost_usd: number | null;
	latency_ms: number;
	/** Millis since epoch, UTC. */
	scored_at: number;
}

export interface OnlineEvalScores {
	window_hours: number;
	scores: OnlineEvalScore[];
}

export async function GET(req: NextRequest): Promise<NextResponse> {
	const p = req.nextUrl.searchParams;
	const qs = new URLSearchParams({
		hours: p.get("hours") ?? "24",
		limit: p.get("limit") ?? "50",
	});
	const traceId = p.get("trace_id");
	if (traceId) qs.set("trace_id", traceId);
	try {
		return NextResponse.json(
			await gatewayGet<OnlineEvalScores>(`/v1/online-evals/scores?${qs}`),
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
				{ error: "failed to load online-eval scores" },
				{ status: 502 },
			);
		}
		throw err;
	}
}
