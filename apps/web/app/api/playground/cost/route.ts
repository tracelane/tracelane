/**
 * GET /api/playground/cost?trace=<id> — poll one playground run's cost
 * (`specs/EVL-03-playground-v2-and-open-in-playground.md` §2/§3, table row 3).
 *
 * The playground NEVER computes its own cost. This reads whatever
 * `gen_ai_usage_cost` the gateway already recorded on the run's `gen_ai.chat`
 * span (`crates/gateway/src/server/spans.rs:975,1015-1026`) — provider-reported
 * cost, or the price-catalog derivation, or absent for an unpriced model
 * (ADR-055: the gateway never fabricates a cost).
 *
 * Tenant isolation is inherited, not re-implemented: `GET /v1/traces/{id}/spans`
 * binds `tenant_id` from the caller's own JWT first
 * (`crates/gateway/src/trace_reads.rs:2393-2400`) and 404s a trace that does
 * not belong to this tenant — the same call `lib/playground-prefill.ts`'s
 * caller uses, and the same route `gatewayGetOrNull` already mints a token for.
 */
import { GatewayError, gatewayGetOrNull } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

interface SpanRow {
	name: string;
	attributes: string;
}

type PlaygroundCostResponse =
	| { state: "pending" }
	| { state: "unpriced" }
	| { state: "priced"; cost_usd: number };

export async function GET(req: NextRequest): Promise<NextResponse> {
	const traceId = req.nextUrl.searchParams.get("trace")?.trim();
	if (!traceId) {
		return NextResponse.json({ error: "trace_required" }, { status: 400 });
	}

	let spans: SpanRow[] | null;
	try {
		spans = await gatewayGetOrNull<SpanRow[]>(
			`/v1/traces/${encodeURIComponent(traceId)}/spans`,
		);
	} catch (err) {
		if (err instanceof GatewayError) {
			return NextResponse.json(
				err.body ?? { error: err.message || "request_failed" },
				{ status: err.status },
			);
		}
		throw err;
	}

	// A brand-new run has not landed in ClickHouse yet — that is "pending", the
	// same honest state as the span not having arrived at all (§4: "recording…").
	const chatSpan = spans?.find((s) => s.name === "gen_ai.chat");
	if (!chatSpan) {
		return NextResponse.json({
			state: "pending",
		} satisfies PlaygroundCostResponse);
	}

	let attrs: Record<string, unknown> = {};
	try {
		const parsed: unknown = JSON.parse(chatSpan.attributes);
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			attrs = parsed as Record<string, unknown>;
		}
	} catch {
		// Unparsable attributes reads as unpriced, never a fabricated $0.00.
	}

	const cost = attrs.gen_ai_usage_cost;
	if (typeof cost === "number" && Number.isFinite(cost)) {
		return NextResponse.json({
			state: "priced",
			cost_usd: cost,
		} satisfies PlaygroundCostResponse);
	}
	return NextResponse.json({
		state: "unpriced",
	} satisfies PlaygroundCostResponse);
}
