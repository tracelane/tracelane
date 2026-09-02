/**
 * GET    /api/online-evals/policy — read this workspace's online-eval policy.
 * POST   /api/online-evals/policy — create or update it.
 * DELETE /api/online-evals/policy — disable it (the row and its salt survive).
 *
 * Thin proxy to the Rust gateway `/v1/online-evals/policy`. The WorkOS JWT is
 * forwarded as Bearer; the gateway resolves org_id → internal tenant UUID
 * (ADR-042) and owns every rule. Tenant identity is never in the body or URL.
 *
 * ── THE ONE THING THIS PROXY MUST NOT DO ────────────────────────────────────
 *
 * **It must not flatten the gateway's 400.** This is the surface where a policy
 * that spends money is created, and the gateway refuses with a NAMED reason —
 * `budget_required`, `invalid_sample_rate`, `unroutable_model`,
 * `unsupported_rubric_kind` — each carrying a `message` a human can act on.
 * Collapsing those into "failed to save" is the `role-403-as-generic-failure`
 * class: the discriminator the user needs is exactly the part thrown away.
 *
 * **So a 4xx is forwarded with its status and BOTH halves — but they are
 * swapped, and the swap is deliberate rather than clever.** `apiFetch` reads
 * exactly one field off an error body (`body.error`) and puts it in
 * `ApiError.message`; that is the string the form renders. Forwarding the
 * gateway body untouched would therefore paint the literal token
 * `budget_required` into the UI while the sentence explaining WHY there is no
 * default sat unread in a field nothing looks at — the same defect one layer
 * further out. So `error` carries the sentence and `code` carries the token,
 * and every other field (`feature`, `upgrade_url`, `required_role`) survives.
 * Adapting a body to the client that reads it is what a proxy is for.
 *
 * A body with no `message` (the `role_forbidden` shape) is forwarded unchanged
 * — there is nothing to swap, and inventing a sentence here would put copy the
 * gateway did not write in the gateway's mouth.
 *
 * It deliberately does NOT re-validate the rules here. A second copy of the
 * ceiling in TypeScript is a second thing to drift from the CHECK constraint;
 * the gateway is one hop away and already the authority.
 */

import { GatewayError, gatewayGet, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export interface OnlineEvalPolicy {
	id: string;
	enabled: boolean;
	rubric_kind: string;
	rubric: string;
	judge_model: string;
	sample_rate: number;
	judge_budget_usd_monthly: number;
	created_at: string;
	updated_at: string;
}

export interface PolicyEnvelope {
	policy: OnlineEvalPolicy | null;
	max_sample_rate: number;
	built_in_rubrics: string[];
}

/**
 * Pass a gateway refusal through with its own body and status.
 *
 * A 5xx is NOT passed through — an upstream stack detail is not something a
 * customer can act on, and it becomes a 502 with a flat message. A 4xx is the
 * user's own input being refused, and that message is the whole value.
 */
function passthrough(err: GatewayError, fallback: string): NextResponse {
	if (err.status >= 400 && err.status < 500) {
		const body = err.body ?? { error: "request_refused", message: err.message };
		const message = typeof body.message === "string" ? body.message : null;
		return NextResponse.json(
			message ? { ...body, error: message, code: body.error } : body,
			{ status: err.status },
		);
	}
	return NextResponse.json({ error: fallback }, { status: 502 });
}

export async function GET(): Promise<NextResponse> {
	try {
		return NextResponse.json(
			await gatewayGet<PolicyEnvelope>("/v1/online-evals/policy"),
		);
	} catch (err) {
		if (err instanceof GatewayError) {
			return passthrough(err, "failed to load the online-eval policy");
		}
		// NEXT_REDIRECT from requireGatewayToken must propagate untouched.
		throw err;
	}
}

export async function POST(req: NextRequest): Promise<NextResponse> {
	let body: unknown;
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}
	try {
		return NextResponse.json(
			await gatewayPost<OnlineEvalPolicy>("/v1/online-evals/policy", body),
		);
	} catch (err) {
		if (err instanceof GatewayError) {
			return passthrough(err, "failed to save the online-eval policy");
		}
		throw err;
	}
}

export async function DELETE(): Promise<NextResponse> {
	try {
		// `gatewayDelete` returns void; the gateway's body says whether a row
		// moved, which the UI does not branch on — a disable is idempotent.
		const { gatewayDelete } = await import("@/lib/gateway");
		await gatewayDelete("/v1/online-evals/policy");
		return NextResponse.json({ disabled: true });
	} catch (err) {
		if (err instanceof GatewayError) {
			return passthrough(err, "failed to disable online evals");
		}
		throw err;
	}
}
