/**
 * EVL-29 — shared types and the error passthrough for the annotation-queue proxy.
 *
 * **This lives OUTSIDE `route.ts` because a Next.js route module may export ONLY
 * route fields.** Exporting the `passthrough` helper from `route.ts` for the
 * sub-routes to import compiled fine under `tsc --noEmit` and passed CI's web
 * typecheck, and then failed the real build with *"passthrough is not a valid
 * Route export field"*. Only `next build` enforces that constraint, so this file
 * is what keeps the helper shared without breaking it.
 *
 * As with the OBS-18 annotations proxy, this route re-validates NOTHING. One
 * validator, at the enforcement point: the gateway owns tenant resolution, the
 * role gate, the `f_annotation_queues` entitlement and the whole rubric schema.
 * A second copy here would drift, and the drift would be silent.
 *
 * Errors keep their status AND their body. That matters more here than
 * anywhere else in this feature: the gateway's 400s are *field-scoped*
 * (`{"error":"expected_output_field_not_usable","field":"...","message":"..."}`)
 * and the queue builder renders the message against the named field. Collapsing
 * them into a generic "couldn't save" would throw away the only thing that
 * tells the author which part of their rubric is wrong.
 */

import { GatewayError, gatewayGet, gatewayPost } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";

export type RubricFieldType =
	| "verdict"
	| "score"
	| "choice"
	| "text"
	| "boolean";

export type RubricField = {
	key: string;
	label: string;
	type: RubricFieldType;
	required: boolean;
	options?: string[];
	min?: number;
	max?: number;
};

export type QueueSource =
	| { kind: "online_eval_score"; max_score: number; rubric?: string }
	| { kind: "trace_error" }
	| { kind: "needs_review" };

export type AnnotationQueue = {
	id: string;
	name: string;
	filter: { source: QueueSource; window_hours: number };
	rubric: RubricField[];
	/** REQUIRED (R222) — every review through this queue lands here. */
	default_dataset_id: string;
	/** REQUIRED (R223) — the rubric key whose answer becomes expected_output. */
	expected_output_field: string;
	created_by: string;
	created_at: string;
	updated_at: string;
	archived_at?: string;
};

/** Pass a gateway error through with its meaning — and its `field` — intact. */
export function passthrough(err: unknown): NextResponse {
	if (err instanceof GatewayError) {
		if (err.status >= 500) {
			return NextResponse.json(
				{ error: "unavailable", reason: "gateway_unreachable" },
				{ status: 502 },
			);
		}
		// `err.body` carries the gateway's typed `{error, field, message}`.
		// Preferring it over `err.message` is what keeps a field-scoped
		// validation failure pointing at its field in the UI.
		const body = (err as { body?: unknown }).body ?? {
			error: err.message || "request_failed",
		};
		return NextResponse.json(body, { status: err.status });
	}
	throw err;
}
