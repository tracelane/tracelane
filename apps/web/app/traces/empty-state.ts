/**
 * Pure copy/classification helpers for `/traces`'s "no rows" and "the gateway
 * rejected the request" states, extracted from `page.tsx` so the OBS-01
 * distinction is unit-tested rather than only visible in a rendered RSC —
 * the same reason `filter-params.ts` exists as its own module.
 */

export interface EmptyCopy {
	title: string;
	description: string;
}

/**
 * The no-rows empty state once at least one filter is active (OBS-01 §2,
 * proof #3). A SEARCH returning zero rows names the term as the thing to
 * change, distinct from "no data matches these filters" — the range/model
 * copy is the wrong hint when the user just mistyped a search term.
 */
export function noMatchCopy(q: string | undefined): EmptyCopy {
	if (q) {
		return {
			title: `No traces match \`${q}\` in this window`,
			description: "Try a different term or widen the time range.",
		};
	}
	return {
		title: "No traces match these filters",
		description: "Try widening the time range or clearing the model filter.",
	};
}

/** The minimal shape of a `GatewayError` this module needs — never the class itself. */
export interface GatewayErrorLike {
	status: number;
	message: string;
	body: Record<string, unknown> | null;
}

export type TraceFetchFailure =
	// A REJECTED request — most commonly `?q=` forced below the gateway's
	// 4-char minimum, but any bad filter reads the same way.
	| { kind: "rejected"; message: string }
	// Transport failure / 5xx — genuinely "the gateway did not answer".
	| { kind: "unreachable" };

/**
 * Classify a `GatewayError` from `/v1/traces` (or `/v1/traces/count`).
 *
 * A 4xx is a validation failure, never "the gateway is down" — rendering the
 * warming banner for it would tell the user their gateway is unreachable
 * when it answered them perfectly correctly (CLAUDE.md §1, "error ≠ empty").
 */
export function classifyTraceFetchError(
	err: GatewayErrorLike,
): TraceFetchFailure {
	if (err.status >= 400 && err.status < 500) {
		const message = (err.body?.error as string | undefined) ?? err.message;
		return { kind: "rejected", message };
	}
	return { kind: "unreachable" };
}
