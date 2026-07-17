/**
 * Session-list and session-detail gateway reads.
 *
 * `fetchSessions` / `fetchSessionTraces` back the `/sessions` list and the
 * `/sessions/[sessionId]` detail page. Both go through `gatewayGet`
 * (`lib/gateway.ts`), which mints the *per-user* WorkOS access token via
 * `requireGatewayToken()` and forwards it as the Bearer. The gateway resolves
 * that JWT's `org_id` → internal tenant UUID (ADR-042) and binds it into
 * `WHERE tenant_id = ?`, so a user only ever sees their own tenant's sessions.
 *
 * only tenant signal. `GATEWAY_BEARER_TOKEN` is never read here.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";

/** A session summary as returned by `GET /v1/sessions` (gateway shape). */
export type SessionSummary = {
	session_id: string;
	turns: number;
	started_at: string;
	last_activity: string;
	duration_us: number;
	error_count: number;
	status: "ok" | "error";
	cost_usd: number;
	total_tokens: number;
	model: string;
};

/** A single trace row within a session, returned by `GET /v1/sessions/:id/traces`. */
export type SessionTraceRow = {
	trace_id: string;
	root_name: string;
	start_time: string;
	start_time_us: number;
	duration_us: number;
	span_count: number;
	error_count: number;
	model: string;
};

/**
 * Fetch recent sessions for the authenticated tenant.
 *
 * Routes through the per-user JWT (`gatewayGet`). A `GatewayError` yields `[]`
 * so the page renders its empty state rather than crashing. Any
 * non-`GatewayError` — notably the `NEXT_REDIRECT` thrown by
 * `requireGatewayToken` for an unauthenticated / org-less session — is
 * re-thrown, never swallowed (`lib/auth.ts` contract).
 *
 * @param opts.days  Look-back window in days forwarded to the gateway.
 * @param opts.limit Max sessions returned (forwarded to the gateway).
 */
export async function fetchSessions(opts?: {
	days?: number;
	limit?: number;
	/** RFC3339 lower bound (overrides `days`) — from the range control. */
	since?: string;
	/** Sort column: turns | cost | tokens | duration | (default) last-activity. */
	sort?: string;
	/** Sort direction: asc | desc. */
	order?: string;
	/** Status filter: error | ok. */
	status?: string;
	/** Response-model filter (exact). */
	model?: string;
}): Promise<SessionSummary[]> {
	const q = new URLSearchParams();
	if (opts?.limit !== undefined) q.set("limit", String(opts.limit));
	if (opts?.days !== undefined) q.set("days", String(opts.days));
	if (opts?.since) q.set("since", opts.since);
	if (opts?.sort) q.set("sort", opts.sort);
	if (opts?.order) q.set("order", opts.order);
	if (opts?.status) q.set("status", opts.status);
	if (opts?.model) q.set("model", opts.model);
	const qs = q.toString();
	try {
		const res = await gatewayGet<{ sessions: SessionSummary[] }>(
			`/v1/sessions${qs ? `?${qs}` : ""}`,
		);
		return res.sessions;
	} catch (err) {
		if (err instanceof GatewayError) return [];
		throw err;
	}
}

/**
 * Fetch the ordered trace list for a single session.
 *
 * Routes through the per-user JWT (`gatewayGet`). Returns `null` on any
 * `GatewayError` (including 404) — the page renders its not-found state. The
 * gateway returns the SAME 404 for "session missing" and "not this tenant's",
 * so existence never leaks across tenants. Any non-`GatewayError` (e.g.
 * `NEXT_REDIRECT`) propagates so the auth redirect is honored.
 *
 * @param sessionId  Raw session identifier. URL-encoded internally before use
 *                   in the gateway path.
 */
export async function fetchSessionTraces(
	sessionId: string,
): Promise<{ session_id: string; traces: SessionTraceRow[] } | null> {
	try {
		return await gatewayGet<{ session_id: string; traces: SessionTraceRow[] }>(
			`/v1/sessions/${encodeURIComponent(sessionId)}/traces`,
		);
	} catch (err) {
		if (err instanceof GatewayError) return null;
		throw err;
	}
}
