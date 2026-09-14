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
 *  posture: the dashboard NEVER binds a tenant id itself; the JWT is the
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
	/**
	 * PLT-46: the `gen_ai.agent.name` of the session's most recent span (e.g.
	 * `"claude-code"`), empty string when no span carried one. Optional
	 * because the gateway is gaining this column separately (Rust,
	 * `trace_reads.rs`'s session SELECT) — a dashboard build must not assume
	 * it has already deployed. Absent or `""` both mean "no agent name";
	 * `apps/web/components/sessions/SessionRow.tsx`'s `SessionRow` renders
	 * nothing for either, and only shows the chip when the value is a
	 * non-empty string.
	 */
	agent_name?: string;
	/**
	 * OBS-20: the customer's own END USER — who initiated this conversation.
	 *
	 * Optional for the same deploy-ordering reason as `agent_name` above: the
	 * gateway gains this column in its own release, and a dashboard build must
	 * not assume it has already shipped.
	 *
	 * THREE values, and they are NOT interchangeable:
	 *   - absent or `""` — nobody sent one. Expected for any tenant that has not
	 *     instrumented it, including a correctly deployed one.
	 *   - a real id — render it.
	 *   - the literal `"[REDACTED:email]"` — the customer sent an email address
	 *     and ingest's PII redaction removed it before storage. Rendering this
	 *     raw, or as blank, both read as a bug; `SessionRow` renders an explained
	 *     "redacted" chip instead.
	 */
	end_user?: string;
};

// OBS-20: `REDACTED_END_USER` lives in `@/lib/end-user` — a module with no
// imports — because render-tested components need it and this file reaches
// authkit. Re-exported here so callers that already import from `lib/sessions`
// need not know that.
export { REDACTED_END_USER } from "@/lib/end-user";

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

// `fetchSessions` (a `days=`/`since=` reader) lived here until DSH-11; the list
// now reads through `lib/metrics/fetch.ts::fetchSessionsFor` with the shared
// window, and its tenant-isolation tests moved with it.

/**
 * Fetch the ordered trace list for a single session.
 *
 * Routes through the per-user JWT (`gatewayGet`). Returns `null` ONLY on a
 * **404** `GatewayError` — the page's `notFound()` is consistent with the
 * gateway's own choice to return the SAME 404 for "session missing" and "not
 * this tenant's", so existence never leaks across tenants.
 *
 * Any OTHER `GatewayError` (502 upstream failure, 401, a timeout collapsed to
 * 503 — see `gatewayGet`) re-throws rather than folding into `null`: a real
 * outage is not "this session does not exist", and letting it read as a 404
 * would tell the caller "not found" for a fact it never actually observed
 * (B-335d). It propagates to the nearest error boundary instead. A
 * non-`GatewayError` (e.g. `NEXT_REDIRECT`) also propagates so the auth
 * redirect is honored.
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
		if (err instanceof GatewayError && err.status === 404) return null;
		throw err;
	}
}
