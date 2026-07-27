/**
 * Prompt gateway reads — list, version resolution, and history.
 *
 * `fetchPromptList` backs `/prompts` (the list page).
 * `fetchVersion` / `fetchHistory` back `/prompts/[name]` (the detail page).
 * All three go through `gatewayGet` (`lib/gateway.ts`), which mints the
 * *per-user* WorkOS access token via `requireGatewayToken()` and forwards it
 * as the Bearer. The gateway resolves that JWT's `org_id` → internal tenant
 * UUID (ADR-042) and binds it into `WHERE tenant_id = ?`, so a user only ever
 * sees their own tenant's prompts.
 *
 * The dashboard NEVER binds a tenant id itself; the JWT is the only tenant
 * signal.
 */

import { GatewayError, gatewayGet } from "@/lib/gateway";

/**
 * Summary row returned by `GET /v1/prompts` (gateway shape).
 *
 * `active` contains one entry per environment that currently has an active
 * version pointer. An empty `active` array means no version has been promoted
 * to any environment yet.
 */
export type PromptSummary = {
	name: string;
	prompt_id: string;
	/** Total count of authored versions (including unpromoted). */
	versions: number;
	/** Version number of the most recently authored version. */
	latest_version: number;
	/** Per-environment active version pointers. */
	active: { env: string; version_number: number }[];
	/** Unix epoch in milliseconds of the last write (author or promote). */
	updated_at_ms: number;
};

/** A prompt version resolved for a given environment (gateway shape). */
export type ResolvedVersion = {
	prompt_version_id: string;
	prompt_id: string;
	version_number: number;
	content: string;
	model_pin: string | null;
	sha256_hex: string;
};

export type EnvLabel = "production" | "staging" | "canary";
export const ENVS: ReadonlyArray<EnvLabel> = [
	"production",
	"staging",
	"canary",
];

/** A promotion or auto-rollback entry in a prompt's history (gateway shape). */
export type HistoryEntry =
	| {
			kind: "promotion";
			promotion_id: string;
			from_env: string;
			to_env: string;
			from_version_id: string | null;
			to_version_id: string;
			decision: string;
			notes: string;
			at_micros: number;
	  }
	| {
			kind: "rollback";
			rollback_id: string;
			from_version_id: string;
			to_version_id: string;
			trigger_metric: string;
			trigger_value: number;
			sigma_drift: number;
			rollback_mode: string;
			at_micros: number;
	  };

/**
 * Fetch the authenticated tenant's prompt list from `GET /v1/prompts`.
 *
 * Returns `null` when the gateway is unreachable (the caller shows an error
 * state rather than an empty state). Returns an empty array `[]` when the
 * gateway is reachable but the tenant has no prompts yet. Any
 * non-`GatewayError` — notably the `NEXT_REDIRECT` thrown by
 * `requireGatewayToken` for an unauthenticated / org-less session — is
 * re-thrown so the auth redirect is honored.
 */
export async function fetchPromptList(): Promise<PromptSummary[] | null> {
	try {
		return await gatewayGet<PromptSummary[]>("/v1/prompts");
	} catch (err) {
		if (err instanceof GatewayError) return null;
		throw err;
	}
}

/**
 * Resolve the active prompt version for `name` in `env`.
 *
 * Routes through the per-user JWT (`gatewayGet`). A gateway non-2xx becomes an
 * `{ error }` value so the page can render a per-env error card (the gateway
 * returns the SAME 404 for "no version in this env" and "not this tenant's", so
 * existence never leaks across tenants). Any non-`GatewayError` — notably the
 * `NEXT_REDIRECT` thrown by `requireGatewayToken` for an unauthenticated /
 * org-less session — is re-thrown, never swallowed (`lib/auth.ts` contract).
 */
export async function fetchVersion(
	name: string,
	env: EnvLabel,
): Promise<ResolvedVersion | { error: string }> {
	try {
		return await gatewayGet<ResolvedVersion>(
			`/v1/prompts/${encodeURIComponent(name)}?env=${env}`,
		);
	} catch (err) {
		if (err instanceof GatewayError) {
			return { error: `gateway responded ${err.status}` };
		}
		throw err;
	}
}

/**
 * Resolve recent promotion/rollback history for `name`.
 *
 * Routes through the per-user JWT (`gatewayGet`). History is best-effort: a
 * gateway non-2xx yields `[]` (the page shows its empty state rather than
 * blowing up). As in `fetchVersion`, a non-`GatewayError` (e.g. `NEXT_REDIRECT`)
 * propagates so the auth redirect is honored.
 */
export async function fetchHistory(
	name: string,
	limit = 50,
): Promise<HistoryEntry[]> {
	try {
		return await gatewayGet<HistoryEntry[]>(
			`/v1/prompts/${encodeURIComponent(name)}/history?limit=${limit}`,
		);
	} catch (err) {
		if (err instanceof GatewayError) return [];
		throw err;
	}
}
