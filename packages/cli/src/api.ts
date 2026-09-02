/**
 * The one HTTP layer for gateway-backed commands.
 *
 * ## Why non-ok is a RETURN and not a throw
 *
 * `prompt.ts` threw on every non-ok response, and the gateway answers a blocked
 * promotion with `409` carrying the whole decision object. So the code that
 * renders a blocked decision was unreachable, and the user got
 * `error: POST /v1/prompts/x/promote -> 409 Conflict: {"promotion_id":…}`.
 * The exit code was right and the message was a stack trace with JSON in it.
 *
 * A CI gate's entire user experience IS the message its pipeline fails with, so
 * the shape is `{ ok, status, body }` and the caller decides. Nothing here
 * turns a status into a verdict.
 */

import process from "node:process";

export interface ConnOpts {
	gateway: string;
	token: string;
}

export interface ApiResponse<T> {
	ok: boolean;
	status: number;
	/** Parsed JSON when the body was JSON, else the raw text under `raw`. */
	body: T | { raw: string };
}

/**
 * Resolve the connection, or exit 2.
 *
 * Token precedence is `--token` -> `TRACELANE_TOKEN` -> `TRACELANE_API_KEY`.
 * Both env names are already in use for the same secret across this CLI
 * (`prompt.ts` reads the first, `trace.ts` the second), and a CI gate is the
 * worst place for someone to discover that.
 */
export function resolveConn(opts: {
	gateway?: string;
	token?: string;
}): ConnOpts {
	const gateway =
		opts.gateway ??
		process.env.TRACELANE_GATEWAY_URL ??
		"https://gateway.tracelane.dev";
	const token =
		opts.token ??
		process.env.TRACELANE_TOKEN ??
		process.env.TRACELANE_API_KEY ??
		"";
	if (!token) {
		process.stderr.write(
			"tlane: no API token. Pass --token, or set TRACELANE_TOKEN " +
				"(TRACELANE_API_KEY is also accepted).\n",
		);
		process.exit(2);
	}
	return { gateway, token };
}

async function parse<T>(res: Response): Promise<ApiResponse<T>> {
	const text = await res.text().catch(() => "");
	let body: T | { raw: string };
	try {
		body = JSON.parse(text) as T;
	} catch {
		body = { raw: text };
	}
	return { ok: res.ok, status: res.status, body };
}

export async function apiGet<T>(
	conn: ConnOpts,
	path: string,
): Promise<ApiResponse<T>> {
	const res = await fetch(`${conn.gateway}${path}`, {
		headers: { authorization: `Bearer ${conn.token}` },
	});
	return parse<T>(res);
}

export async function apiPost<T>(
	conn: ConnOpts,
	path: string,
	body: unknown,
): Promise<ApiResponse<T>> {
	const res = await fetch(`${conn.gateway}${path}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${conn.token}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
	});
	return parse<T>(res);
}

/** The typed fields the gateway puts at the TOP level of an error body. */
interface GatewayError {
	error?: string;
	message?: string;
	required_scope?: string;
	required_role?: string;
	feature?: string;
	upgrade_url?: string;
}

/**
 * Render a non-ok response as lines a human can act on.
 *
 * The gateway unescapes `error` / `message` / `required_scope` /
 * `required_role` / `upgrade_url` at the top level deliberately, so a caller
 * can render the scope NAME rather than "403 Forbidden". `admin` is required to
 * START an eval run and `read` to POLL it, and scopes are a flat set with no
 * hierarchy - so a CI key needs BOTH, and a generic failure message is how
 * someone spends an afternoon on the wrong one.
 */
export function renderApiError(
	method: string,
	path: string,
	res: ApiResponse<unknown>,
): string[] {
	const b = res.body as GatewayError & { raw?: string };
	const lines = [`${method} ${path} -> ${res.status}`];
	if (b.message) lines.push(b.message);
	else if (b.error) lines.push(b.error);
	else if (b.raw) lines.push(b.raw.slice(0, 400));
	if (b.required_scope)
		lines.push(
			`required scope: ${b.required_scope}. Note scopes are a FLAT set - \`admin\` does not imply \`read\`, and a CI key needs both \`read\` and \`admin\`.`,
		);
	if (b.required_role) lines.push(`required role: ${b.required_role}`);
	if (b.feature) lines.push(`entitlement: ${b.feature}`);
	if (b.upgrade_url) lines.push(`upgrade: ${b.upgrade_url}`);
	return lines;
}
