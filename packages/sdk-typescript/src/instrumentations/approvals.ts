/**
 * Pause, wait for a person's decision, resume. The gateway detects and holds a risky MCP tool
 * call; this module waits for the answer and retries the identical call. It decides nothing: a
 * retry without an approved row is held again by the gateway.
 *
 *   const h = isHeld(result);                       // HeldCall | null
 *   const d = await waitForDecision(h, { baseUrl, apiKey });
 *   // OpenAI Agents JS: tool({ ..., execute: withApproval(execute, { baseUrl, apiKey }) })
 *
 * Contract: crates/gateway/src/mcp_proxy.rs (legacy JSON-RPC text), mcp_protected.rs (409 body),
 * mcp_routes.rs (GET /v1/approvals/{id}). Global fetch only; no dependencies.
 */

export type Decision = "approved" | "denied" | "expired" | "timeout";
export interface HeldCall {
	approvalId: string;
	expiresAt: string | null;
	kind: "legacy" | "protected";
}
export interface WaitOptions {
	baseUrl: string;
	apiKey: string;
	timeoutMs?: number;
	pollMs?: number;
	maxPollMs?: number;
	fetch?: typeof fetch;
	sleep?: (ms: number) => Promise<void>;
	clock?: () => number;
}

/** The status read was refused (401/403/404) or redirected (3xx). Never carries the API key. */
export class ApprovalError extends Error {
	constructor(
		message: string,
		readonly status?: number,
	) {
		super(message);
	}
}

const LOOPBACK = ["localhost", "127.0.0.1", "[::1]"];
const MAX_BODY = 64 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TEXT =
	/^approval required "?([0-9a-fA-F-]{36})"?; retry the same call after approval$/;

/** Headers that let a retry read/consume this approval but never create a new one. */
export const retryHeaders = (h: HeldCall): Record<string, string> => ({
	"x-tracelane-approval-id": h.approvalId,
});

const rec = (v: unknown): Record<string, unknown> | null =>
	typeof v === "object" && v !== null && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: null;

function toolText(v: unknown): string | null {
	if (typeof v === "string") return v;
	const o = rec(v);
	const r = rec(o?.result) ?? o;
	if (r?.isError !== true || !Array.isArray(r.content)) return null;
	const t = rec(r.content[0])?.text;
	return typeof t === "string" ? t : null;
}

/** Parse a real fetch `Response` (its `json()` is async). Reads a clone, so the caller can still read `res`. */
export async function isHeldResponse(res: unknown): Promise<HeldCall | null> {
	try {
		const o = rec(res);
		if (!o || typeof o.clone !== "function" || typeof o.json !== "function")
			return null;
		return isHeld(
			await (o.clone as () => { json(): Promise<unknown> })().json(),
		);
	} catch {
		return null;
	}
}

/** Parse the gateway's held answer; null for anything else (never throws). */
export function isHeld(result: unknown): HeldCall | null {
	try {
		let v = result;
		const o = rec(v);
		if (o && typeof o.status === "number" && typeof o.json === "function") {
			v = (o.json as () => unknown)(); // sync .json() only; a real Response goes through isHeldResponse
			if (v instanceof Promise) return null;
		}
		if (typeof v === "string") {
			if (v.length > MAX_BODY) return null;
			if (/^\s*[{[]/.test(v)) v = JSON.parse(v);
		}
		const b = rec(v);
		if (b?.error === "approval_required") {
			const id = b.approval_id;
			if (typeof id !== "string" || !UUID.test(id)) return null;
			return {
				approvalId: id,
				expiresAt: typeof b.expires_at === "string" ? b.expires_at : null,
				kind: "protected",
			};
		}
		const id = TEXT.exec((toolText(v) ?? "").trim())?.[1];
		return id && UUID.test(id)
			? { approvalId: id, expiresAt: null, kind: "legacy" }
			: null;
	} catch {
		return null;
	}
}

function checkedBase(raw: string): string {
	let u: URL | undefined;
	try {
		u = new URL(raw);
	} catch {
		/* falls through to the refusal below */
	}
	if (
		!u ||
		!(
			u.protocol === "https:" ||
			(u.protocol === "http:" && LOOPBACK.includes(u.hostname))
		)
	) {
		throw new RangeError("baseUrl must be https (http only for localhost)");
	}
	return raw.replace(/\/+$/, "");
}

const positive = (name: string, v: number): void => {
	if (!Number.isFinite(v) || v <= 0)
		throw new RangeError(`${name} must be a finite number > 0`);
};

/**
 * Poll GET /v1/approvals/{id} with the agent's own key until a terminal status or the deadline.
 * Only an explicit `approved` returns "approved". consumed / unknown terminal => "expired";
 * deadline => "timeout" (the approval may still be pending). 401/403/404 throw ApprovalError.
 */
export async function waitForDecision(
	held: HeldCall,
	o: WaitOptions,
): Promise<Decision> {
	const timeout = o.timeoutMs ?? 300_000;
	const poll = o.pollMs ?? 2_000;
	const maxPoll = o.maxPollMs ?? 15_000;
	positive("timeoutMs", timeout);
	positive("pollMs", poll);
	positive("maxPollMs", maxPoll);
	if (!UUID.test(held.approvalId))
		throw new RangeError("held.approvalId is not a UUID");
	const f = o.fetch ?? fetch;
	const sleep =
		o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
	const now = o.clock ?? Date.now;
	const url = `${checkedBase(o.baseUrl)}/v1/approvals/${held.approvalId.toLowerCase()}`;
	const deadline = now() + timeout;
	let wait = poll;
	for (;;) {
		let code = 599;
		let status: unknown;
		let retryAfter = 0;
		try {
			const r = await f(url, {
				headers: {
					Authorization: `Bearer ${o.apiKey}`,
					Accept: "application/json",
				},
				signal: AbortSignal.timeout(Math.min(10_000, timeout)),
				redirect: "manual", // never forward the Authorization header to a redirect target
			});
			code = r.status;
			const ra = Number(r.headers?.get("retry-after"));
			if (Number.isFinite(ra) && ra > 0) retryAfter = ra * 1000;
			if (code === 200) status = rec(await r.json())?.status;
		} catch {
			/* transient: keep polling until the deadline */
		}
		if (
			code === 401 ||
			code === 403 ||
			code === 404 ||
			(code >= 300 && code < 400)
		) {
			throw new ApprovalError(
				`approval status read refused: HTTP ${code} for ${held.approvalId}`,
				code,
			);
		}
		if (status === "approved") return "approved";
		if (status === "denied") return "denied";
		if (status === "expired" || status === "consumed") return "expired";
		const left = deadline - now();
		if (left <= 0) return "timeout";
		await sleep(Math.min(Math.max(wait, retryAfter), left));
		wait = Math.min(wait * 1.5, maxPoll);
	}
}

/**
 * Wrap a tool `execute` (OpenAI Agents JS `tool({ execute })`, or an MCP `callTool`). Held => wait;
 * approved => retry the identical call once; anything else => a refusal string for the model, no retry.
 */
export function withApproval<A extends unknown[], R>(
	execute: (...args: A) => Promise<R>,
	o: Omit<WaitOptions, "baseUrl" | "apiKey"> & {
		baseUrl: string;
		apiKey: string;
		wait?: (held: HeldCall, o: WaitOptions) => Promise<Decision>;
	},
): (...args: A) => Promise<R | string> {
	const { wait = waitForDecision, ...opts } = o;
	return async (...args: A): Promise<R | string> => {
		const first = await execute(...args);
		const held = isHeld(first);
		if (!held) return first;
		const decision = await wait(held, opts);
		if (decision !== "approved")
			return `Tracelane approval ${decision}: the action was not performed. Do not retry.`;
		const retry = await execute(...args);
		return isHeld(retry)
			? "Tracelane approval pending: the action was not performed. Do not retry."
			: retry;
	};
}
