/**
 * Record a control change in the gateway's control-change audit BEFORE the
 * dashboard makes it outside the gateway (WorkOS membership, CMK rows,
 * workspace rename/delete).
 *
 * Fail-CLOSED (`.claude/rules/security.md`): if the gateway refuses or cannot be
 * reached the route must NOT perform the change. The gateway also enforces the
 * capability, the admin IP allowlist and SSO-required, so a refusal here is an
 * authorization decision and its status/body are mirrored to the caller.
 *
 * `before`/`after` are ids, roles, fingerprints and status only — never key
 * material, never a raw email.
 */

import { GatewayError, gatewayPost } from "@/lib/gateway";
import { logSafe } from "@/lib/polar-webhook";
import { NextResponse } from "next/server";

export type ControlChangeResult =
	| { ok: true }
	| { ok: false; response: NextResponse };

const PATH = "/v1/audit/control-changes";

function isRedirect(err: unknown): boolean {
	const digest = (err as { digest?: unknown } | null)?.digest;
	return typeof digest === "string" && digest.startsWith("NEXT_REDIRECT");
}

export async function recordControlChange(
	action: string,
	targetId: string,
	before?: unknown,
	after?: unknown,
): Promise<ControlChangeResult> {
	try {
		await gatewayPost(PATH, {
			action,
			target_id: targetId,
			...(before === undefined ? {} : { before }),
			...(after === undefined ? {} : { after }),
		});
		return { ok: true };
	} catch (err) {
		if (isRedirect(err)) throw err;
		if (err instanceof GatewayError && err.status !== 503) {
			return {
				ok: false,
				response: NextResponse.json(
					err.body ?? { error: "control_audit_refused" },
					{ status: err.status },
				),
			};
		}
		if (err instanceof GatewayError && err.body) {
			return {
				ok: false,
				response: NextResponse.json(err.body, { status: 503 }),
			};
		}
		console.error(
			`[control-change] record failed for ${logSafe(action)}: ${logSafe(err instanceof Error ? err.message : "error")}`,
		);
		return {
			ok: false,
			response: NextResponse.json(
				{ error: "control_audit_unavailable" },
				{ status: 503 },
			),
		};
	}
}

/** Best-effort `<action>.failed` follow-up when the change itself failed. */
export async function recordControlChangeFailed(
	action: string,
	targetId: string,
	before?: unknown,
	after?: unknown,
): Promise<void> {
	try {
		await recordControlChange(`${action}.failed`, targetId, before, after);
	} catch (err) {
		console.error(
			`[control-change] failed-record error for ${logSafe(action)}: ${logSafe(err instanceof Error ? err.message : "error")}`,
		);
	}
}

/** `alice@example.com` -> `a***@example.com`. */
export function redactEmail(email: string): string {
	const at = email.lastIndexOf("@");
	if (at < 1) return "***";
	return `${email[0]}***${email.slice(at)}`;
}
