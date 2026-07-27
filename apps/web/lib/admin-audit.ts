/**
 * Admin-action audit log helper (ADR-031, TS side).
 *
 * Inserts one row into `admin_audit_log` per mutating admin action.
 * Failure to record is logged at console.error and swallowed — we'd
 * rather lose one audit row than 500 the user on a transient
 * Postgres blip. The Rust mirror lives at
 * `crates/gateway/src/admin_audit.rs`; the schema is migration 11.
 *
 * ## Convention
 *
 * `action` is `<target>.<verb>`, e.g. `api_key.create`,
 * `api_key.revoke`, `prompt.promote`, `billing.subscription.cancel`,
 * `member.invite`, `byok.provider_key.create`.
 *
 * ## V1 scope
 *
 * V1 ships the helper + three demo call sites
 * (api-keys POST/DELETE, prompts/[name]/promote POST). A V1.1 sweep
 * wires the remaining ~12 admin endpoints — tracked in ADR-031 +
 * CHANGELOG with the explicit endpoint list.
 */

import { db } from "@/db";
import { sql } from "drizzle-orm";
import type { NextRequest } from "next/server";

export interface AdminAuditEntry {
	/**
	 * WorkOS user id (opaque string, e.g. `user_01HXYZ...`). Stored
	 * as TEXT in the schema — Tracelane has no local users table;
	 * WorkOS is the identity system of record.
	 */
	actorUserId: string;
	/** Internal Tracelane workspace UUID (`tenants.id`), nullable. */
	actorWorkspaceId?: string | null;
	/** `<target>.<verb>` e.g. "api_key.create" */
	action: string;
	/** Schema-bearing category e.g. "api_key" */
	targetType: string;
	/** Mutated row id (UUID or external id) */
	targetId: string;
	beforeJson?: unknown;
	afterJson?: unknown;
	ipAddr?: string | null;
	userAgent?: string | null;
}

/**
 * Extract the request IP from `x-forwarded-for` (first hop) or the
 * fallback `x-real-ip`. Returns `null` if neither is set so the
 * helper can decline to write an invalid `INET`.
 */
export function ipFromRequest(req: NextRequest): string | null {
	const xff = req.headers.get("x-forwarded-for");
	if (xff) {
		// `x-forwarded-for: client, proxy1, proxy2` — take the first hop.
		const first = xff.split(",")[0]?.trim();
		if (first) return first;
	}
	return req.headers.get("x-real-ip");
}

/**
 * Record one admin action. Best-effort: errors are logged and
 * swallowed so the calling route doesn't fail on an audit-write blip.
 *
 * Use parameter binding via Drizzle's `sql` template — never string
 * interpolation. The `ipAddr` is cast to `INET` server-side; an
 * invalid string falls back to NULL so a malformed `x-forwarded-for`
 * never blocks the audit insert.
 */
export async function recordAdminAction(entry: AdminAuditEntry): Promise<void> {
	try {
		const beforeJson = entry.beforeJson
			? JSON.stringify(entry.beforeJson)
			: null;
		const afterJson = entry.afterJson ? JSON.stringify(entry.afterJson) : null;
		await db.execute(sql`
			INSERT INTO admin_audit_log
				(actor_user_id, actor_workspace_id, action, target_type, target_id,
				 before_json, after_json, ip_addr, user_agent)
			VALUES
				(${entry.actorUserId},
				 ${entry.actorWorkspaceId ?? null}::uuid,
				 ${entry.action},
				 ${entry.targetType},
				 ${entry.targetId},
				 ${beforeJson}::jsonb,
				 ${afterJson}::jsonb,
				 ${entry.ipAddr ?? null}::inet,
				 ${entry.userAgent ?? null})
		`);
	} catch (err) {
		// Best-effort retry without ipAddr if it was the source of the
		// failure. Distinguishing "bad INET" from other Postgres errors
		// without a typed driver is awkward — we just retry once
		// without ipAddr; if THAT fails too, we give up and log.
		if (entry.ipAddr != null) {
			try {
				const beforeJson = entry.beforeJson
					? JSON.stringify(entry.beforeJson)
					: null;
				const afterJson = entry.afterJson
					? JSON.stringify(entry.afterJson)
					: null;
				await db.execute(sql`
					INSERT INTO admin_audit_log
						(actor_user_id, actor_workspace_id, action, target_type, target_id,
						 before_json, after_json, ip_addr, user_agent)
					VALUES
						(${entry.actorUserId},
						 ${entry.actorWorkspaceId ?? null}::uuid,
						 ${entry.action},
						 ${entry.targetType},
						 ${entry.targetId},
						 ${beforeJson}::jsonb,
						 ${afterJson}::jsonb,
						 NULL,
						 ${entry.userAgent ?? null})
				`);
				return;
			} catch (retryErr) {
				console.error("[admin_audit] insert retry failed", retryErr);
				return;
			}
		}
		console.error("[admin_audit] insert failed", err);
	}
}
