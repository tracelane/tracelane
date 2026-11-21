/**
 * GET/PUT /api/settings/action-control — the owner switch for action control (preview).
 * `specs/ACT-20-workspace-action-control-toggle.md`.
 *
 * Writes `tenants.action_control` (Drizzle, no plan or billing change). The tenant is the
 * session's org resolved to the tenant UUID by SELECT only — never the body, never an
 * upsert — and every lookup fails closed. The change is recorded in the change history
 * BEFORE it is made (`lib/control-change.ts`, fail-closed), serialized per workspace, and
 * made conditional on the value just read so a concurrent change is a refusal, not a
 * silent overwrite. The decision itself is `lib/action-control-setting.ts`.
 * CSRF is the middleware's (`lib/csrf.ts`, every PUT).
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import {
	ACTION_CONTROL_OFF_WARNING,
	type ChangeDecision,
	type ChangeRole,
	PROPAGATION_NOTE,
	decideActionControlChange,
} from "@/lib/action-control-setting";
import { canAdmin, requireSession } from "@/lib/auth";
import {
	recordControlChange,
	recordControlChangeFailed,
} from "@/lib/control-change";
import { rateLimit } from "@/lib/rate-limit";
import { callerIsOrgAdmin } from "@/lib/workos-org";
import { and, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

import { withOwnerMutation } from "../team/owner-lock";

const ACTION = "workspace.action_control.set";

async function readTenant(
	orgId: string,
): Promise<{ id: string; actionControl: boolean } | "missing" | "error"> {
	try {
		const [row] = await db
			.select({ id: tenants.id, actionControl: tenants.actionControl })
			.from(tenants)
			.where(eq(tenants.workosOrgId, orgId))
			.limit(1);
		return row ?? "missing";
	} catch {
		console.error("[action-control] tenant lookup failed");
		return "error";
	}
}

function lookupFailure(r: "missing" | "error"): NextResponse {
	return r === "missing"
		? NextResponse.json({ error: "tenant_not_found" }, { status: 404 })
		: NextResponse.json({ error: "tenant_unavailable" }, { status: 503 });
}

function refusal(d: ChangeDecision): NextResponse | null {
	if (d.action !== "refuse") return null;
	if (d.reason === "role_unverified")
		return NextResponse.json(
			{ error: "could not verify permissions" },
			{ status: 502 },
		);
	if (d.reason === "not_owner")
		return NextResponse.json(
			{ error: "role_forbidden", required_role: "owner_or_admin" },
			{ status: 403 },
		);
	return NextResponse.json(
		{ error: "confirmation_required", warning: d.warning },
		{ status: 409 },
	);
}

export async function GET(): Promise<NextResponse> {
	const session = await requireSession();
	const row = await readTenant(session.tenantId);
	if (typeof row === "string") return lookupFailure(row);
	// UI gating only; the PUT re-verifies the role against WorkOS.
	return NextResponse.json({
		enabled: row.actionControl,
		can_edit: canAdmin(session.role),
		note: PROPAGATION_NOTE,
		off_warning: ACTION_CONTROL_OFF_WARNING,
	});
}

export async function PUT(request: NextRequest): Promise<NextResponse> {
	const session = await requireSession();

	let body: { enabled?: unknown; confirmed?: unknown } | null;
	try {
		body = (await request.json()) as typeof body;
	} catch {
		return NextResponse.json({ error: "invalid_body" }, { status: 400 });
	}
	if (
		!body ||
		typeof body.enabled !== "boolean" ||
		typeof body.confirmed !== "boolean"
	)
		return NextResponse.json({ error: "invalid_body" }, { status: 400 });
	const { enabled, confirmed } = body;

	// Authority from WorkOS, fail-closed, before any lookup or write.
	const key = process.env.WORKOS_API_KEY;
	if (!key)
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	const admin = await callerIsOrgAdmin(key, session.tenantId, session.userId);
	const role: ChangeRole =
		admin === null ? "unverified" : admin ? "admin" : "other";
	if (role !== "admin") {
		const early = refusal(
			decideActionControlChange({
				role,
				current: !enabled,
				requested: enabled,
				confirmed,
			}),
		);
		if (early) return early;
	}

	try {
		if (!(await rateLimit(`action-control:t:${session.tenantId}`, 10, 300_000)))
			return NextResponse.json({ error: "rate_limited" }, { status: 429 });
	} catch {
		return NextResponse.json(
			{ error: "rate_limit_unavailable" },
			{ status: 503 },
		);
	}

	return withOwnerMutation(
		session.tenantId,
		async () => {
			const row = await readTenant(session.tenantId);
			if (typeof row === "string") return lookupFailure(row);

			const decision = decideActionControlChange({
				role,
				current: row.actionControl,
				requested: enabled,
				confirmed,
			});
			const refused = refusal(decision);
			if (refused) return refused;
			if (decision.action === "noop")
				return NextResponse.json({
					enabled: row.actionControl,
					changed: false,
				});
			if (decision.action !== "write")
				return NextResponse.json(
					{ error: "unexpected_decision" },
					{ status: 500 },
				);

			const before = { action_control: row.actionControl };
			const after = { action_control: decision.next };
			const rec = await recordControlChange(
				ACTION,
				session.tenantId,
				before,
				after,
			);
			if (!rec.ok) return rec.response;

			let updated: { id: string }[];
			try {
				updated = await db
					.update(tenants)
					.set({ actionControl: decision.next })
					.where(
						and(
							eq(tenants.id, row.id),
							eq(tenants.actionControl, row.actionControl),
						),
					)
					.returning({ id: tenants.id });
			} catch {
				await recordControlChangeFailed(
					ACTION,
					session.tenantId,
					before,
					after,
				);
				console.error("[action-control] write failed");
				return NextResponse.json({ error: "write_failed" }, { status: 503 });
			}
			if (updated.length !== 1) {
				await recordControlChangeFailed(
					ACTION,
					session.tenantId,
					before,
					after,
				);
				return NextResponse.json(
					{ error: "changed_elsewhere" },
					{ status: 409 },
				);
			}
			return NextResponse.json({
				enabled: decision.next,
				changed: true,
				note: PROPAGATION_NOTE,
				warning: decision.warning,
			});
		},
		{
			error: "write_unavailable",
			message: "Could not confirm the change. Reload and try again.",
		},
	);
}
