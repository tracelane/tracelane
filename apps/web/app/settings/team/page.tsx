/**
 * /settings/team — org member list + invite UI.
 *
 * Fetches the tenant's plan from Postgres to enforce the seat limit
 * enforced by the entitlements layer. The TeamManager client component
 * handles the WorkOS team API calls.
 */

import { TeamManager } from "@/components/settings/TeamManager";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { canAdmin, requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Team — Settings" };

// Reads the session cookie + Postgres at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function TeamPage() {
	const session = await requireSession();

	const tenantRows = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);

	// Fail CLOSED to `free` when the tenant row is unresolvable
	// (`.claude/rules/tenancy.md`) — an absent row must not read as unlimited.
	const plan: Plan = (tenantRows[0]?.plan as Plan) ?? "free";
	// Seat cap comes from the SAME authoritative source the invite route enforces
	// (`resolveEntitlements`), never a hardcoded map — so the displayed cap can
	// never drift from what the server actually allows. ADR-076: seats are
	// UNLIMITED on every paid tier; only Free is capped, at 1. The component
	// takes `< 0` as its unlimited sentinel, so translate at the seam.
	const ent = await resolveEntitlements(tenantRows[0]?.id, plan);
	const membersMax = ent.unlimited_seats ? -1 : 1;

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Team</h2>
			<p className="text-xs text-ink-2 mb-6">
				Manage org members. Invitations are sent via email through WorkOS.
				{membersMax > 0 && (
					<>
						{" "}
						Your <span className="capitalize">{plan}</span> plan allows up to{" "}
						<strong className="text-ink-2">{membersMax}</strong>{" "}
						{membersMax === 1 ? "seat" : "seats"}.
					</>
				)}
			</p>
			<TeamManager
				membersMax={membersMax}
				currentUserId={session.userId}
				canManage={canAdmin(session.role)}
			/>
		</div>
	);
}
