/**
 * OrgSwitcher — the workspace identity block under the sidebar logo.
 *
 * Server component: reads the session with the NON-redirecting `optionalSession`
 * (the sidebar renders on signed-out routes too) and the org display name from
 * Postgres, then renders quietly-nothing when there is no session.
 *
 * V1 is single-org-per-session and single-environment, so we show the active
 * org name + a static "Production" environment tag. A true org / environment
 * switcher (membership list, an `environments` dimension) is V1.1 — we render no
 * dropdown we cannot yet fulfil (a dead control is worse than none).
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { optionalSession } from "@/lib/auth";
import { eq } from "drizzle-orm";

export async function OrgSwitcher() {
	const session = await optionalSession();
	if (!session) return null;

	let name = "Workspace";
	try {
		const [row] = await db
			.select({ name: tenants.name })
			.from(tenants)
			.where(eq(tenants.workosOrgId, session.tenantId))
			.limit(1);
		if (row?.name?.trim()) name = row.name.trim();
	} catch {
		// Postgres hiccup → keep the generic label; never break the shell.
	}

	// Workspace identity pill (Option B — single-user-per-workspace). Just the
	// workspace name + a status dot: no redundant "Production" tag (the name
	// already conveys it) and no avatar (there is no per-user account menu — the
	// account lives under Settings, so a non-clickable initial is noise).
	return (
		<div className="hidden items-center gap-2 rounded-full bg-surface-2 px-3 py-1.5 text-[12.5px] font-medium sm:flex">
			<span className="h-1.5 w-1.5 rounded-full bg-accent" aria-hidden />
			<span className="max-w-[180px] truncate text-ink" title={name}>
				{name}
			</span>
		</div>
	);
}
