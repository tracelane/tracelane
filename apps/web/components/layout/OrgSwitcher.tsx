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

	return (
		<div className="mx-1 mb-2 rounded-md border border-line bg-surface-2/40 px-3 py-2">
			<p className="truncate text-[13px] font-medium text-ink" title={name}>
				{name}
			</p>
			<span className="mt-0.5 inline-flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide text-ink-3">
				<span className="h-1.5 w-1.5 rounded-full bg-ok" aria-hidden />
				Production
			</span>
		</div>
	);
}
