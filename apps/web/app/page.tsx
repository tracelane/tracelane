/**
 * Root redirect — sends users with no workspace to /onboarding, everyone else
 * to the overview-first /dashboard (§1: the landing surface is the overview,
 * not raw trace rows).
 *
 * ── THIS ROUTE ASKS ONE QUESTION: DO YOU HAVE A WORKSPACE? ──────────────────
 * It used to ask a second one — "do you have a non-revoked API key?" — and
 * redirect to the 3-step onboarding wizard when the answer was no. That is a
 * different question, and it was wrong for three months (R201).
 *
 * THE FAILURE, on 2026-08-26: the founder's own account — six months old, Team
 * plan, 9,502 spans, an intact `tenants` row — revoked its last old API key and
 * was met with "Welcome to Tracelane, Step 1 of 3, name your workspace". At the
 * time 15 of 19 production tenants had zero active keys, so this was the
 * majority state, not an edge case. Revoking a key is ordinary hygiene; being
 * demoted to a new user for it is not a consequence anyone would predict.
 *
 * No key count can make an existing workspace a new signup. `redirect()` here
 * is a routing decision on the FIRST authenticated page, so the only question
 * it may ask is the one that decides which product you are in.
 *
 * WHAT THE OLD CHECK WAS PROTECTING IS NOT LOST — it moves, it is not deleted.
 * A genuinely new user landing on an empty dashboard with no next step was a
 * real concern. `NoApiKeysPanel` on /dashboard is that next step: same
 * information, same call to action, offered instead of imposed. It is scoped to
 * the surface where the emptiness is visible rather than to the router.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { eq } from "drizzle-orm";
import { redirect } from "next/navigation";

// Reads the session cookie + Postgres at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function Home() {
	// Use the app's bypass-aware session wrapper, not raw `withAuth()`.
	// requireSession redirects to /sign-in when unauthenticated (ensureSignedIn)
	// and /onboarding when the user has no org — AND it honors the E2E auth
	// bypass. A direct `withAuth()` here throws "route not covered by AuthKit
	// middleware" under the bypass (the middleware skips AuthKit when the bypass
	// is active), which broke `/` and the whole L16 headless gate.
	const { tenantId: organizationId } = await requireSession();

	// `organizationId` is the WorkOS org id, matched against the `workos_org_id`
	// COLUMN — never against `tenants.id`. Binding the raw org id to the UUID
	// primary key matches zero rows silently, which is this repo's #1 recurring
	// bug class and would read here as "no workspace".
	const tenantRows = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, organizationId))
		.limit(1);

	if (!tenantRows[0]) redirect("/onboarding");

	redirect("/dashboard");
}
