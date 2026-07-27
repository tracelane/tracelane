/**
 * Root redirect — sends new users to /onboarding, returning users to the
 * not raw trace rows).
 *
 * New user = authenticated but has no active API keys yet.
 * This check is intentionally lightweight: one indexed Postgres query.
 */

import { db } from "@/db";
import { apiKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { and, count, eq, isNull } from "drizzle-orm";
import { redirect } from "next/navigation";

// Reads the session cookie + Postgres at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function Home() {
	// Use the app's bypass-aware session wrapper, not raw `withAuth()`.
	// requireSession redirects to /sign-in when unauthenticated (ensureSignedIn)
	// and /onboarding when the user has no org — same behavior as the old manual
	// checks — AND it honors the E2E auth bypass. A direct `withAuth()` here
	// throws "route not covered by AuthKit middleware" under the bypass (the
	// middleware skips AuthKit when the bypass is active), which broke `/` and
	// the whole L16 headless gate.
	const { tenantId: organizationId } = await requireSession();

	const tenantRows = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, organizationId))
		.limit(1);

	if (!tenantRows[0]) redirect("/onboarding");

	const [keyCount] = await db
		.select({ cnt: count() })
		.from(apiKeys)
		.where(
			and(eq(apiKeys.tenantId, tenantRows[0].id), isNull(apiKeys.revokedAt)),
		);

	if ((keyCount?.cnt ?? 0) === 0) redirect("/onboarding");

	redirect("/dashboard");
}
