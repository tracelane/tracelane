/**
 * Auth helpers for server components and API routes.
 *
 * Wraps WorkOS AuthKit session. tenant_id = WorkOS organizationId —
 * extracted from the session, never from request body or URL params.
 */

import { db } from "@/db";
import { tenants } from "@/db/schema";
import {
	e2eAuthEnabled,
	e2eTestGatewayToken,
	e2eTestSession,
} from "@/lib/e2e-auth";
import { withAuth } from "@workos-inc/authkit-nextjs";
import { eq } from "drizzle-orm";
import { redirect } from "next/navigation";
import { cache } from "react";

export type Session = {
	tenantId: string;
	userId: string;
	email: string;
	/**
	 * WorkOS membership role slug for the active org (`owner`/`member`/`viewer`),
	 * read from the session JWT — never a Tracelane role table (IDENTITY_TEAM_SPEC
	 * §1). `null` for the WorkOS default `admin`, unknown slugs, or a session
	 * predating role configuration. UI gating only; the gateway is authoritative.
	 */
	role: string | null;
};

/**
 * Owner-scoped UI gating (IDENTITY_TEAM_SPEC §1): billing, member management,
 * BYOK/encryption keys, workspace/org settings.
 *
 * **Allowlist, not a denylist (PL-9).** This mirrors the gateway's
 * `Claims::can_admin`, which is authoritative — and that means it must mirror
 * the FIXED one. It previously denied only a literal `member`/`viewer`, so an
 * unrecognised slug, a renamed role, `null` and `undefined` all passed. WorkOS's
 * default org role is `admin`, so the default fell through to full access.
 *
 * These two must move together: the gateway now 403s an unrecognised or absent
 * slug, so a permissive UI here would render buttons that fail on click — the
 * dead-button class the L16 Playwright gate exists to catch.
 */
export function canAdmin(role: string | null | undefined): boolean {
	// `admin` is WorkOS's built-in org role and maps to owner, exactly as
	// `Role::from_slug` does in crates/gateway/src/auth/mod.rs.
	return role === "owner" || role === "admin";
}

/**
 * Get the current session in a Server Component or Route Handler.
 *
 * Redirects to /sign-in if no session exists (via `ensureSignedIn`), and to
 * /onboarding if the user is signed in but has no organization yet (fresh
 * signup before the onboarding wizard provisions one). Pages render the
 * wizard; route handlers respond 307 to it.
 *
 * `redirect()` throws NEXT_REDIRECT — callers must never swallow it in a
 * broad `try/catch`.
 */
export async function requireSession(): Promise<Session> {
	// Dev-only E2E bypass. Fail-closed: e2eAuthEnabled returns true
	// ONLY in a non-prod build with the opt-in flag set, and THROWS in a prod
	// build that carries the flag (see lib/e2e-auth.ts for the predicate). The
	// session is the FIXED disposable test workspace — never derived from the
	// request, never a real tenant.
	if (e2eAuthEnabled()) return e2eTestSession();

	// `withAuth({ensureSignedIn:true})`'s internal auto-redirect throws a
	// form that OpenNext/CF does NOT turn into a 307 — so an unauthenticated hit
	// on a page that calls `requireSession()` 500s instead of redirecting to
	// sign-in. Resolve the session WITHOUT the auto-redirect, then redirect
	// explicitly with Next's `redirect()` (the framework-handled form already used
	// below for onboarding/archived). Authed users get the identical session — only
	// the unauthenticated branch changes. `.catch(() => null)` covers withAuth
	// throwing on no-session; the explicit `redirect()` stays OUTSIDE any catch so
	// its NEXT_REDIRECT is never swallowed.
	const session = await withAuth().catch(() => null);
	if (!session?.user) redirect("/sign-in");
	const { user, organizationId, role } = session;

	if (!organizationId) redirect("/onboarding");

	// Archived-org guard (IDENTITY_TEAM_SPEC §5): a soft-deleted org must land on
	// the "organization deleted" state, not a working (but empty) dashboard.
	// Fail-OPEN: a transient Postgres error must NOT lock everyone out, so only a
	// row we positively read as archived redirects. One indexed lookup.
	if (await isOrgArchived(organizationId)) redirect("/organization-deleted");

	return {
		tenantId: organizationId,
		userId: user.id,
		email: user.email,
		role: role ?? null,
	};
}

/**
 * True only when the tenant row is positively read as archived. Any error
 * (Postgres down, no row yet) returns `false` — fail-open, so a DB blip can't
 * lock a live org out of its dashboard. `redirect()` is never called here.
 */
async function isOrgArchived(workosOrgId: string): Promise<boolean> {
	try {
		const [row] = await db
			.select({ archivedAt: tenants.archivedAt })
			.from(tenants)
			.where(eq(tenants.workosOrgId, workosOrgId))
			.limit(1);
		return !!row?.archivedAt;
	} catch {
		return false;
	}
}

/**
 * Non-redirecting session read for components in the ALWAYS-rendered layout tree
 * (the sidebar org switcher) that must render on both signed-in and signed-out
 * routes. Returns `null` — never `redirect()` — when there is no session or no
 * org, so it can never cause a redirect loop on /sign-in.
 *
 * `withAuth()` (no `ensureSignedIn`) never throws NEXT_REDIRECT; the only throw
 * is the "route not covered by AuthKit middleware" case, which we treat as
 * "no badge" (fail-safe — an optional identity chip must never break the page).
 */
export async function optionalSession(): Promise<Session | null> {
	if (e2eAuthEnabled()) return e2eTestSession();
	try {
		const { user, organizationId, role } = await withAuth();
		if (!user || !organizationId) return null;
		return {
			tenantId: organizationId,
			userId: user.id,
			email: user.email,
			role: role ?? null,
		};
	} catch {
		return null;
	}
}

/**
 * Get the WorkOS access token (the signed JWT) for forwarding to the Rust
 * gateway, plus the WorkOS organization id.
 *
 * Server-only: the client-sanitized auth object strips `accessToken`, so a
 * route handler that proxies to the gateway must mint the Bearer here rather
 * than expect the browser to attach one. The forwarded token carries the
 * WorkOS `org_id`; the gateway bridges it to the internal tenant UUID
 * (ADR-042 bug #2).
 *
 * Redirects (307) to /onboarding when signed in without an org, and to
 * /sign-in if the session somehow lacks an access token — matching
 * `requireSession`'s `redirect()` contract (never swallow NEXT_REDIRECT).
 *
 * MEMOIZED PER REQUEST with React `cache()`. Every `gatewayGet` calls this, and
 * /dashboard makes eight of them — so without memoization one dashboard render
 * ran `withAuth()` eight times, and `withAuth` calls iron-session `unsealData`
 * on EVERY invocation (authkit-nextjs 4.0.1 `dist/esm/session.js:343,399` — it
 * carries no `cache()` of its own; verified, not assumed). That is eight
 * AES-decrypt + key-derive cycles per page on a Worker's single CPU budget, for
 * one unchanging session.
 *
 * `cache()` is per-REQUEST, not global: two different users in flight never
 * share an entry, so this cannot leak a session across tenants. The redirect
 * paths still throw NEXT_REDIRECT on the first call, which is what propagates.
 */
export const requireGatewayToken = cache(
	async function requireGatewayToken(): Promise<{
		token: string;
		tenantId: string;
	}> {
		// Dev-only E2E bypass — same fail-closed contract as requireSession.
		// Returns a deliberately-fake token (the gateway 401s it → pages degrade to
		// the warming/empty state) bound to the disposable test tenant.
		if (e2eAuthEnabled()) return e2eTestGatewayToken();

		//  AGAIN, in the function that was never given the fix. `requireSession`
		// dropped `ensureSignedIn` in 2026-07-28 because its auto-redirect throws a
		// form OpenNext/CF does NOT turn into a 307 — but THIS function kept it, and
		// this is the one every `gatewayGet` calls.
		//
		// The reachable failure is not "no session", it is a session that cannot be
		// REFRESHED: an expired `access-token` whose `wos-auth-verifier` cookies have
		// also expired. `withAuth` then attempts a refresh and writes the new cookie
		// DURING an RSC render, which Next.js forbids outright:
		//     Error: Cookies can only be modified in a Server Action or Route Handler
		// Unhandled, that lands in the error boundary. Measured on prod with a 4-hour-old
		// session: **7 of 11 pages showed "Something went wrong"** — /dashboard, /gateway,
		// /guardrails, /plans, /prompts, /settings/team, /signatures — while /audit, which
		// only reaches `requireSession`, correctly redirected to sign-in. The three that
		// "rendered" did so because `gatewayGetOrNull` swallows the throw and shows an
		// empty state, which is arguably worse: a hard auth failure dressed as no data.
		//
		// Same remedy, same shape: resolve WITHOUT the auto-redirect, then `redirect()`
		// explicitly. The `redirect()` calls stay OUTSIDE the catch so their
		// NEXT_REDIRECT is never swallowed — the contract this file already states.
		// The EXISTING checks are kept verbatim below — this function's contract is
		// about the TOKEN, not about `user`, and widening it would change who gets
		// redirected where. Only the throw becomes a redirect.
		const auth = await withAuth().catch(() => null);

		if (!auth) redirect("/sign-in");
		const { organizationId, accessToken } = auth;

		if (!organizationId) redirect("/onboarding");
		if (!accessToken) redirect("/sign-in");

		return { token: accessToken, tenantId: organizationId };
	},
);
