/**
 * POST /api/onboarding/organization — provision the caller's workspace.
 *
 * Tracelane owns org lifecycle (WorkOS auto-org-on-signup is intentionally
 * OFF). A freshly signed-up user has no organization. In order:
 *   1. If the session already carries an org → ensure tenant row, return.
 *   2. Else look up the user's existing org memberships (covers retry after a
 *      partial failure: org+membership created but the session cookie was
 *      never switched, or the cookie was lost) → switch to it, ensure tenant
 *      row, return.
 *   3. Else create org + membership, switch the session, ensure tenant row.
 *
 * Idempotent across retries. `switchToOrganization` re-mints the AuthKit
 * session cookie so subsequent requests carry the org id.
 */

import { upsertTenantId, upsertUserMirror } from "@/lib/tenant";
import { switchToOrganization, withAuth } from "@workos-inc/authkit-nextjs";
import { type NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const WORKOS_API = "https://api.workos.com";

/** Display name from the WorkOS user's first/last, or null. */
function displayName(user: {
	firstName?: string | null;
	lastName?: string | null;
}): string | null {
	const n = [user.firstName, user.lastName].filter(Boolean).join(" ").trim();
	return n || null;
}

interface Membership {
	organization_id: string;
	status: string;
}

/** First active org membership for the user, or null. */
async function existingOrgId(
	userId: string,
	key: string,
): Promise<string | null> {
	const res = await fetch(
		`${WORKOS_API}/user_management/organization_memberships?user_id=${encodeURIComponent(userId)}&statuses=active`,
		{ headers: { Authorization: `Bearer ${key}` } },
	);
	if (!res.ok) return null;
	const json = (await res.json()) as { data?: Membership[] };
	return json.data?.[0]?.organization_id ?? null;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
	const { user, organizationId } = await withAuth({ ensureSignedIn: true });

	// 1. Session already scoped to an org.
	if (organizationId) {
		const tenantId = await upsertTenantId(organizationId);
		await upsertUserMirror({
			tenantDbId: tenantId,
			workosUserId: user.id,
			email: user.email,
			name: displayName(user),
		});
		return NextResponse.json({ organizationId, tenantId, created: false });
	}

	const key = process.env.WORKOS_API_KEY;
	if (!key) {
		return NextResponse.json(
			{ error: "WorkOS API not configured" },
			{ status: 501 },
		);
	}

	// 2. Retry-safe: reuse an existing membership if the user already has one.
	const priorOrg = await existingOrgId(user.id, key);
	if (priorOrg) {
		await switchToOrganization(priorOrg);
		const tenantId = await upsertTenantId(priorOrg);
		await upsertUserMirror({
			tenantDbId: tenantId,
			workosUserId: user.id,
			email: user.email,
			name: displayName(user),
		});
		return NextResponse.json({
			organizationId: priorOrg,
			tenantId,
			created: false,
		});
	}

	// 3. Fresh provisioning.
	let name = "";
	try {
		name = ((await request.json()) as { name?: string }).name?.trim() ?? "";
	} catch {
		// empty / non-JSON body → derive a default below
	}
	if (!name) name = `${user.email.split("@")[0] ?? "workspace"}'s workspace`;

	const orgRes = await fetch(`${WORKOS_API}/organizations`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${key}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({ name }),
	});
	if (!orgRes.ok) {
		return NextResponse.json({ error: "org creation failed" }, { status: 502 });
	}
	const org = (await orgRes.json()) as { id: string };

	// Pin the workspace CREATOR to `admin`. WorkOS's default role is `member`
	// (docs: create organization membership), which would 403 the owner out of
	// the admin-gated rename / member-removal / Admin-Portal surface on their OWN
	// workspace. Invitees still get the default `member` (see the invite route).
	// `admin` is the WorkOS built-in privileged slug and what `isPrivilegedRole`
	const memRes = await fetch(
		`${WORKOS_API}/user_management/organization_memberships`,
		{
			method: "POST",
			headers: {
				Authorization: `Bearer ${key}`,
				"Content-Type": "application/json",
			},
			body: JSON.stringify({
				user_id: user.id,
				organization_id: org.id,
				role_slug: "admin",
			}),
		},
	);
	if (!memRes.ok) {
		return NextResponse.json(
			{ error: "membership creation failed" },
			{ status: 502 },
		);
	}

	await switchToOrganization(org.id);
	const tenantId = await upsertTenantId(org.id);
	await upsertUserMirror({
		tenantDbId: tenantId,
		workosUserId: user.id,
		email: user.email,
		name: displayName(user),
	});
	return NextResponse.json(
		{ organizationId: org.id, tenantId, created: true },
		{ status: 201 },
	);
}
