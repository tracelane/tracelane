/**
 * GET /api/settings/team — list org members via WorkOS Management API.
 *
 * Requires WORKOS_API_KEY env var. Returns member list from WorkOS
 * organization_memberships endpoint, scoped to the authenticated tenant's org.
 */

import { requireSession } from "@/lib/auth";
import { type NextRequest, NextResponse } from "next/server";

interface WorkOSMembership {
	id: string;
	user_id: string;
	organization_id: string;
	role: { slug: string };
	created_at: string;
}

interface WorkOSUser {
	id: string;
	email: string;
	first_name: string | null;
	last_name: string | null;
}

interface MemberRow {
	id: string;
	userId: string;
	email: string;
	name: string;
	role: string;
	joinedAt: string;
}

async function workosGet<T>(path: string): Promise<T | null> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) return null;

	const res = await fetch(`https://api.workos.com${path}`, {
		headers: { Authorization: `Bearer ${key}` },
	});

	if (!res.ok) return null;
	return res.json() as Promise<T>;
}

export async function GET(_req: NextRequest): Promise<NextResponse> {
	const session = await requireSession();

	const memberships = await workosGet<{ data: WorkOSMembership[] }>(
		`/user_management/organization_memberships?organization_id=${encodeURIComponent(session.tenantId)}&limit=100`,
	);

	if (!memberships) {
		return NextResponse.json(
			{ error: "WorkOS API not configured or request failed" },
			{ status: 503 },
		);
	}

	// Fetch user details for each membership in parallel
	const members = await Promise.all(
		memberships.data.map(async (m): Promise<MemberRow> => {
			const user = await workosGet<WorkOSUser>(
				`/user_management/users/${encodeURIComponent(m.user_id)}`,
			);
			return {
				id: m.id,
				userId: m.user_id,
				email: user?.email ?? m.user_id,
				name:
					[user?.first_name, user?.last_name].filter(Boolean).join(" ") || "—",
				role: m.role.slug,
				joinedAt: m.created_at,
			};
		}),
	);

	return NextResponse.json(members);
}
