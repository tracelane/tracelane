/**
 * WorkOS organization helpers — cursor-paginated list reads + the org-admin
 * gate, shared by the team/workspace API routes.
 *
 * Server-only (reads `WORKOS_API_KEY` at the call site; the key is passed in so
 * this module never touches env directly). Every list follows WorkOS
 * `list_metadata.after` to completion so a >100-member/invitation org can't
 * silently under-count (the seat gate) or 404 a page-2 member (removal).
 */

const WORKOS = "https://api.workos.com";
// 50 pages × 100 = 5000 rows — a hard stop so a broken cursor can't loop forever.
const MAX_PAGES = 50;

export interface OrgMembership {
	id: string;
	user_id: string;
	organization_id: string;
	role: { slug: string };
}

export interface OrgInvitation {
	id: string;
	email: string;
	state: string;
	created_at: string;
	/**
	 * WorkOS invitation carries a FLAT `role_slug` string (verified against the
	 * live API 2026-07-11) — NOT the nested `role: { slug }` shape memberships
	 * use. Optional (older invites created without a role omit it).
	 */
	role_slug?: string | null;
}

/** Admin/owner are the privileged org roles. `owner` is treated as an
 * admin-equivalent to match the member-list RoleBadge; WorkOS's own defaults are
 * `admin`/`member`, so `owner` only appears if the org defined that role. */
export function isPrivilegedRole(slug: string): boolean {
	return slug === "admin" || slug === "owner";
}

/** Follow WorkOS cursor pagination, collecting every `data` row. `null` on any
 * failed request (callers fail the gate closed). */
async function listAll<T>(key: string, path: string): Promise<T[] | null> {
	const out: T[] = [];
	let after: string | null = null;
	for (let page = 0; page < MAX_PAGES; page++) {
		const sep = path.includes("?") ? "&" : "?";
		const url = `${WORKOS}${path}${sep}limit=100${
			after ? `&after=${encodeURIComponent(after)}` : ""
		}`;
		const res = await fetch(url, {
			headers: { Authorization: `Bearer ${key}` },
		});
		if (!res.ok) return null;
		const json = (await res.json()) as {
			data?: T[];
			list_metadata?: { after?: string | null };
		};
		if (Array.isArray(json.data)) out.push(...json.data);
		after = json.list_metadata?.after ?? null;
		if (!after) break;
	}
	return out;
}

export function listMemberships(
	key: string,
	orgId: string,
): Promise<OrgMembership[] | null> {
	return listAll<OrgMembership>(
		key,
		`/user_management/organization_memberships?organization_id=${encodeURIComponent(orgId)}`,
	);
}

export function listInvitations(
	key: string,
	orgId: string,
): Promise<OrgInvitation[] | null> {
	return listAll<OrgInvitation>(
		key,
		`/user_management/invitations?organization_id=${encodeURIComponent(orgId)}`,
	);
}

/**
 * Fetch a single invitation IFF it belongs to `orgId` (tenant isolation).
 * `null` when the id doesn't exist, belongs to another org (no existence leak),
 * or the WorkOS lookup failed. Callers turn `null` into a 404/502.
 */
export async function getInvitationInOrg(
	key: string,
	orgId: string,
	invitationId: string,
): Promise<OrgInvitation | null> {
	const res = await fetch(
		`${WORKOS}/user_management/invitations/${encodeURIComponent(invitationId)}`,
		{ headers: { Authorization: `Bearer ${key}` } },
	);
	if (!res.ok) return null;
	const inv = (await res.json()) as OrgInvitation & {
		organization_id?: string;
	};
	return inv.organization_id === orgId ? inv : null;
}

/**
 * Is `userId` an admin/owner of `orgId`?
 * @returns `true`/`false` when resolved, or `null` when the WorkOS lookup failed
 *   (the caller should treat `null` as fail-closed → 502).
 */
export async function callerIsOrgAdmin(
	key: string,
	orgId: string,
	userId: string,
): Promise<boolean | null> {
	const members = await listMemberships(key, orgId);
	if (members === null) return null;
	const caller = members.find((m) => m.user_id === userId);
	return !!caller && isPrivilegedRole(caller.role.slug);
}
