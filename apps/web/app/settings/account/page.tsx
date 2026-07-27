/**
 * /settings/account — profile (display name) + danger zone
 * (IDENTITY_TEAM_SPEC §5). Reads the session + the `users` mirror name so the
 * form is never a blank page. Org deletion is offered only to owners.
 */

import { ProfileManager } from "@/components/settings/ProfileManager";
import { canAdmin, requireSession } from "@/lib/auth";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Account — Settings" };

export const dynamic = "force-dynamic";

/**
 * Seed the display name from WorkOS — the system of record (spec principle #1)
 * — NOT the `users` mirror, which is a best-effort cache that isn't reliably
 * populated (B-101). Falls back to empty on any error; never blank-crashes.
 */
async function currentDisplayName(workosUserId: string): Promise<string> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) return "";
	try {
		const res = await fetch(
			`https://api.workos.com/user_management/users/${encodeURIComponent(workosUserId)}`,
			{ headers: { Authorization: `Bearer ${key}` } },
		);
		if (!res.ok) return "";
		const u = (await res.json()) as {
			first_name?: string | null;
			last_name?: string | null;
		};
		return [u.first_name, u.last_name].filter(Boolean).join(" ").trim();
	} catch {
		return "";
	}
}

export default async function AccountPage() {
	const session = await requireSession();
	const currentName = await currentDisplayName(session.userId);

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Account</h2>
			<p className="text-xs text-ink-2 mb-6">
				Your profile and account controls. Email changes are not yet self-serve.
			</p>
			<ProfileManager
				initialName={currentName}
				email={session.email}
				canDeleteOrg={canAdmin(session.role)}
			/>
		</div>
	);
}
