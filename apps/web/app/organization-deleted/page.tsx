/**
 * /organization-deleted — terminal state for a soft-deleted org
 * (IDENTITY_TEAM_SPEC §5). requireSession redirects an archived org here so the
 * user lands on a clear message, not a broken/empty dashboard.
 *
 * MUST NOT call requireSession (it would redirect-loop). Static, no session read.
 */

import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Organization deleted" };

export default function OrganizationDeletedPage() {
	return (
		// `bg-bg`, the page GROUND. It was `bg-surface`, which under the P0 palette is
		// the CARD colour (#ffffff against a #fafaf9 ground) — so this was the one
		// full-screen route rendering the card material edge to edge. When ground and
		// card were both pure white that was invisible; the moment they split, it was
		// the only page in the app on the wrong plane.
		<div className="min-h-screen grid place-items-center bg-bg p-6">
			<div className="max-w-md text-left space-y-4">
				<h1 className="t-h1">This organization was deleted</h1>
				<p className="text-sm text-ink-2">
					Access to dashboards, API keys, and ingestion has been revoked.
					Workspace data becomes eligible for purge after a 30-day grace period
					by default; this is not a guarantee of completed deletion by day 30.
					Audit records and backups have separate retention rules.
				</p>
				<Link
					href="/sign-out"
					className="inline-block rounded-control bg-action px-4 py-2 text-sm font-medium text-action-on hover:bg-action/90 transition-colors"
				>
					Sign out
				</Link>
			</div>
		</div>
	);
}
