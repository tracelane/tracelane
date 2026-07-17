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
		<div className="flex min-h-screen items-center justify-center bg-surface px-6">
			<div className="max-w-md text-center space-y-4">
				<h1 className="text-lg font-semibold text-ink">
					This organization was deleted
				</h1>
				<p className="text-sm text-ink-2">
					Its workspace is scheduled for permanent deletion within 30 days. If
					this was a mistake, contact support before then to restore it. Access
					to dashboards, API keys, and ingestion has been revoked.
				</p>
				<Link
					href="/sign-out"
					className="inline-block rounded-lg bg-accent px-4 py-2 text-sm font-medium text-accent-on hover:bg-accent/90 transition-colors"
				>
					Sign out
				</Link>
			</div>
		</div>
	);
}
