/**
 * /dashboards — list the tenant's custom dashboards, create new ones.
 *
 * Empty state: "Create your first dashboard" with a one-line explanation that
 * tiles are composed from the metric catalog (spec §5). The built-in /dashboard
 * is unchanged and stays first in the nav.
 *
 * Data source: Postgres dashboards table, direct Drizzle read in RSC —
 * the same pattern as /settings/api-keys. tenant_id from the session's
 * resolved internal UUID (never the raw WorkOS org id).
 */

import { db } from "@/db";
import { dashboardTiles, dashboards } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { upsertTenantId } from "@/lib/tenant";
import { EmptyState } from "@tracelanedev/ui";
import { count, desc, eq, inArray } from "drizzle-orm";
import type { Metadata } from "next";
import Link from "next/link";
import { DashboardCard } from "./DashboardCard";

export const metadata: Metadata = { title: "Dashboards — Tracelane" };
export const dynamic = "force-dynamic";

function PlusIcon() {
	return (
		<svg
			aria-hidden="true"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
		>
			<line x1="12" y1="5" x2="12" y2="19" />
			<line x1="5" y1="12" x2="19" y2="12" />
		</svg>
	);
}

export default async function DashboardsPage() {
	const session = await requireSession();
	const canEdit =
		session.role === "owner" ||
		session.role === "admin" ||
		session.role === "member";
	const tenantDbId = await upsertTenantId(session.tenantId);

	// Load dashboards for this tenant.
	const rows = await db
		.select({
			id: dashboards.id,
			name: dashboards.name,
			createdBy: dashboards.createdBy,
			createdAt: dashboards.createdAt,
			updatedAt: dashboards.updatedAt,
		})
		.from(dashboards)
		.where(eq(dashboards.tenantId, tenantDbId))
		.orderBy(desc(dashboards.updatedAt));

	// Attach tile counts.
	const tileCounts =
		rows.length > 0
			? await db
					.select({
						dashboardId: dashboardTiles.dashboardId,
						count: count(),
					})
					.from(dashboardTiles)
					.where(
						inArray(
							dashboardTiles.dashboardId,
							rows.map((r) => r.id),
						),
					)
					.groupBy(dashboardTiles.dashboardId)
			: [];

	const countByDashboard = new Map(
		tileCounts.map((r) => [r.dashboardId, r.count]),
	);

	const enriched = rows.map((r) => ({
		...r,
		tileCount: countByDashboard.get(r.id) ?? 0,
	}));

	return (
		<div className="space-y-8 px-1 py-2 sm:px-2 sm:py-4 lg:px-3">
			<header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
				<div>
					<h1 className="t-h1">Dashboards</h1>
					<p className="mt-2 max-w-2xl text-sm text-ink-2">
						Compose tiles from the metric catalog — the same numbers as the
						built-in pages, arranged your way.
					</p>
				</div>
				{canEdit && (
					<Link
						href="/dashboards/new"
						className="inline-flex items-center gap-2 rounded-[var(--radius-control)] bg-action px-4 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<PlusIcon />
						New dashboard
					</Link>
				)}
			</header>

			{enriched.length === 0 ? (
				<EmptyState
					title="No dashboards yet"
					description="Build a dashboard by composing tiles from the metric catalog — the same numbers as the built-in pages, arranged your way."
					action={
						canEdit ? (
							<Link href="/dashboards/new" className="text-action">
								Create your first dashboard →
							</Link>
						) : undefined
					}
				/>
			) : (
				<div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
					{enriched.map((d) => (
						<DashboardCard key={d.id} dashboard={d} canEdit={canEdit} />
					))}
				</div>
			)}
		</div>
	);
}
