/**
 * /settings/workspace — org identity and tenant metadata.
 *
 * Shows WorkOS organization name + ID, plan, tenant row ID, and the
 * `WorkspaceManager` mutation surface: in-app org rename (PATCH) + WorkOS Admin
 * Portal launchers for SSO / domains / directory sync. Org details are fetched
 * from the WorkOS Management API directly; every mutation derives the org id
 * from the session server-side.
 */

import { WorkspaceManager } from "@/components/settings/WorkspaceManager";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Workspace — Settings" };

interface WorkOSOrg {
	id: string;
	name: string;
	created_at: string;
	domains: { domain: string }[];
}

async function fetchOrg(orgId: string): Promise<WorkOSOrg | null> {
	const key = process.env.WORKOS_API_KEY;
	if (!key) return null;

	const res = await fetch(
		`https://api.workos.com/organizations/${encodeURIComponent(orgId)}`,
		{ headers: { Authorization: `Bearer ${key}` } },
	);
	if (!res.ok) return null;
	return res.json() as Promise<WorkOSOrg>;
}

function InfoRow({ label, value }: { label: string; value: string }) {
	return (
		<div className="flex items-start gap-4 py-3 border-b border-line last:border-0">
			<dt className="w-36 shrink-0 text-xs text-ink-2 pt-0.5">{label}</dt>
			<dd className="text-xs font-mono text-ink break-all">{value}</dd>
		</div>
	);
}

// Reads the session cookie + Postgres at request time — never prerender.
export const dynamic = "force-dynamic";

export default async function WorkspacePage() {
	const session = await requireSession();

	const [tenantRows, org] = await Promise.all([
		db
			.select({
				id: tenants.id,
				plan: tenants.plan,
				createdAt: tenants.createdAt,
			})
			.from(tenants)
			.where(eq(tenants.workosOrgId, session.tenantId))
			.limit(1),
		fetchOrg(session.tenantId),
	]);

	const tenant = tenantRows[0];

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Workspace</h2>
			<p className="text-xs text-ink-2 mb-6">
				Rename your organization, and manage SSO, domains, and directory sync.
			</p>

			<div className="mb-6">
				<WorkspaceManager initialName={org?.name ?? ""} />
			</div>

			<div className="rounded-lg border border-line">
				<dl className="px-4">
					{org?.name && <InfoRow label="Organization" value={org.name} />}
					{tenant?.id && <InfoRow label="Tenant ID" value={tenant.id} />}
					<InfoRow label="WorkOS Org ID" value={session.tenantId} />
					{org?.domains?.length ? (
						<InfoRow
							label="Domains"
							value={org.domains.map((d) => d.domain).join(", ")}
						/>
					) : null}
					{tenant?.plan && (
						<InfoRow
							label="Plan"
							value={tenant.plan.charAt(0).toUpperCase() + tenant.plan.slice(1)}
						/>
					)}
					{org?.created_at && (
						<InfoRow
							label="Created"
							value={new Date(org.created_at).toLocaleDateString("en-US", {
								year: "numeric",
								month: "long",
								day: "numeric",
							})}
						/>
					)}
				</dl>
			</div>
		</div>
	);
}
