/**
 * /settings/byok — Customer-Managed Key (CMK) registry.
 *
 * This dashboard registry records fingerprints. Gateway KMS configuration is a
 * separate security API; registration here does not configure gateway KMS.
 */

import { ByokKeyManager } from "@/components/settings/ByokKeyManager";
import { db } from "@/db";
import { tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Encryption Keys (CMK) — Settings" };
export const dynamic = "force-dynamic";

export default async function ByokPage() {
	const session = await requireSession();
	const [row] = await db
		.select({ id: tenants.id, plan: tenants.plan })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	const plan: Plan = (row?.plan as Plan) ?? "free";
	const ent = await resolveEntitlements(row?.id, plan);

	if (!ent.byok_cmk) {
		return (
			<div className="space-y-1">
				<h2 className="text-sm font-semibold text-ink">
					Encryption Keys (CMK)
				</h2>
				<p className="mb-4 max-w-2xl text-xs text-ink-2">
					The CMK fingerprint registry and gateway customer KMS configuration
					are available on Business and Enterprise. Registering a fingerprint
					here does not configure KMS encryption.
				</p>
				<div className="max-w-2xl rounded-card border border-action-line bg-action-soft px-4 py-3 text-sm text-ink">
					<span className="font-semibold">
						Register a key fingerprint for your workspace.
					</span>{" "}
					<Link
						href="/settings/billing"
						className="font-medium text-action-ink underline underline-offset-2"
					>
						View plan details →
					</Link>
				</div>
			</div>
		);
	}

	return (
		<div className="space-y-1">
			<h2 className="text-sm font-semibold text-ink">Encryption Keys (CMK)</h2>
			<p className="mb-3 max-w-2xl text-xs text-ink-2">
				<span className="font-medium text-ink">Optional.</span> Register your
				own public key as the intended customer-managed key for your workspace,
				for regulated environments. Stored as a fingerprint only.
			</p>
			{/* The fingerprint registry and gateway KMS configuration are separate. */}
			<div className="mb-4 max-w-2xl rounded-card border border-line bg-surface-2 p-3 text-xs text-ink-2">
				<div className="mb-1 font-medium text-ink">
					Fingerprint registry · separate from gateway KMS
				</div>
				<p>
					Registering a public key records its fingerprint, never your private
					key. It does not configure the gateway&apos;s customer KMS. Configure
					customer KMS through the gateway security API to wrap provider-key
					data keys. Keys shown as{" "}
					<span className="font-medium text-ink">Registered</span> on this page
					are fingerprint records.
				</p>
			</div>
			<p className="mb-6 text-xs text-ink-3">
				Looking for the provider API keys the gateway routes with (Anthropic,
				OpenAI, …)?{" "}
				<Link
					href="/settings/providers"
					className="font-medium text-action-ink hover:underline"
				>
					LLM Provider Keys →
				</Link>
			</p>
			<ByokKeyManager />
		</div>
	);
}
