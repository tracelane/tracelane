/**
 * /settings/byok — Customer-Managed Key (CMK) registry.
 *
 * HONESTY (tile-provenance audit P3 #13): this is a REGISTRY, not yet an
 * enforcement surface. The gateway does NOT consume `cmk_keys` today — envelope
 * encryption uses a server-held master key; "rotate" is a future job. So the page
 * must NOT claim "Tracelane cannot read them", and it is gated on the `byok_cmk`
 * entitlement (Business+) so a non-entitled tenant can't register a key and see a
 * misleading "active" state. Copy states the real status: registered now,
 * enforced in a later release.
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
					Customer-managed keys (CMK) for regulated environments are part of the
					Business plan and above.
				</p>
				<div className="max-w-2xl rounded-lg border border-action-line bg-action-soft px-4 py-3 text-sm text-action-ink">
					<span className="font-semibold">
						Customer-managed encryption is available on Business ($899/mo) and
						Enterprise.
					</span>{" "}
					<Link
						href="/settings/billing"
						className="font-medium underline underline-offset-2"
					>
						Upgrade →
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
			{/* Honest state — this registry is not yet enforced. */}
			<div className="mb-4 max-w-2xl rounded-lg border border-line bg-surface-2 p-3 text-xs text-ink-2">
				<div className="mb-1 font-medium text-ink">
					Registered now · enforcement in a later release
				</div>
				<p>
					Registering a key records it (Tracelane stores only the fingerprint,
					never your private key). Envelope-encrypting new provider keys and
					trace payloads <span className="text-ink">under your key</span> is on
					the roadmap — until it ships, data-at-rest is encrypted under
					Tracelane&apos;s server-managed key. Keys shown as{" "}
					<span className="font-medium text-ink">Registered</span> are recorded,
					not yet enforcing.
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
