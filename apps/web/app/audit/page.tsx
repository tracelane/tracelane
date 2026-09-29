/** Audit evidence: a bounded check, never a workspace-wide integrity verdict. */
import { AuditHelpBar } from "@/components/audit/AuditHelpBar";
import {
	AuditLedgerView,
	type AuditWindow,
	type LedgerRange,
} from "@/components/audit/AuditLedgerView";
import { AuditSalesSurface } from "@/components/audit/AuditSalesSurface";
import {
	type AuditKeyContext,
	AuditWorkflow,
} from "@/components/audit/AuditWorkflow";
import { db } from "@/db";
import { auditAnchorRecords, tenantAuditKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { e2eAuditFixture } from "@/lib/e2e-audit-fixture";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import { PageHeader } from "@tracelanedev/ui";
import { and, eq, min } from "drizzle-orm";
import type { Metadata } from "next";
import { Suspense } from "react";
import Loading from "./loading";
import { auditFingerprint, readPlatformTrustRoot } from "./trust-root";

export const metadata: Metadata = { title: "Audit evidence — Tracelane" };
export const dynamic = "force-dynamic";

async function getAuditAccess(): Promise<{
	selfVerify: boolean;
	exportEntitled: boolean;
	tenantPubkeyB64: string;
	workspaceKeyCreatedAt?: string;
	workspaceFingerprint?: string;
	workspaceKeySinceSeq?: number;
}> {
	const session = await requireSession();
	const [row] = await db
		.select({
			id: tenants.id,
			plan: tenants.plan,
		})
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	const plan: Plan = (row?.plan as Plan) ?? "builder";
	// ADR-066 split: `audit_self_verify` (default TRUE, all plans) renders the
	// chain + in-browser verify; `audit_ledger` (= f_audit_addon, seeded TRUE on
	// Enterprise only — the paid Article-12 add-on is NOT sold, BILL-01 §10.4 / B-392)
	// gates ONLY the Article-12 export. So a non-entitled
	// tenant still SEEs + verifies their own chain; the export is the upsell.
	//
	// Resolve entitlements + audit key in parallel (both depend on tenant id).
	const [entitlements, keyRow] = await Promise.all([
		resolveEntitlements(row?.id, plan),
		row !== undefined
			? db
					.select({
						pubkey: tenantAuditKeys.publicKeyB64,
						createdAt: tenantAuditKeys.createdAt,
					})
					.from(tenantAuditKeys)
					.where(eq(tenantAuditKeys.tenantId, row.id))
					.limit(1)
					.then(([r]) => r)
					.catch(() => undefined)
			: Promise.resolve(undefined),
	]);
	// AUD-29: where the workspace key took over — the first batch it signed, from the
	// CANONICAL anchor records (ADR-078 B). The verifier then refuses a platform-signed
	// batch at or past it even when this window holds no workspace-signed batch. A
	// failed read leaves it unset: the in-window rule still holds, and the page says
	// nothing it did not check.
	const workspaceKeySinceSeq =
		row !== undefined && keyRow?.pubkey
			? await db
					.select({ since: min(auditAnchorRecords.batchStartSeq) })
					.from(auditAnchorRecords)
					.where(
						and(
							eq(auditAnchorRecords.tenantId, row.id),
							eq(auditAnchorRecords.ed25519Pubkey, keyRow.pubkey),
						),
					)
					.then(([r]) => r?.since ?? undefined)
					.catch(() => undefined)
			: undefined;
	return {
		selfVerify: entitlements.audit_self_verify,
		exportEntitled: entitlements.audit_ledger,
		workspaceKeySinceSeq,
		tenantPubkeyB64: keyRow?.pubkey ?? "",
		workspaceKeyCreatedAt: keyRow?.createdAt.toISOString(),
		workspaceFingerprint: keyRow?.pubkey
			? await auditFingerprint(keyRow.pubkey).catch(() => undefined)
			: undefined,
	};
}

interface SelfVerifyResponse {
	chain_ndjson: string;
	window: AuditWindow;
}

async function LedgerData({
	tenantPubkeyB64,
	exportEntitled,
	...keys
}: AuditKeyContext & {
	tenantPubkeyB64: string;
	exportEntitled: boolean;
}) {
	// Both plans use the SAME bounded self-verify route, which includes only fully
	// covered anchor batches. Never call the bulk export to render the page.
	// The lifetime inventory is distinct from the plan-retention count.
	const [evidence, inventory] = await Promise.allSettled([
		gatewayGet<SelfVerifyResponse>(
			"/v1/audit/self-verify?limit=1000&order=desc",
		),
		gatewayGet<LedgerRange>("/v1/audit/ledger-range"),
	]);
	if (evidence.status === "rejected") {
		const status =
			evidence.reason instanceof GatewayError
				? evidence.reason.status
				: undefined;
		return (
			<section className="surface-card p-6" aria-live="polite">
				<AuditWorkflow report={null} rows={0} batches={0} readError {...keys} />
				<p className="mt-4 text-xs font-medium uppercase tracking-widest text-ink-2">
					CANNOT DETERMINE
				</p>
				<h2 className="mt-2 text-xl font-semibold">
					We couldn’t check your evidence
				</h2>
				<p className="mt-2 text-sm text-ink-2">
					{status === 401
						? "Sign in again to read this workspace’s ledger."
						: status === 403
							? "This workspace or sign-in does not have permission to read the ledger."
							: "The ledger read did not complete. Its integrity is unknown here."}
				</p>
				<div className="mt-5 flex gap-5 text-sm">
					<a
						className="underline"
						href={status === 401 ? "/sign-in" : "/audit"}
					>
						{status === 401 ? "Sign in" : "Retry ledger read"}
					</a>
					<a className="underline" href="/support">
						Contact support
					</a>
				</div>
			</section>
		);
	}
	return (
		<AuditLedgerView
			{...keys}
			ndjson={evidence.value.chain_ndjson}
			tenantPubkeyB64={tenantPubkeyB64}
			canExport={exportEntitled}
			ledgerRange={
				inventory.status === "fulfilled" ? inventory.value : undefined
			}
			window={evidence.value.window}
		/>
	);
}

export default async function AuditPage({
	searchParams,
}: {
	searchParams: Promise<{ e2e_fixture?: string }>;
}) {
	const sp = await searchParams;
	const fixture = sp.e2e_fixture ? await e2eAuditFixture(sp.e2e_fixture) : null;
	// Reuse the existing dev/test-only fixture gate. No additional production bypass.
	if (fixture && sp.e2e_fixture === "empty") fixture.ndjson = "";
	if (fixture && sp.e2e_fixture === "proof-failed") {
		fixture.ndjson = fixture.ndjson
			.split("\n")
			.filter(Boolean)
			.map((line) => {
				const record = JSON.parse(line);
				if (record.type === "anchor")
					record.rekor.checkpoint.envelope = "invalid-checkpoint";
				return JSON.stringify(record);
			})
			.join("\n");
	}
	const platformRoot = await readPlatformTrustRoot();
	// The existing explicit dev-only fixture gate is the only entry to these local vectors.
	if (fixture && sp.e2e_fixture?.startsWith("platform-")) {
		const workspace = await gatewayGet<{
			ed25519_pubkey_b64: string;
			created_at: string;
			workspace_key_since_seq?: number | null;
		}>("/v1/audit/pubkey");
		// Dev-only fixture vectors are signed by a TEST platform key the fixture gateway
		// serves; production never takes this branch (the pinned key is its root).
		const fixturePlatform = await gatewayGet<{ ed25519_pubkey_b64: string }>(
			"/v1/audit/platform-pubkey",
		);
		return (
			<div className="mx-auto max-w-6xl space-y-5 px-4 py-6">
				<PageHeader title="Audit evidence" />
				<LedgerData
					tenantPubkeyB64={workspace.ed25519_pubkey_b64}
					exportEntitled
					workspaceKeyCreatedAt={workspace.created_at}
					workspaceKeySinceSeq={workspace.workspace_key_since_seq ?? undefined}
					workspaceFingerprint={
						await auditFingerprint(workspace.ed25519_pubkey_b64)
					}
					platformPubkeyB64={fixturePlatform.ed25519_pubkey_b64}
					platformFingerprint={
						await auditFingerprint(fixturePlatform.ed25519_pubkey_b64)
					}
					platformKeySource="gateway"
				/>
			</div>
		);
	}
	const access = fixture
		? {
				selfVerify: true,
				exportEntitled: true,
				tenantPubkeyB64: fixture.tenantPubkeyB64,
				workspaceKeyCreatedAt: undefined,
				workspaceFingerprint: fixture.tenantPubkeyB64
					? await auditFingerprint(fixture.tenantPubkeyB64)
					: undefined,
			}
		: await getAuditAccess();
	return (
		<div className="mx-auto max-w-6xl px-2 py-4 sm:px-6 sm:py-6">
			<header className="mb-4 flex flex-wrap items-start justify-between gap-4">
				<div>
					<p className="mb-2 text-xs font-medium uppercase tracking-widest text-ink-3">
						The evidence behind your AI
					</p>
					<PageHeader title={<>Audit evidence</>} />
					<p className="mt-2 text-sm text-ink-2">
						Check recorded events for changes. Inspect the proof. Know what
						needs attention.
					</p>
				</div>
				<a
					href="https://docs.tracelane.dev/audit-ledger"
					className="text-sm text-ink-2 underline underline-offset-4"
				>
					How verification works ↗
				</a>
			</header>
			{fixture ? (
				<AuditLedgerView
					{...platformRoot}
					workspaceFingerprint={access.workspaceFingerprint}
					ndjson={fixture.ndjson}
					tenantPubkeyB64={fixture.tenantPubkeyB64}
					canExport={sp.e2e_fixture !== "free"}
					ledgerRange={
						sp.e2e_fixture === "unknown-total"
							? undefined
							: {
									total:
										sp.e2e_fixture === "billion" ||
										sp.e2e_fixture === "newest-billion"
											? 1_000_000_000
											: sp.e2e_fixture === "empty"
												? 0
												: sp.e2e_fixture === "tampered-later"
													? 1000
													: 4,
									from: 0,
									to:
										sp.e2e_fixture === "billion" ||
										sp.e2e_fixture === "newest-billion"
											? 999_999_999
											: sp.e2e_fixture === "tampered-later"
												? 999
												: 3,
									latest_event_at:
										sp.e2e_fixture === "empty" ? null : "2026-09-24T00:00:00Z",
									latest_anchor_at: [
										"empty",
										"newest-billion",
										"tampered-later",
									].includes(sp.e2e_fixture ?? "")
										? null
										: "2026-09-24T00:01:00Z",
								}
					}
					window={{
						since: "2026-07-01T00:00:00Z",
						until: "2026-09-24T00:00:00Z",
					}}
				/>
			) : access.selfVerify ? (
				<Suspense fallback={<Loading />}>
					<LedgerData
						{...platformRoot}
						workspaceFingerprint={access.workspaceFingerprint}
						workspaceKeyCreatedAt={access.workspaceKeyCreatedAt}
						workspaceKeySinceSeq={access.workspaceKeySinceSeq}
						tenantPubkeyB64={access.tenantPubkeyB64}
						exportEntitled={access.exportEntitled}
					/>
				</Suspense>
			) : (
				<AuditSalesSurface />
			)}
			<footer className="mt-6 space-y-4 border-t border-line pt-5">
				<AuditHelpBar exportEntitled={access.exportEntitled} />
			</footer>
		</div>
	);
}
