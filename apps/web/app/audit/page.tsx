/**
 * Audit Ledger page — the tamper-evident record, gated honestly to the Audit SKU.
 *
 * Entitled tenants get the chain visualization + a client-side "Verify integrity"
 * (the real verifier runs in their browser) + the Article-12 export. Non-entitled
 * tenants get the sales surface (what it does + upgrade CTA) — never fake data.
 * tenant_id comes from the WorkOS session; the gateway owns the tenant-scoped read.
 *
 * Window resolution (priority order):
 *   1. Explicit ?since=<ISO>&until=<ISO> — custom date range (auditor path)
 *   2. ?range=<key> — preset window (24h/7d/30d/90d/all)
 *   3. Default: "all"
 *
 * Speed notes:
 *   • getAuditAccess() is the only DB round-trip; LedgerData/SelfVerifyData
 *     receive the resolved pubkey as a prop — no duplicate requireSession() or
 *     tenant selects inside those components.
 *   • The two gateway fetches (summary + export) are fired in parallel via
 *     Promise.all with per-fetch .catch() so a summary failure doesn't abort export.
 *   • LedgerData/SelfVerifyData are wrapped in <Suspense> so HTML streams from
 *     the page shell immediately; the ledger content streams in after the gateway.
 */

import { AuditHelpBar } from "@/components/audit/AuditHelpBar";
import {
	AuditLedgerView,
	type AuditSummary,
} from "@/components/audit/AuditLedgerView";
import { AuditSalesSurface } from "@/components/audit/AuditSalesSurface";
import { WarmingBanner } from "@/components/empty-states/WarmingBanner";
import { db } from "@/db";
import { tenantAuditKeys, tenants } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { e2eAuditFixture } from "@/lib/e2e-audit-fixture";
import { type Plan, resolveEntitlements } from "@/lib/entitlements";
import { GatewayError, gatewayGet, gatewayGetText } from "@/lib/gateway";
import { EmptyState, Skeleton } from "@tracelanedev/ui";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";
import { Suspense } from "react";

export const metadata: Metadata = { title: "Audit Ledger — Tracelane" };
export const dynamic = "force-dynamic";

/** Date-range windows for the ledger view → the export `since`/`until` params.
 * `all` maps to a wide floor (the ledger is append-only, no automatic expiry). */
const RANGES = { "24h": 1, "7d": 7, "30d": 30, "90d": 90, all: null } as const;
export type AuditRange = keyof typeof RANGES;
/** Genesis floor for the append-only ledger — the export/summary window always
 * starts here so the chain the verifier sees begins at seq 0 (verifiable). */
const GENESIS_SINCE = "2020-01-01T00:00:00Z";
function rangeSinceIso(range: AuditRange): string {
	const days = RANGES[range];
	return days == null
		? GENESIS_SINCE
		: new Date(Date.now() - days * 86_400_000).toISOString();
}

/**
 * Single DB round-trip: session → tenant row → entitlements + audit key (parallel).
 * Returns everything LedgerData and SelfVerifyData need so they never re-query.
 */
async function getAuditAccess(): Promise<{
	selfVerify: boolean;
	exportEntitled: boolean;
	retentionDays: number;
	tenantPubkeyB64: string;
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
	// chain + in-browser verify; `audit_ledger` (= f_audit_addon, the $999 paid
	// add-on) gates ONLY the Article-12 evidence-pack export. So a non-entitled
	// tenant still SEEs + verifies their own chain; the export is the upsell.
	//
	// Resolve entitlements + audit key in parallel (both depend on tenant id).
	const [entitlements, keyRow] = await Promise.all([
		resolveEntitlements(row?.id, plan),
		row !== undefined
			? db
					.select({ pubkey: tenantAuditKeys.publicKeyB64 })
					.from(tenantAuditKeys)
					.where(eq(tenantAuditKeys.tenantId, row.id))
					.limit(1)
					.then(([r]) => r)
			: Promise.resolve(undefined),
	]);
	return {
		selfVerify: entitlements.audit_self_verify,
		exportEntitled: entitlements.audit_ledger,
		// The plan's trace-retention (spans TTL). The audit_log itself has NO TTL
		// (append-only) — shown as a contrast so the user sees the ledger outlives
		// their trace data.
		retentionDays: entitlements.retention_days,
		tenantPubkeyB64: keyRow?.pubkey ?? "",
	};
}

/** Server verdict shape returned by the FREE gateway self-verify endpoint
 * (ADR-066). We consume `chain_ndjson` to render + re-verify in the browser.
 * `total_in_window` is the EXACT uncapped count so the UI shows an honest
 * "Showing N of {total}" instead of the loaded cap reading as the whole ledger. */
interface SelfVerifyResponse {
	chain_ndjson: string;
	/** Rows actually loaded (capped at the render limit). */
	rows_verified?: number;
	/** Exact uncapped count of chain rows in the retention window. */
	total_in_window?: number;
}

/** Streaming fallback for Suspense — mirrors the loading.tsx skeleton without the
 * outer <main> so it nests correctly inside the page shell. */
function AuditFallback() {
	return (
		<div className="space-y-4">
			<Skeleton className="h-28 w-full rounded-xl" />
			<Skeleton className="mt-2 h-5 w-40" />
			<div className="mt-2 space-y-1.5">
				{["a", "b", "c", "d", "e", "f", "g", "h"].map((id) => (
					<Skeleton key={id} className="h-10 w-full" />
				))}
			</div>
		</div>
	);
}

/** FREE self-verify surface (ADR-066): render the caller's OWN recent chain +
 * the in-browser "Verify integrity" for tenants WITHOUT the paid Audit add-on.
 * The export affordance is hidden (canExport=false) and replaced by the upsell.
 * `tenantPubkeyB64` is resolved once by getAuditAccess() — not re-fetched here. */
async function SelfVerifyData({
	range,
	since,
	until,
	retentionDays,
	tenantPubkeyB64,
}: {
	range: AuditRange;
	since?: string;
	until?: string;
	retentionDays: number;
	tenantPubkeyB64: string;
}) {
	let res: SelfVerifyResponse;
	try {
		res = await gatewayGet<SelfVerifyResponse>("/v1/audit/self-verify");
	} catch (err) {
		if (err instanceof GatewayError) {
			return (
				<>
					<WarmingBanner />
					<EmptyState
						title="No audit events yet"
						description="Audit events appear here as your agents run — the tamper-evident chain starts from the first event."
					/>
				</>
			);
		}
		throw err;
	}
	if (!res.chain_ndjson?.trim()) {
		return (
			<EmptyState
				title="No audit events yet"
				description="Audit events appear here as your agents run — the tamper-evident chain starts from the first event."
			/>
		);
	}
	// The gateway self-verify endpoint returns the whole retention window; the
	// range control filters the DISPLAYED chain in-browser. Compute the lower
	// bound server-side (a deterministic string → no hydration drift): explicit
	// `since` wins; a preset maps via rangeSinceIso; "all" → no filter.
	const windowSince =
		since ?? (range !== "all" ? rangeSinceIso(range) : undefined);
	return (
		<AuditLedgerView
			ndjson={res.chain_ndjson}
			tenantPubkeyB64={tenantPubkeyB64}
			range={since ? undefined : range}
			since={since}
			until={until}
			windowSince={windowSince}
			windowUntil={until}
			windowTotal={res.total_in_window}
			retentionDays={retentionDays}
			canExport={false}
		/>
	);
}

/**
 * Paid Audit add-on surface (f_audit_addon).
 * `tenantPubkeyB64` is resolved once by getAuditAccess() — not re-fetched here.
 * The two gateway calls (summary + export) fire in parallel; a summary failure
 * is best-effort (falls back to client-computed breakdown from loaded rows).
 */
async function LedgerData({
	range,
	since,
	until,
	retentionDays,
	tenantPubkeyB64,
}: {
	range: AuditRange;
	since?: string;
	until?: string;
	retentionDays: number;
	tenantPubkeyB64: string;
}) {
	// Window resolution: explicit since/until wins over preset range.
	const sinceIso = since ?? rangeSinceIso(range);
	const untilIso = until ?? new Date().toISOString();

	// Parallel gateway fetches — summary is best-effort (can fail without aborting
	// the export); the export fetch determines the render path.
	const [summary, ndjsonOrNull] = await Promise.all([
		// Best-effort aggregate. Catch any error → undefined (client fallback).
		gatewayGet<AuditSummary>(
			`/v1/audit/summary?since=${encodeURIComponent(sinceIso)}&until=${encodeURIComponent(untilIso)}`,
		).catch((_: unknown): AuditSummary | undefined => undefined),
		// Required export. GatewayError → null (show empty state); other errors propagate.
		gatewayGetText(
			`/v1/audit/export?since=${encodeURIComponent(sinceIso)}&until=${encodeURIComponent(untilIso)}&limit=1000`,
		).catch((err: unknown): null => {
			if (err instanceof GatewayError) return null;
			throw err;
		}),
	]);

	if (ndjsonOrNull === null) {
		return (
			<>
				<WarmingBanner />
				<EmptyState
					title="No audit events yet"
					description="Audit events appear here as your agents run — the tamper-evident chain starts from the first event."
				/>
			</>
		);
	}
	if (!ndjsonOrNull.trim()) {
		return (
			<EmptyState
				title="No audit events yet"
				description="Audit events appear here as your agents run — the tamper-evident chain starts from the first event."
			/>
		);
	}
	return (
		<AuditLedgerView
			ndjson={ndjsonOrNull}
			tenantPubkeyB64={tenantPubkeyB64}
			range={since ? undefined : range}
			since={since}
			until={until}
			retentionDays={retentionDays}
			summary={summary}
			canExport
		/>
	);
}

export default async function AuditPage({
	searchParams,
}: {
	searchParams: Promise<{
		e2e_fixture?: string;
		range?: string;
		since?: string;
		until?: string;
	}>;
}) {
	const sp = await searchParams;
	// E2E-only hero seam (returns null in prod): drives the REAL in-browser
	// verifier over a REAL anchored/tampered fixture without a live gateway or a
	// seeded Neon, so the launch gate actually asserts the audit hero. Gated on
	// the dev/test e2e auth bypass — never active in production.
	const fixture = sp.e2e_fixture ? await e2eAuditFixture(sp.e2e_fixture) : null;

	// Verification is genesis-anchored (the verifier requires the chain to start at
	// seq 0), so the view is NOT windowable. Force the full-chain-from-genesis view
	// regardless of any legacy ?range=/&since= in the URL — a bookmarked "24h" must
	// not resurrect the empty-window bug (it filtered the genesis-anchored first-1000
	// rows down to zero). The complete ledger is the export.
	const range: AuditRange = "all";
	const since = undefined;
	const until = undefined;

	// Single DB round-trip: resolves entitlements + audit key in parallel.
	// The fixture path bypasses real session/entitlement resolution.
	const access = fixture
		? {
				selfVerify: false as const,
				exportEntitled: false as const,
				retentionDays: 0,
				tenantPubkeyB64: "",
			}
		: await getAuditAccess();

	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			{/* No date-range control: "Verify integrity" recomputes the chain from its
			    GENESIS root (seq 0), so it is inherently NOT windowable — a "last 24h"
			    slice doesn't start at genesis and can't be verified (that was the
			    24h-shows-0 bug). The view shows the first N events from genesis; the
			    complete ledger is the export. */}
			<div className="mb-6 max-w-2xl">
				<h1 className="text-2xl font-semibold text-ink">Audit Ledger</h1>
				<p className="mt-1 text-[13px] text-ink-2">
					A tamper-evident, independently verifiable record of every
					gateway-proxied call and guardrail verdict.
				</p>
			</div>

			<AuditHelpBar exportEntitled={access.exportEntitled} />

			{fixture ? (
				<AuditLedgerView
					ndjson={fixture.ndjson}
					tenantPubkeyB64={fixture.tenantPubkeyB64}
				/>
			) : access.exportEntitled ? (
				// Paid Audit add-on: full chain + verify + Article-12 evidence export.
				// Wrapped in Suspense so the page shell (header) streams first; the
				// ledger content streams in after the gateway round-trips complete.
				<Suspense fallback={<AuditFallback />}>
					<LedgerData
						range={range}
						since={since}
						until={until}
						retentionDays={access.retentionDays}
						tenantPubkeyB64={access.tenantPubkeyB64}
					/>
				</Suspense>
			) : access.selfVerify ? (
				// ADR-066 free surface: SEE + verify your OWN chain; export is the upsell.
				<Suspense fallback={<AuditFallback />}>
					<SelfVerifyData
						range={range}
						since={since}
						until={until}
						retentionDays={access.retentionDays}
						tenantPubkeyB64={access.tenantPubkeyB64}
					/>
				</Suspense>
			) : (
				// Self-verify switched off for this workspace (rare override).
				<AuditSalesSurface />
			)}
		</div>
	);
}
