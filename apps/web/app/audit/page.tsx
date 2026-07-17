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
 */

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
import { EmptyState } from "@tracelanedev/ui";
import { eq } from "drizzle-orm";
import type { Metadata } from "next";

export const metadata: Metadata = { title: "Audit Ledger — Tracelane" };
export const dynamic = "force-dynamic";

/** Date-range windows for the ledger view → the export `since`/`until` params.
 * `all` maps to a wide floor (the ledger is append-only, no automatic expiry). */
const RANGES = { "24h": 1, "7d": 7, "30d": 30, "90d": 90, all: null } as const;
export type AuditRange = keyof typeof RANGES;
function isRange(v: string | undefined): v is AuditRange {
	return v != null && v in RANGES;
}
function rangeSinceIso(range: AuditRange): string {
	const days = RANGES[range];
	return days == null
		? "2020-01-01T00:00:00Z"
		: new Date(Date.now() - days * 86_400_000).toISOString();
}

/** Validate that a string looks like an ISO 8601 datetime (safe to use in URLs). */
function isIso(v: string | undefined): v is string {
	return typeof v === "string" && /^\d{4}-\d{2}-\d{2}/.test(v);
}

async function getAuditAccess(): Promise<{
	selfVerify: boolean;
	exportEntitled: boolean;
	retentionDays: number;
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
	const entitlements = await resolveEntitlements(row?.id, plan);
	return {
		selfVerify: entitlements.audit_self_verify,
		exportEntitled: entitlements.audit_ledger,
		// The plan's trace-retention (spans TTL). The audit_log itself has NO TTL
		// (append-only) — shown as a contrast so the user sees the ledger outlives
		// their trace data.
		retentionDays: entitlements.retention_days,
	};
}

/** The tenant's TRUSTED Ed25519 audit pubkey (base64), resolved server-side —
 * the ADR-062 C2 out-of-band trust root for the in-browser verifier. Empty when
 * the tenant has no audit key yet (verification is then chain-only). */
async function fetchTenantPubkeyB64(): Promise<string> {
	const session = await requireSession();
	const [tenantRow] = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	if (!tenantRow?.id) return "";
	const [keyRow] = await db
		.select({ pubkey: tenantAuditKeys.publicKeyB64 })
		.from(tenantAuditKeys)
		.where(eq(tenantAuditKeys.tenantId, tenantRow.id))
		.limit(1);
	return keyRow?.pubkey ?? "";
}

/** Server verdict shape returned by the FREE gateway self-verify endpoint
 * (ADR-066). We consume `chain_ndjson` to render + re-verify in the browser. */
interface SelfVerifyResponse {
	chain_ndjson: string;
}

/** FREE self-verify surface (ADR-066): render the caller's OWN recent chain +
 * the in-browser "Verify integrity" for tenants WITHOUT the paid Audit add-on.
 * The export affordance is hidden (canExport=false) and replaced by the upsell. */
async function SelfVerifyData({ retentionDays }: { retentionDays: number }) {
	const tenantPubkeyB64 = await fetchTenantPubkeyB64();
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
	return (
		<AuditLedgerView
			ndjson={res.chain_ndjson}
			tenantPubkeyB64={tenantPubkeyB64}
			retentionDays={retentionDays}
			canExport={false}
		/>
	);
}

async function LedgerData({
	range,
	since,
	until,
	retentionDays,
}: {
	range: AuditRange;
	since?: string;
	until?: string;
	retentionDays: number;
}) {
	// The tenant's audit signing pubkey — the ADR-062 C2 trust root. The dashboard
	// is TLS-authenticated and the user is authenticated to their own tenant, so
	// serving their own pubkey server-side IS the trusted out-of-band channel; the
	// client verifier fails closed if the exported bundle's key differs.
	let tenantPubkeyB64 = "";
	const session = await requireSession();
	const [tenantRow] = await db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.workosOrgId, session.tenantId))
		.limit(1);
	if (tenantRow?.id) {
		const [keyRow] = await db
			.select({ pubkey: tenantAuditKeys.publicKeyB64 })
			.from(tenantAuditKeys)
			.where(eq(tenantAuditKeys.tenantId, tenantRow.id))
			.limit(1);
		tenantPubkeyB64 = keyRow?.pubkey ?? "";
	}

	// Window resolution: explicit since/until wins over preset range.
	const sinceIso = since ?? rangeSinceIso(range);
	const untilIso = until ?? new Date().toISOString();

	// Aggregate summary (total + per-day + per-type), computed server-side in
	// ClickHouse so the breakdown is exact for a large ledger — the export row cap
	// does not apply. Best-effort: a failure falls back to the client computing an
	// approximate breakdown from the loaded rows.
	let summary: AuditSummary | undefined;
	try {
		summary = await gatewayGet<AuditSummary>(
			`/v1/audit/summary?since=${encodeURIComponent(sinceIso)}&until=${encodeURIComponent(untilIso)}`,
		);
	} catch {
		summary = undefined;
	}

	let ndjson: string;
	try {
		// The selected window; the gateway resolves the tenant from the forwarded token.
		ndjson = await gatewayGetText(
			`/v1/audit/export?since=${encodeURIComponent(sinceIso)}&until=${encodeURIComponent(untilIso)}&limit=1000`,
		);
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
	if (!ndjson.trim()) {
		return (
			<EmptyState
				title="No audit events yet"
				description="Audit events appear here as your agents run — the tamper-evident chain starts from the first event."
			/>
		);
	}
	return (
		<AuditLedgerView
			ndjson={ndjson}
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

	// Explicit since/until wins over preset range.
	const hasSinceUntil = isIso(sp.since) && isIso(sp.until);
	const range: AuditRange = isRange(sp.range) ? sp.range : "all";
	const since = hasSinceUntil ? sp.since : undefined;
	const until = hasSinceUntil ? sp.until : undefined;

	const access = fixture
		? { selfVerify: false, exportEntitled: false, retentionDays: 0 }
		: await getAuditAccess();
	return (
		<main className="mx-auto max-w-5xl p-6">
			<div className="mb-6">
				<h1 className="text-2xl font-semibold text-ink">Audit Ledger</h1>
				<p className="mt-1 text-[13px] text-ink-2">
					A tamper-evident, independently verifiable record of every
					gateway-proxied call and guardrail verdict.
				</p>
			</div>
			{fixture ? (
				<AuditLedgerView
					ndjson={fixture.ndjson}
					tenantPubkeyB64={fixture.tenantPubkeyB64}
				/>
			) : access.exportEntitled ? (
				// Paid Audit add-on: full chain + verify + Article-12 evidence export.
				<LedgerData
					range={range}
					since={since}
					until={until}
					retentionDays={access.retentionDays}
				/>
			) : access.selfVerify ? (
				// ADR-066 free surface: SEE + verify your OWN chain; export is the upsell.
				<SelfVerifyData retentionDays={access.retentionDays} />
			) : (
				// Self-verify switched off for this workspace (rare override).
				<AuditSalesSurface />
			)}
		</main>
	);
}
