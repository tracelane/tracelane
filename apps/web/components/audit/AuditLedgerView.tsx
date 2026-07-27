"use client";

import {
	deriveAuditVerdict,
	humanizeVerdictKind,
	isAlarm,
} from "@/app/audit/verdict";
import {
	type VerifyReport,
	verifyLedgerText,
} from "@tracelanedev/audit-verifier";
import { Button, Card, StatCard, cn } from "@tracelanedev/ui";
import Link from "next/link";
import { useCallback, useMemo, useRef, useState } from "react";

interface Row {
	seq: number;
	event_type: string;
	event_time: string;
	/** Who/what emitted the event (e.g. "user1", "system"). */
	actor?: string;
	/** The event content the row hash actually covers. For "v2.1" exports this is a
	 * JSON *string* (the verbatim canonical payload that was hashed); for older
	 * formats it's the nested payload object. Shown so the hash is meaningful. */
	payload?: unknown;
	row_hash: string;
	prev_hash: string;
	rekor_entry_id?: string | null;
}

/** Parse the ledger rows, EXCLUDING the per-batch `type:"anchor"` records — those
 * are anchor metadata, not chain events. Including them (the old bug) inflated the
 * event count and rendered a phantom `# — ← —` row that also zeroed the chain head. */
function parseRows(ndjson: string): Row[] {
	const rows: Row[] = [];
	for (const line of ndjson.split(/\r?\n/)) {
		if (!line.trim()) continue;
		try {
			const rec = JSON.parse(line) as Row & { type?: string };
			if (rec.type === "anchor") continue;
			if (typeof rec.row_hash !== "string" || rec.row_hash === "") continue;
			rows.push(rec);
		} catch {
			// the verifier surfaces parse errors authoritatively; the viz just skips
		}
	}
	return rows;
}

const short = (h: string) => (h ? `${h.slice(0, 12)}…` : "—");

/** Server-computed aggregate (matches the gateway `AuditSummary` JSON). Exact for
 * any ledger size — the export row cap does not apply. */
export interface AuditSummary {
	total: number;
	first_event?: string;
	last_event?: string;
	by_day: Array<{ day: string; count: number }>;
	by_type: Array<{ event_type: string; count: number }>;
}

/** Thousands-grouped integer, deterministic (no locale → no hydration drift). */
const fmtCount = (n: number) =>
	n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");

/** Full unambiguous wall-clock datetime from ISO string (no locale → no hydration
 * drift). Shows "YYYY-MM-DD HH:MM:SS" so midnight timestamps are not confused
 * with relative offsets. */
function fmtDateTime(iso: string): string {
	const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/.exec(iso);
	return m ? `${m[1]} ${m[2]}` : iso;
}

/** Pretty-print the exact content a row hash covers. v2.1 payloads are JSON
 * strings — parse then re-indent; non-JSON strings show raw; objects stringify. */
function formatPayload(payload: unknown): string {
	if (payload == null || payload === "") return "(no payload)";
	let obj: unknown = payload;
	if (typeof payload === "string") {
		try {
			obj = JSON.parse(payload);
		} catch {
			return payload;
		}
	}
	try {
		return JSON.stringify(obj, null, 2);
	} catch {
		return String(payload);
	}
}

/** A compact one-line preview of the hashed content for the collapsed row. */
function payloadPreview(payload: unknown): string {
	if (payload == null || payload === "") return "";
	const s = (typeof payload === "string" ? payload : JSON.stringify(payload))
		.replace(/\s+/g, " ")
		.trim();
	return s.length > 60 ? `${s.slice(0, 60)}…` : s;
}

/** The public Sigstore Rekor v2 log this product anchors to (ADR-062). The docs
 * publish this exact host as "the public log". A logIndex is ONLY meaningful WITH
 * this log id — v2 (`log2025-1`) and the legacy v1 log have independent index
 * spaces, so a bare index quoted without its log is ambiguous/wrong. */
const PUBLIC_LOG = "log2025-1.rekor.sigstore.dev";
/** The log's signed checkpoint — the ONE independently-fetchable v2 artifact
 * (tree size + root + the log's signature over them). Rekor v2 is a tiled log with
 * NO per-entry web page (GET-by-index is 501/404), and search.sigstore.dev only
 * searches the legacy v1 log — so we NEVER link a v2 index there. Each root's
 * inclusion proof + this checkpoint travel in the exported evidence and verify
 * OFFLINE against the pinned log key. */
const CHECKPOINT_URL = `https://${PUBLIC_LOG}/checkpoint`;

/** Rows per page in the chain viz. The whole ledger is already in memory; we slice
 * so a 600-event chain renders ~50 nodes, not 600 — the "super fast" requirement. */
const PAGE_SIZE = 50;
/** Max anchor chips shown before the "Show N more" toggle in TrustPanel. */
const ANCHOR_PREVIEW = 12;

interface AnchorRec {
	type?: string;
	anchor_state?: string;
	rekor?: { log_index?: string };
}

/** The per-batch `type:"anchor"` records — used only to list Rekor log indices;
 * the verifier does the real cryptographic work over the full bundle. */
function parseAnchors(ndjson: string): AnchorRec[] {
	const out: AnchorRec[] = [];
	for (const line of ndjson.split(/\r?\n/)) {
		if (!line.trim()) continue;
		try {
			const rec = JSON.parse(line) as AnchorRec;
			if (rec.type === "anchor") out.push(rec);
		} catch {
			// the verifier surfaces parse errors authoritatively; the viz skips
		}
	}
	return out;
}

/** base64 → bytes (browser). `undefined` on empty/invalid — the verifier then
 * runs chain-only (never a green signature/anchor claim). */
function b64ToBytes(b64: string): Uint8Array | undefined {
	if (!b64) return undefined;
	try {
		const bin = atob(b64);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	} catch {
		return undefined;
	}
}

// ---------------------------------------------------------------------------
// CopyButton — clipboard affordance for short IDs / keys
// ---------------------------------------------------------------------------
function CopyButton({
	value,
	label = "Copy",
}: { value: string; label?: string }) {
	const [copied, setCopied] = useState(false);
	const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	function copy() {
		navigator.clipboard.writeText(value).then(() => {
			setCopied(true);
			if (timerRef.current) clearTimeout(timerRef.current);
			timerRef.current = setTimeout(() => setCopied(false), 1800);
		});
	}

	return (
		<button
			type="button"
			onClick={copy}
			title={`Copy ${label}`}
			aria-label={copied ? "Copied!" : `Copy ${label}`}
			className="rounded px-1 py-0.5 text-[10px] text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
		>
			{copied ? "✓" : "⎘"}
		</button>
	);
}

// ---------------------------------------------------------------------------
// LogIndexChip — a coordinate in log2025-1 (NOT a link: Rekor v2 has no per-entry
// web viewer, and search.sigstore.dev resolves the WRONG log — the legacy v1). The
// index is verified offline from the exported inclusion proof + checkpoint.
// ---------------------------------------------------------------------------
function LogIndexChip({ index }: { index: string }) {
	return (
		<span
			title={`Index ${index} in Sigstore Rekor v2 (${PUBLIC_LOG}). Verified offline from your evidence bundle's inclusion proof + signed checkpoint — Rekor v2 is a tiled log with no per-entry web page.`}
			className="inline-flex items-center gap-1 rounded-md border border-seal-line bg-seal-soft/60 px-1.5 py-0.5 font-mono text-[11px] text-seal-ink"
		>
			logIndex {index}
		</span>
	);
}

// ---------------------------------------------------------------------------
// CompactColumnChart — vertical bar chart (SQRT scale, weekly agg, click filter)
// ---------------------------------------------------------------------------

/** ISO week start (Monday) for a given day string "YYYY-MM-DD". */
function weekStart(day: string): string {
	const d = new Date(`${day}T00:00:00Z`);
	const dow = d.getUTCDay(); // 0=Sun
	const diff = dow === 0 ? -6 : 1 - dow;
	d.setUTCDate(d.getUTCDate() + diff);
	return d.toISOString().slice(0, 10);
}

function aggregateToWeeks(
	byDay: Array<{ day: string; count: number }>,
): Array<{ day: string; count: number; label: string }> {
	const weeks = new Map<
		string,
		{ day: string; count: number; label: string }
	>();
	for (const { day, count } of byDay) {
		const ws = weekStart(day);
		const existing = weeks.get(ws);
		if (existing) {
			existing.count += count;
		} else {
			weeks.set(ws, { day: ws, count, label: `w/o ${ws}` });
		}
	}
	return [...weeks.values()].sort((a, b) => (a.day < b.day ? -1 : 1));
}

/** Compact inline column chart for event volume. One slim vertical bar per
 * day (or per ISO week when window > 30 days). SQRT scale makes
 * 50 vs 200 vs 300k all distinguishable. Click a column to narrow the window
 * to that day (drives URL so the server refetches). Bars use neutral ink-muted
 * tokens — no purple/accent, supporting context only. */
function CompactColumnChart({
	byDay,
}: {
	byDay: Array<{ day: string; count: number }>;
}) {
	const useWeeks = byDay.length > 30;
	const buckets = useWeeks
		? aggregateToWeeks(byDay)
		: byDay.map((d) => ({ ...d, label: d.day }));

	if (buckets.length === 0) return null;

	const maxCount = Math.max(...buckets.map((b) => b.count), 1);
	const maxH = 48; // px

	return (
		<details className="group mt-3">
			<summary className="flex cursor-pointer list-none items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-ink-3 hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal [&::-webkit-details-marker]:hidden">
				<span aria-hidden className="transition-transform group-open:rotate-90">
					▸
				</span>
				Volume detail
				{useWeeks && (
					<span className="normal-case font-normal text-ink-3">(weekly)</span>
				)}
			</summary>

			<div
				className="mt-2 flex items-end gap-px overflow-x-auto pb-1"
				style={{ minHeight: `${maxH + 16}px` }}
				aria-label="Events per day chart"
			>
				{buckets.map((b) => {
					const h = Math.max(
						Math.round((Math.sqrt(b.count) / Math.sqrt(maxCount)) * maxH),
						2,
					);
					return (
						<div
							key={b.day}
							title={`${b.label}: ${fmtCount(b.count)} events (√-scaled)`}
							className="shrink-0 rounded-sm bg-surface-3"
							style={{ width: "8px", height: `${h}px` }}
						>
							<span className="sr-only">
								{b.label}: {fmtCount(b.count)} events
							</span>
						</div>
					);
				})}
			</div>
			<p className="mt-1 text-[10px] text-ink-3">
				One bar per {useWeeks ? "week" : "day"} · √-scaled. This is the complete
				chain from genesis, so it is not date-filtered.
			</p>
		</details>
	);
}

// ---------------------------------------------------------------------------
// NegativeScenarioPanel — explains what a failed verification looks like.
// Collapsible so it doesn't dominate the page but is always accessible.
// ---------------------------------------------------------------------------
function NegativeScenarioPanel() {
	return (
		<details className="group">
			<summary className="flex cursor-pointer list-none items-center gap-2 rounded-lg border border-line bg-surface px-4 py-3 text-[13px] font-medium text-ink-2 hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal [&::-webkit-details-marker]:hidden">
				<span
					aria-hidden
					className="shrink-0 text-ink-3 transition-transform group-open:rotate-90"
				>
					▸
				</span>
				What does a failed verification look like?
			</summary>
			<div className="mt-2 rounded-lg border border-line bg-surface p-5">
				<p className="max-w-2xl text-[13px] text-ink-2">
					The verifier runs entirely in your browser — nothing is trusted from
					our servers. If any event in the ledger is tampered with or reordered
					after recording, the verifier catches it:
				</p>
				<ul className="mt-3 space-y-3">
					<li className="flex gap-3">
						<span className="mt-0.5 shrink-0 font-bold text-danger">✗</span>
						<div>
							<span className="text-[13px] font-medium text-ink">
								Row hash mismatch.
							</span>{" "}
							<span className="text-[13px] text-ink-2">
								Recomputing a row&apos;s SHA-256 hash over its payload will not
								match the stored hash. The verifier highlights that row in{" "}
								<span className="font-medium text-danger">loud red</span> with
								the exact <code className="font-mono text-ink-2">seq</code>{" "}
								number.
							</span>
						</div>
					</li>
					<li className="flex gap-3">
						<span className="mt-0.5 shrink-0 font-bold text-danger">✗</span>
						<div>
							<span className="text-[13px] font-medium text-ink">
								Chain break.
							</span>{" "}
							<span className="text-[13px] text-ink-2">
								Every row&apos;s{" "}
								<code className="font-mono text-ink-2">prev_hash</code> must
								equal the previous row&apos;s{" "}
								<code className="font-mono text-ink-2">row_hash</code>. A
								tampered or reordered row breaks this link at that point — and
								at every subsequent row.
							</span>
						</div>
					</li>
					<li className="flex gap-3">
						<span className="mt-0.5 shrink-0 font-bold text-danger">✗</span>
						<div>
							<span className="text-[13px] font-medium text-ink">
								Verdict: Integrity check failed.
							</span>{" "}
							<span className="text-[13px] text-ink-2">
								The &ldquo;Verify integrity&rdquo; result shows{" "}
								<span className="font-medium text-danger">red</span>, not green
								— with the first broken seq number and the reason (hash
								mismatch, chain break, or missing anchor proof).
							</span>
						</div>
					</li>
				</ul>
				<p className="mt-3 text-[12px] text-ink-3">
					<span className="font-medium text-ink-2">
						The word &ldquo;evident&rdquo; is deliberate.
					</span>{" "}
					This is tamper-evident protection: a change is visible to any
					independent verifier who recomputes the hashes offline. Altering an
					event silently is not possible; getting away with it undetected is
					what the chain makes hard. The verifier code is open-source and runs
					locally — you do not need to trust our read-out.
				</p>
			</div>
		</details>
	);
}

// ---------------------------------------------------------------------------
// AboutLedger — self-documenting panel: scope, types, span, histogram
// ---------------------------------------------------------------------------
function AboutLedger({
	total,
	loadedCount,
	eventTypeCounts,
	byDay,
	anchoredCount,
	retentionDays,
	serverTotal,
	loadCap,
}: {
	total: number;
	loadedCount: number;
	eventTypeCounts: Array<[string, number]>;
	byDay: Array<{ day: string; count: number }>;
	anchoredCount: number;
	retentionDays?: number;
	/** True when `total` is the gateway's exact window count (paid export path).
	 * False on the free self-verify path, where `total` is a CLIENT count over the
	 * capped fetch — used only for the honest "capped load" note below. */
	serverTotal: boolean;
	/** The self-verify fetch cap (rows) — for the honest free-path label. */
	loadCap: number;
}) {
	// On the free path a full-cap load means the ledger may be larger than shown.
	const cappedLoad = !serverTotal && loadedCount >= loadCap;
	return (
		<Card className="bg-surface p-5">
			<div className="max-w-3xl">
				<h2 className="text-sm font-semibold text-ink">About this ledger</h2>
				<p className="mt-1 text-[13px] text-ink-2">
					An <strong>append-only, tamper-evident</strong> record of what the
					gateway did — every proxied request and every guardrail / eval verdict
					— so you can prove to an auditor exactly what ran and that the record
					was not altered. It covers <strong>gateway-proxied traffic</strong>
					{"; full-fidelity spans sent via the SDK / OTLP live in "}
					<Link
						href="/traces"
						className="text-ink-2 underline-offset-2 hover:underline hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
					>
						Traces
					</Link>{" "}
					and are not part of this chain.
				</p>
			</div>

			{/* Stat tiles — the two that PROVE something about the ledger: how much
			    is publicly anchored, and that it never expires. (The confusing
			    "First–last event (loaded)" and a redundant event count were removed
			    — the event count already appears in the verify panel + chain header.) */}
			<div className="mt-4 grid grid-cols-2 gap-3 border-t border-line pt-3">
				<StatCard
					label="Public anchoring"
					value={
						anchoredCount > 0 ? (
							<span className="tabular-nums">{anchoredCount} anchored</span>
						) : (
							"best-effort"
						)
					}
					tone={anchoredCount > 0 ? "ok" : "default"}
					sub="batches within the events shown · Sigstore Rekor v2"
					hint="Events are grouped into fixed-size batches (about 100 events each) as they accrue; each batch's Merkle root is anchored once to Sigstore's public transparency log, starting from your ledger's genesis. This count is the batches falling within the events loaded here — the full ledger has more, and every batch's proof travels in the export."
				/>
				<StatCard
					label="Retention"
					value="Append-only"
					sub="no automatic expiry"
					hint="The audit ledger is append-only — it has no TTL and outlives your plan's trace-retention window"
				/>
			</div>

			{retentionDays ? (
				<p className="mt-2 text-[11px] text-ink-3">
					Full-fidelity trace data expires after{" "}
					<span className="tabular-nums">{retentionDays}</span> days on your
					plan; this evidence ledger does not.
				</p>
			) : null}

			{/* Volume detail — demoted inside <details> so it doesn't fight the
			    trust panel for attention. The About panel's message is TRUST. */}
			<CompactColumnChart byDay={byDay} />

			{eventTypeCounts.length > 0 && (
				<div className="mt-3">
					<div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
						Event types recorded (this window)
					</div>
					<div className="flex flex-wrap gap-1.5">
						{eventTypeCounts.map(([t, c]) => (
							<span
								key={t}
								className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2/50 px-2 py-0.5 text-[11px]"
							>
								<span className="font-mono text-ink-2">{t}</span>
								<span className="tabular-nums font-medium text-ink">
									{fmtCount(c)}
								</span>
							</span>
						))}
					</div>
				</div>
			)}

			{total > loadedCount && (
				<p className="mt-3 text-[11px] text-ink-3">
					The chain view below shows the first{" "}
					<span className="tabular-nums">{fmtCount(loadedCount)}</span> of{" "}
					<span className="tabular-nums">{fmtCount(total)}</span> events, from
					your chain&apos;s genesis — enough to verify integrity in the browser.
					The <strong>complete</strong> ledger is the export below.
				</p>
			)}

			{/* Free-path truncation: a full-cap load means the ledger MAY hold more
			    than shown. The paid-path `total > loadedCount` note can't fire here
			    (total === loadedCount by construction), so disclose it explicitly. */}
			{cappedLoad && (
				<p className="mt-3 text-[11px] text-ink-3">
					Loaded the most recent{" "}
					<span className="tabular-nums">{fmtCount(loadCap)}</span> events to
					verify in your browser. Your ledger may hold more — this is a fetch
					limit, not the full total. Narrow the range, or use the{" "}
					<span className="font-mono">tlane verify</span> CLI, for the complete
					chain.
				</p>
			)}
		</Card>
	);
}

// ---------------------------------------------------------------------------
// TrustPanel — the ONE dominant integrity surface (ADR-062)
// Combines: anchor status + verify CTA + post-verify verdict + claim breakdown.
// The ONLY Lava CTA on the page. The ONLY large green element is "Verified".
// ---------------------------------------------------------------------------
function TrustPanel({
	anchoredIndices,
	hasAnchorRecords,
	report,
	verifying,
	onVerify,
	rowCount,
	windowTotal,
	chainHead,
	keyId,
	tenantPubkeyB64,
	anchorRecords,
	isTruncated = false,
}: {
	anchoredIndices: string[];
	hasAnchorRecords: boolean;
	report: VerifyReport | null;
	verifying: boolean;
	onVerify: () => void;
	rowCount: number;
	/** EXACT total events in the window — so "Events" reads "Showing N of {total}"
	 * and the loaded render-cap never reads as the whole ledger. */
	windowTotal: number;
	chainHead: string;
	keyId: string;
	tenantPubkeyB64?: string;
	anchorRecords: AnchorRec[];
	/** The visible rows are a subset of the full ledger — the chain head shown is
	 * the loaded page's tip, not the ledger tip (audit #10). */
	isTruncated?: boolean;
}) {
	// ONE verdict drives the banner, the alarm styling, and the claim cards — so
	// the headline can never be greener than the details (the green-while-broken
	// bug: the old `verified` ignored `signatures_valid`). See app/audit/verdict.ts.
	const verdict = deriveAuditVerdict(report);
	const verified = verdict.state === "verified";
	const stripped = verdict.state === "stripped";
	const alarm = isAlarm(verdict);
	// Collapsed by default: show first ANCHOR_PREVIEW chips only.
	const [showAllAnchors, setShowAllAnchors] = useState(false);

	return (
		<Card
			provenance={!alarm}
			className={cn(
				"p-5",
				alarm && "border border-danger/50 bg-danger-soft/30",
			)}
		>
			{/* ── Status indicator ─────────────────────────────────────────── */}
			{/* Column on narrow (the CTA sits BELOW the explainer, full-width, so the
			    explainer never squeezes to one word per line); row from sm up. */}
			<div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between sm:gap-x-6">
				<div className="flex-1 min-w-0">
					{/* Pre-verify: neutral "ready" state */}
					{verdict.state === "ready" && (
						<div className="flex items-start gap-3">
							<span aria-hidden className="mt-0.5 text-xl text-ink-3 shrink-0">
								◆
							</span>
							<div>
								<div className="text-base font-semibold text-ink">
									Ready to verify
								</div>
								<p className="mt-0.5 text-[13px] text-ink-2">
									<strong>What this does:</strong> re-hashes every event and
									re-checks each link to the one before it, starting from your
									chain&apos;s genesis — proving the events are intact and in
									order (any change would break a hash). It runs entirely{" "}
									<strong>in your browser</strong> over the ledger (SHA-256,
									domain-separated) — nothing is trusted from our server, so a
									green result is one you reproduced yourself.
								</p>
							</div>
						</div>
					)}

					{/* GREEN: chain + signatures + ≥1 public anchor all verified. */}
					{verdict.state === "verified" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-seal-ink shrink-0 font-bold"
							>
								✓
							</span>
							<div>
								<div className="text-xl font-bold text-seal-ink">Verified</div>
								<p className="mt-0.5 text-[13px] text-seal-ink/80 tabular-nums">
									Hash chain intact · {verdict.rows} rows · off-platform
									reproducible. Signed by your key, and {verdict.anchors} root
									{verdict.anchors === 1 ? "" : "s"} anchored in Sigstore&apos;s{" "}
									<span className="font-mono">{PUBLIC_LOG}</span> append-only
									log, checkpoint verified.
								</p>
							</div>
						</div>
					)}

					{/* GREEN (ADR-070): windowed verify — genesis predates the retention
					    window, so the chain is rooted at a public Rekor anchor and verified
					    from that seq to the tip. Honest scope: earlier rows are unverified. */}
					{verdict.state === "verified_windowed" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-seal-ink shrink-0 font-bold"
							>
								✓
							</span>
							<div>
								<div className="text-xl font-bold text-seal-ink">Verified</div>
								<p className="mt-0.5 text-[13px] text-seal-ink/80 tabular-nums">
									Hash chain intact from seq {verdict.fromSeq} to the latest
									entry, rooted at {verdict.anchors} public Rekor anchor
									{verdict.anchors === 1 ? "" : "s"} (Sigstore{" "}
									<span className="font-mono">{PUBLIC_LOG}</span>, checkpoint
									verified). Earlier entries predate your retention window — run{" "}
									<span className="font-mono">tlane verify</span> over the full
									export to verify from genesis.
								</p>
							</div>
						</div>
					)}

					{/* GREEN (qualified): chain intact + signed, but no public anchor fell
					    inside this loaded view — still tamper-evident, just not anchored here. */}
					{verdict.state === "chain_only" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-seal-ink shrink-0 font-bold"
							>
								✓
							</span>
							<div>
								<div className="text-xl font-bold text-seal-ink">
									Chain verified
								</div>
								<p className="mt-0.5 text-[13px] text-seal-ink/80 tabular-nums">
									Hash chain intact · {verdict.rows} rows · off-platform
									reproducible, signed by your key. No public anchor fell inside
									this view — run{" "}
									<span className="font-mono">tlane verify</span> over the full
									export for the public-log proofs.
								</p>
							</div>
						</div>
					)}

					{/* NEUTRAL: no rows in this view — nothing to verify. Not green
					    (verifying zero rows is not a pass) and not an alarm. */}
					{verdict.state === "empty" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-seal-ink/50 shrink-0 font-bold"
							>
								—
							</span>
							<div>
								<div className="text-xl font-bold text-seal-ink/70">
									Nothing to verify
								</div>
								<p className="mt-0.5 text-[13px] text-seal-ink/60">
									This view has no audit entries yet — there is nothing to
									verify. Entries appear here as your workspace records events.
								</p>
							</div>
						</div>
					)}

					{/* RED: broken hash chain. */}
					{verdict.state === "chain_broken" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-danger shrink-0 font-bold"
							>
								✗
							</span>
							<div>
								<div className="text-xl font-bold text-danger">
									Integrity check failed
								</div>
								<p className="mt-0.5 text-[13px] text-danger/80">
									The hash chain is broken
									{verdict.firstSeq != null
										? ` at seq ${verdict.firstSeq}`
										: ""}{" "}
									— see the chain view below.
								</p>
							</div>
						</div>
					)}

					{/* RED (ADR-070): a windowed view with no public anchor inside it —
					    nothing publicly trusted roots the loaded rows. */}
					{verdict.state === "unrooted_window" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-danger shrink-0 font-bold"
							>
								✗
							</span>
							<div>
								<div className="text-xl font-bold text-danger">
									Cannot verify this window
								</div>
								<p className="mt-0.5 text-[13px] text-danger/80">
									This view starts after your chain&apos;s genesis (older rows
									are past your retention window) and has no public Rekor anchor
									inside it to establish trust. Configure your tenant audit
									public key so an anchor in this view can root the chain.
								</p>
							</div>
						</div>
					)}

					{/* RED: a batch claims public anchoring but its proof is missing. */}
					{verdict.state === "stripped" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-danger shrink-0 font-bold"
							>
								✗
							</span>
							<div>
								<div className="text-xl font-bold text-danger">
									Anchor proof missing
								</div>
								<p className="mt-0.5 text-[13px] text-danger/80">
									A batch claims to be publicly anchored but its proof is absent
									— a possible strip or downgrade.
								</p>
							</div>
						</div>
					)}

					{/* RED: chain intact, but a real public-anchor check failed. */}
					{verdict.state === "signature_failed" && (
						<div className="flex items-start gap-3">
							<span
								aria-hidden
								className="mt-0.5 text-2xl text-danger shrink-0 font-bold"
							>
								✗
							</span>
							<div>
								<div className="text-xl font-bold text-danger">
									Anchor verification failed
								</div>
								<p className="mt-0.5 text-[13px] text-danger/80">
									The hash chain is intact, but a public-anchor check did not
									pass: {verdict.reasons.map(humanizeVerdictKind).join("; ")}.
								</p>
							</div>
						</div>
					)}
				</div>

				{/* The SINGLE Lava CTA — Verify integrity (full-width on narrow). */}
				<div className="shrink-0">
					<Button
						variant="primary"
						onClick={onVerify}
						disabled={verifying || rowCount === 0}
						className="cta-lava w-full sm:w-auto"
					>
						{verifying ? "Verifying…" : "Verify integrity"}
					</Button>
				</div>
			</div>

			{/* ── Anchor status line — conditionally shows "Publicly anchored"
			     only when anchor records are present (hasAnchorRecords). When
			     absent, shows "Not yet anchored" so we never claim public anchoring
			     without evidence. The Playwright e2e test checks for the full text
			     "Publicly anchored (Sigstore Rekor v2)" on the anchored fixture. */}
			{/* What-to-do-next — shown ONLY on a real failure (alarm). The banner says
			    WHAT broke; a user also needs to know it is not their config and what the
			    remediation path is. */}
			{alarm && (
				<div className="mt-4 rounded-lg border border-danger/40 bg-danger-soft/20 p-4">
					<div className="text-[12px] font-semibold text-ink">
						What this means &amp; what to do next
					</div>
					<ol className="mt-1.5 list-decimal space-y-1.5 pl-4 text-[12px] text-ink-2">
						<li>
							This is the check working, not a product bug: the verifier ran in
							your browser and the ledger it saw does <strong>not</strong> match
							its own hashes. Something altered the events after they were
							recorded — most often the exported file was edited or truncated
							after download.
						</li>
						<li>
							Re-download a fresh copy from{" "}
							<strong>Download the complete ledger</strong> below and verify
							again. A clean export that still fails points at the stored
							ledger, not your file.
						</li>
						<li>
							If a fresh export still fails, treat it as a potential integrity
							incident and{" "}
							<a
								href="/support"
								className="font-medium text-danger underline-offset-2 hover:underline"
							>
								contact Tracelane support
							</a>{" "}
							with the first failing <code className="font-mono">seq</code>{" "}
							shown below and your export attached. Nothing in the app can
							&ldquo;fix&rdquo; a broken chain — that is the point of
							tamper-evidence.
						</li>
					</ol>
				</div>
			)}

			<div className="mt-4 space-y-2 border-t border-line pt-3">
				{/* Status line — wraps cleanly on narrow (no ml-auto orphaning). */}
				<div className="flex flex-wrap items-center gap-x-3 gap-y-1">
					{hasAnchorRecords ? (
						<span className="flex items-center gap-1.5">
							<span
								aria-hidden
								className={cn(
									"text-sm",
									verified
										? "text-seal-ink"
										: alarm
											? "text-danger"
											: "text-ink-3",
								)}
							>
								◆
							</span>
							<span className="text-[12px] font-medium text-ink">
								Publicly anchored (Sigstore Rekor v2)
							</span>
						</span>
					) : (
						<span className="flex items-center gap-1.5">
							<span aria-hidden className="text-sm text-ink-3">
								◇
							</span>
							<span className="text-[12px] text-ink-3">
								Not yet anchored — begins with your first gateway-proxied batch
							</span>
						</span>
					)}
					{hasAnchorRecords && !alarm && (
						<span className="text-[12px] text-ink-2 tabular-nums">
							{anchoredIndices.length} batch
							{anchoredIndices.length === 1 ? "" : "es"} anchored
						</span>
					)}
					{alarm && stripped && (
						<span className="text-[12px] font-medium text-danger">
							Anchor proof missing — possible strip/downgrade
						</span>
					)}
				</div>

				{/* Anchored roots — the indices are ALWAYS named with their log
				    (v2 `log2025-1` and the legacy v1 log have independent index
				    spaces; a bare index is ambiguous). They are NOT links: Rekor v2
				    has no per-entry web page, and search.sigstore.dev resolves the
				    WRONG (v1) log. Verification is offline from the exported bundle;
				    the ONE fetchable public artifact is the signed checkpoint. */}
				{anchoredIndices.length > 0 && (
					<div>
						<div className="mb-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
							<span className="text-[10px] font-semibold uppercase tracking-wide text-ink-3">
								Anchored roots in
							</span>
							<a
								href={CHECKPOINT_URL}
								target="_blank"
								rel="noreferrer noopener"
								title="Fetch this log's signed checkpoint — its independently-verifiable public state (tree size, root, log signature)."
								className="break-all font-mono text-[11px] text-ink-2 underline-offset-2 hover:text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
							>
								{PUBLIC_LOG} · checkpoint ↗
							</a>
						</div>
						{/* Count label — only shown when collapsed and there are hidden chips. */}
						{anchoredIndices.length > ANCHOR_PREVIEW && !showAllAnchors && (
							<p className="mb-1 text-[11px] text-ink-3">
								<span className="tabular-nums font-medium text-ink">
									{anchoredIndices.length}
								</span>{" "}
								batches anchored — showing first{" "}
								<span className="tabular-nums">{ANCHOR_PREVIEW}</span>
							</p>
						)}
						<div className="flex flex-wrap gap-1.5">
							{(showAllAnchors
								? anchoredIndices
								: anchoredIndices.slice(0, ANCHOR_PREVIEW)
							).map((i) => (
								<LogIndexChip key={i} index={i} />
							))}
						</div>
						{/* Show-more toggle — only when there are more than ANCHOR_PREVIEW chips. */}
						{anchoredIndices.length > ANCHOR_PREVIEW && (
							<button
								type="button"
								onClick={() => setShowAllAnchors((v) => !v)}
								className="mt-1.5 text-[11px] text-ink-2 underline-offset-2 hover:text-ink hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
							>
								{showAllAnchors
									? "Show fewer ▴"
									: `Show ${anchoredIndices.length - ANCHOR_PREVIEW} more ▾`}
							</button>
						)}
						<p className="mt-1.5 text-[11px] text-ink-3">
							Clicking that link opens the log&apos;s signed checkpoint — raw
							text showing the log origin, tree size, current root hash, and the
							log&apos;s own signature over them. This is expected output, not
							an error; it is the one independently-fetchable public artifact.
							You verify each anchored batch root against it offline using the
							inclusion proof bundled in your downloaded evidence.
						</p>
						<p className="mt-1 text-[11px] text-ink-3">
							Rekor v2 is a tiled log with no per-entry web page. Each
							root&apos;s inclusion proof + the log&apos;s signed checkpoint
							travel in your downloaded evidence and verify offline against the
							pinned log key — confirm the live log with{" "}
							<code className="break-all font-mono text-ink-2">
								curl {CHECKPOINT_URL}
							</code>
							.
						</p>
					</div>
				)}
			</div>

			{/* ── Standing facts strip ─────────────────────────────────────── */}
			<dl className="mt-2.5 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[12px]">
				<div className="flex items-center gap-1.5">
					<dt
						className="text-ink-3"
						title={
							windowTotal > rowCount
								? "The verifier loads the most recent events (a render cap); the export streams the complete ledger."
								: undefined
						}
					>
						Events
					</dt>
					<dd className="font-mono tabular-nums text-ink">
						{windowTotal > rowCount ? (
							<>
								<span title="loaded to verify in-browser">
									{fmtCount(rowCount)}
								</span>{" "}
								<span className="text-ink-3">of {fmtCount(windowTotal)}</span>
							</>
						) : (
							fmtCount(rowCount)
						)}
					</dd>
				</div>
				{chainHead && (
					<div className="flex items-center gap-1.5">
						<dt
							className="text-ink-3"
							title={
								isTruncated
									? "The tip of the LOADED page, not necessarily the ledger's latest row — more rows exist beyond what was loaded."
									: undefined
							}
						>
							{isTruncated ? "Chain head (loaded)" : "Chain head"}
						</dt>
						<dd className="font-mono text-ink" title={chainHead}>
							{short(chainHead)}
						</dd>
						<CopyButton value={chainHead} label="chain head hash" />
					</div>
				)}
				{keyId && (
					<div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
						{/* Identity, not a signing claim — presence of a key does not assert
						    these rows are signed. Signing is established only by the
						    in-browser "Verify integrity" report below (audit #10). */}
						<dt className="text-ink-3">Audit signing key</dt>
						<dd className="flex min-w-0 items-center gap-1">
							<span
								className="max-w-[9rem] truncate font-mono text-ink"
								title={tenantPubkeyB64}
							>
								{keyId}
							</span>
							<CopyButton value={tenantPubkeyB64 ?? ""} label="signing key" />
						</dd>
						<a
							href="/settings/audit"
							className="text-ink-2 underline-offset-2 hover:underline hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
							title="Confirm this key out-of-band on Settings → Audit signing key"
						>
							verify this key ↗
						</a>
					</div>
				)}
			</dl>

			{/* ── Post-verify: two-claim breakdown ─────────────────────────── */}
			{report && (
				<div className="mt-4 grid gap-3 sm:grid-cols-2">
					{/* CLAIM 1 OF 2 — hash chain */}
					<div
						className={cn(
							"rounded-lg border p-3",
							report.hash_chain_valid
								? "border-seal-line bg-seal-soft/40"
								: "border-danger/40 bg-danger-soft/40",
						)}
					>
						<div className="text-[10px] font-semibold uppercase tracking-wide text-ink-3">
							Claim 1 of 2 · what we recomputed
						</div>
						<div className="mt-0.5 text-[11px] font-semibold uppercase tracking-wide text-ink-2">
							Hash chain
						</div>
						{report.hash_chain_valid ? (
							<>
								<div className="mt-1 text-sm font-medium text-seal-ink tabular-nums">
									Verified · {report.rows_seen} rows · off-platform reproducible
								</div>
								<div className="mt-1 text-[11px] text-ink-2">
									Every row hash + the prev-hash chain recomputed and matched.
								</div>
							</>
						) : (
							<>
								<div className="mt-1 text-sm font-medium text-danger">
									Chain broken — recomputed hashes do not match
								</div>
								{report.errors.slice(0, 4).map((e) => (
									<div
										key={`${e.seq}-${e.kind}`}
										className="mt-1 font-mono text-[11px] text-danger"
									>
										at seq {e.seq ?? "?"}: {e.kind}
									</div>
								))}
							</>
						)}
					</div>

					{/* CLAIM 2 OF 2 — signature + public anchor */}
					{(() => {
						const label = (
							<>
								<div className="text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Claim 2 of 2 · what the public log proves
								</div>
								<div className="mt-0.5 text-[11px] font-semibold uppercase tracking-wide text-ink-2">
									Signature &amp; public anchor
								</div>
							</>
						);
						if (!report.signatures_valid) {
							const kinds = [
								...new Set(report.errors.map((e) => e.kind)),
							].slice(0, 4);
							return (
								<div className="rounded-lg border border-danger/40 bg-danger-soft/40 p-3">
									{label}
									<div className="mt-1 text-sm font-medium text-danger">
										Verification FAILED
									</div>
									<div className="mt-1 text-[11px] text-danger">
										{report.strip_detected
											? "An anchor claims to be publicly anchored but its proof is missing (stripped). "
											: ""}
										{kinds.length > 0
											? `Reasons: ${kinds.map(humanizeVerdictKind).join("; ")}.`
											: ""}
									</div>
								</div>
							);
						}
						if (
							report.anchors_included > 0 &&
							!report.strip_detected &&
							report.hash_chain_valid
						) {
							return (
								<div className="rounded-lg border border-seal-line bg-seal-soft/40 p-3">
									{label}
									<div className="mt-1 text-sm font-medium text-seal-ink">
										<span className="tabular-nums">
											{report.anchors_included}
										</span>{" "}
										root
										{report.anchors_included === 1 ? "" : "s"} independently
										verified
									</div>
									<div className="mt-1 text-[11px] text-ink-2">
										Signed by your key, included in Sigstore&apos;s{" "}
										<span className="font-mono">{PUBLIC_LOG}</span> append-only
										log, checkpoint verified. Indices in the anchor strip above.
									</div>
								</div>
							);
						}
						if (report.anchors_included > 0 && !report.hash_chain_valid) {
							return (
								<div className="rounded-lg border border-danger/40 bg-danger-soft/40 p-3">
									{label}
									<div className="mt-1 text-sm font-medium text-danger">
										Anchor in log, but rows changed
									</div>
									<div className="mt-1 text-[11px] text-danger">
										The anchored root is still in the public log, but the
										ledger&apos;s rows no longer match it — see the broken chain
										(Claim 1).
									</div>
								</div>
							);
						}
						if (!tenantPubkeyB64 || anchorRecords.length === 0) {
							return (
								<div className="rounded-lg border border-line bg-surface p-3">
									{label}
									<div className="mt-1 text-sm font-medium text-ink">
										No signed batches yet
									</div>
									<div className="mt-1 text-[11px] text-ink-2">
										Signing + anchoring begin with your first gateway-proxied
										batch.
									</div>
								</div>
							);
						}
						return (
							<div className="rounded-lg border border-line bg-surface p-3">
								{label}
								<div className="mt-1 text-sm font-medium text-ink">
									Signed locally (Ed25519)
								</div>
								<div className="mt-1 text-[11px] text-ink-2">
									Your key&apos;s attestation verified. These batches are not
									yet publicly anchored (anchoring is best-effort,
									gateway-path).
								</div>
							</div>
						);
					})()}
				</div>
			)}
		</Card>
	);
}

// ---------------------------------------------------------------------------
// ChainList — hash chain visualized with linkage highlighting + chain head.
// Collapsed by default: shows a preview of the first CHAIN_PREVIEW rows so
// the page remains fast at real volume. The "Show full chain" toggle reveals
// the paginated list. Each row is a <details> (summary → full hash/payload).
// ---------------------------------------------------------------------------

const CHAIN_PREVIEW = 8;

function ChainList({
	rows,
	brokenSeqs,
	grandTotal,
	verifiedFromSeq,
}: {
	rows: Row[];
	brokenSeqs: Set<number>;
	/** Server-computed total events in this window (may exceed rows.length). */
	grandTotal?: number;
	/** ADR-070: verified scope start; rows below it are present-but-unverified. */
	verifiedFromSeq?: number;
}) {
	const [chainOpen, setChainOpen] = useState(false);
	const [page, setPage] = useState(0);
	const [hoveredSeq, setHoveredSeq] = useState<number | null>(null);

	const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
	const clamped = Math.min(page, totalPages - 1);
	const start = clamped * PAGE_SIZE;
	const chainBroken = brokenSeqs.size > 0;
	const firstBrokenSeq = chainBroken
		? rows.find((r) => brokenSeqs.has(r.seq))?.seq
		: undefined;
	const chainHead = rows.length ? (rows[rows.length - 1]?.row_hash ?? "") : "";
	const serverTotal = grandTotal ?? rows.length;

	// Which rows to actually render: first CHAIN_PREVIEW when collapsed, or the
	// current pagination page when expanded.
	const visibleRows = chainOpen
		? rows.slice(start, start + PAGE_SIZE)
		: rows.slice(0, CHAIN_PREVIEW);

	// Show the chain-head terminator on the true last row when either:
	//   (a) expanded and on the last pagination page, or
	//   (b) collapsed and the total rows fit within the preview.
	const isLastPage = chainOpen
		? clamped === totalPages - 1
		: rows.length <= CHAIN_PREVIEW;

	function jumpToBroken() {
		if (firstBrokenSeq === undefined) return;
		const idx = rows.findIndex((r) => r.seq === firstBrokenSeq);
		if (idx >= 0) {
			setPage(Math.floor(idx / PAGE_SIZE));
			setChainOpen(true);
		}
	}

	function toggleChain() {
		if (chainOpen) setPage(0); // reset pagination when collapsing
		setChainOpen((o) => !o);
	}

	return (
		<div>
			{/* ── Header ─────────────────────────────────────────────────── */}
			<div className="mb-2 flex flex-wrap items-center justify-between gap-2">
				<h2 className="text-sm font-semibold text-ink">
					Hash chain ·{" "}
					<span className="tabular-nums">{fmtCount(rows.length)}</span> event
					{rows.length === 1 ? "" : "s"} loaded
				</h2>
				<div className="flex flex-wrap items-center gap-2">
					{firstBrokenSeq !== undefined && (
						<button
							type="button"
							onClick={jumpToBroken}
							className="rounded-md border border-danger/40 bg-danger-soft/50 px-2 py-1 text-[11px] font-medium text-danger hover:bg-danger-soft focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							Jump to first break (#{firstBrokenSeq})
						</button>
					)}
					{rows.length > CHAIN_PREVIEW && (
						<button
							type="button"
							onClick={toggleChain}
							aria-expanded={chainOpen}
							className="rounded-md border border-line px-2 py-1 text-[11px] text-ink-2 hover:bg-surface-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							{chainOpen
								? "Collapse chain ▴"
								: `Show full chain (first ${fmtCount(rows.length)} of ${fmtCount(serverTotal)} events) ▾`}
						</button>
					)}
				</div>
			</div>

			{/* ── Honest scope note — always visible ──────────────────────── */}
			<p className="mb-2 text-[11px] text-ink-3">
				{!chainOpen ? (
					<>
						Showing first{" "}
						<span className="tabular-nums">
							{fmtCount(Math.min(CHAIN_PREVIEW, rows.length))}
						</span>{" "}
						of <span className="tabular-nums">{fmtCount(serverTotal)}</span>{" "}
						events, from genesis — the complete ledger is the export (or{" "}
						<code className="font-mono text-ink-2">tlane verify</code> on it).
					</>
				) : (
					<>
						Showing{" "}
						<span className="tabular-nums">
							{start + 1}–{Math.min(start + PAGE_SIZE, rows.length)}
						</span>{" "}
						of <span className="tabular-nums">{fmtCount(rows.length)}</span>{" "}
						loaded events
						{serverTotal > rows.length && (
							<>
								{" "}
								(full ledger:{" "}
								<span className="tabular-nums">{fmtCount(serverTotal)}</span>)
							</>
						)}{" "}
						— use <code className="font-mono text-ink-2">tlane verify</code> CLI
						for the complete ledger.
					</>
				)}
			</p>

			{/* ── Row list ──────────────────────────────────────────────── */}
			<ol className="space-y-0">
				{visibleRows.map((r, idx) => {
					const broken = brokenSeqs.has(r.seq);
					// ADR-070: rows before the verified scope (a windowed root) are present
					// but UNVERIFIED — shown dimmed, never hidden.
					const preAnchor =
						verifiedFromSeq !== undefined &&
						verifiedFromSeq > 0 &&
						r.seq < verifiedFromSeq;
					// nextRow: the row immediately following in the full sorted set
					// (not just the visible slice) so the hash linkage annotation works
					// correctly at page/preview boundaries.
					const nextRow = chainOpen ? rows[start + idx + 1] : rows[idx + 1];
					// Hash linkage: when this row is hovered, its row_hash connects to
					// the next row's prev_hash — highlight both to make the chain legible.
					const isHovered = hoveredSeq === r.seq;
					const prevRowHovered = hoveredSeq === r.seq - 1;
					const hashLinked = isHovered && !!nextRow;

					return (
						<li
							key={r.seq}
							className={cn("flex gap-3", preAnchor && "opacity-45")}
							title={
								preAnchor
									? `Present but unverified — before the verified scope (seq ${verifiedFromSeq})`
									: undefined
							}
							onMouseEnter={() => setHoveredSeq(r.seq)}
							onMouseLeave={() => setHoveredSeq(null)}
						>
							{/* chain thread — continuous dotted teal spine */}
							<div className="relative flex w-3 shrink-0 justify-center">
								<span
									aria-hidden
									className={cn(
										"absolute inset-y-0 w-px border-l border-dashed",
										broken ? "border-danger/60" : "border-seal/50",
									)}
								/>
								<span
									aria-hidden
									className={cn(
										"relative z-10 mt-3.5 h-1.5 w-1.5 rounded-full ring-2 ring-bg",
										broken ? "bg-danger" : "bg-seal",
									)}
								/>
							</div>
							<details
								className={cn(
									"group mb-1.5 min-w-0 flex-1 rounded-lg border transition-colors",
									broken
										? "border-danger/50 bg-danger-soft/40"
										: isHovered
											? "border-seal/30 bg-seal-soft/20"
											: "border-line bg-surface",
								)}
							>
								{/* collapsed row — event + time + hash trailing */}
								<summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-[11px] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal [&::-webkit-details-marker]:hidden">
									<span
										aria-hidden
										className="shrink-0 text-ink-3 transition-transform group-open:rotate-90"
									>
										▸
									</span>
									<span className="shrink-0 font-mono tabular-nums text-ink-3">
										#{r.seq}
									</span>
									<span className="shrink-0 font-medium text-ink-2">
										{r.event_type}
									</span>
									{broken ? (
										<span className="min-w-0 flex-1 truncate font-medium text-danger">
											⚠ hash mismatch — click to inspect
										</span>
									) : (
										<span className="min-w-0 flex-1 truncate font-mono text-ink-3">
											{payloadPreview(r.payload)}
										</span>
									)}
									{/* Full date+time — unambiguous wall-clock (midnight ≠ offset) */}
									<span className="shrink-0 font-mono tabular-nums text-ink-3 text-[10px]">
										{fmtDateTime(r.event_time)}
									</span>
									<span
										className={cn(
											"hidden shrink-0 font-mono sm:inline",
											hashLinked ? "text-seal-ink" : "text-ink-3",
										)}
										title={r.row_hash}
									>
										{short(r.row_hash)}
									</span>
								</summary>

								{/* expanded — data covered by this hash */}
								<div className="space-y-2 border-t border-line px-3 pb-3 pt-2">
									<div className="text-[10px] font-semibold uppercase tracking-wide text-ink-3">
										Data covered by this hash
									</div>
									<dl className="flex flex-wrap gap-x-5 gap-y-1 text-[11px]">
										<div className="flex gap-1.5">
											<dt className="text-ink-3">seq</dt>
											<dd className="font-mono tabular-nums text-ink">
												{r.seq}
											</dd>
										</div>
										<div className="flex gap-1.5">
											<dt className="text-ink-3">type</dt>
											<dd className="text-ink">{r.event_type}</dd>
										</div>
										{r.actor && (
											<div className="flex gap-1.5">
												<dt className="text-ink-3">actor</dt>
												<dd className="font-mono text-ink">{r.actor}</dd>
											</div>
										)}
										<div className="flex gap-1.5">
											<dt className="text-ink-3">time</dt>
											<dd className="font-mono text-ink">{r.event_time}</dd>
										</div>
									</dl>
									<div>
										<div className="mb-0.5 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
											payload
										</div>
										<pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-md bg-surface-2 p-2 font-mono text-[11px] text-ink">
											{formatPayload(r.payload)}
										</pre>
									</div>
									{/* Hash linkage — show the chain connection explicitly */}
									<div className="space-y-0.5 break-all font-mono text-[10px]">
										<div
											className={cn(
												"flex items-start gap-1.5",
												hashLinked ? "text-seal-ink" : "text-ink-3",
											)}
										>
											<span className="shrink-0 text-ink-2">row_hash</span>
											<span className="break-all">{r.row_hash}</span>
											{hashLinked && (
												<span
													className="shrink-0 text-seal-ink"
													title="This hash becomes the prev_hash of the next row"
												>
													→ next
												</span>
											)}
										</div>
										<div
											className={cn(
												"flex items-start gap-1.5",
												prevRowHovered ? "text-seal-ink" : "text-ink-3",
											)}
										>
											<span className="shrink-0 text-ink-2">← prev</span>
											<span className="break-all">{r.prev_hash}</span>
											{prevRowHovered && (
												<span className="shrink-0 text-seal-ink">
													← from prev row
												</span>
											)}
										</div>
									</div>
									{broken && (
										<div className="text-[11px] font-medium text-danger">
											row hash mismatch — recomputing this row&apos;s hash over
											the data above does not match the stored hash.
										</div>
									)}
								</div>
							</details>
						</li>
					);
				})}

				{/* "… N more" prompt — only when collapsed and there are hidden rows */}
				{!chainOpen && rows.length > CHAIN_PREVIEW && (
					<li className="flex gap-3">
						<div className="relative flex w-3 shrink-0 justify-center">
							<span
								aria-hidden
								className="absolute inset-y-0 w-px border-l border-dashed border-line-2"
							/>
						</div>
						<button
							type="button"
							onClick={() => setChainOpen(true)}
							className="mb-1.5 flex-1 rounded-lg border border-dashed border-line bg-surface-2/40 px-3 py-2 text-left text-[11px] text-ink-3 hover:bg-surface-2 hover:text-ink-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							…{" "}
							<span className="tabular-nums">
								{fmtCount(rows.length - CHAIN_PREVIEW)}
							</span>{" "}
							more event{rows.length - CHAIN_PREVIEW === 1 ? "" : "s"} — click
							to expand full chain
						</button>
					</li>
				)}

				{/* Chain head terminator — final node. Neutral (not Verify-green)
				    when the chain is broken — the head is a stored fact, not a
				    verification claim, and green must never read as "verified" here.
				    Shown on the last page when expanded, or when all rows fit in preview. */}
				{isLastPage && rows.length > 0 && (
					<li className="flex gap-3">
						<div className="relative flex w-3 shrink-0 justify-center">
							<span
								aria-hidden
								className={cn(
									"absolute top-0 h-3.5 w-px border-l border-dashed",
									chainBroken ? "border-line-2" : "border-seal/50",
								)}
							/>
							<span
								aria-hidden
								className={cn(
									"relative z-10 mt-3.5 h-2 w-2 rounded-sm ring-2 ring-bg",
									chainBroken ? "bg-ink-3" : "bg-seal",
								)}
							/>
						</div>
						<div
							className={cn(
								"mb-1.5 flex min-w-0 flex-1 items-center gap-2 rounded-lg border px-3 py-2 text-[11px]",
								chainBroken
									? "border-line bg-surface"
									: "border-seal/30 bg-seal-soft/30",
							)}
						>
							<span
								className={cn(
									"font-medium",
									chainBroken ? "text-ink-2" : "text-seal-ink",
								)}
							>
								chain head
							</span>
							<span className="font-mono text-ink-3" title={chainHead}>
								{short(chainHead)}
							</span>
							<CopyButton value={chainHead} label="chain head hash" />
						</div>
					</li>
				)}
			</ol>

			{/* Pagination — only visible when the full chain is expanded */}
			{chainOpen && rows.length > PAGE_SIZE && (
				<div className="mt-2 flex flex-wrap items-center justify-end gap-1.5 text-[11px] text-ink-2">
					<span className="tabular-nums">
						{start + 1}–{Math.min(start + PAGE_SIZE, rows.length)} of{" "}
						{fmtCount(rows.length)}
					</span>
					<button
						type="button"
						onClick={() => setPage(Math.max(0, clamped - 1))}
						disabled={clamped === 0}
						className="rounded-md border border-line px-2 py-1 text-ink hover:bg-surface-2 disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
					>
						Prev
					</button>
					<span className="tabular-nums">
						{clamped + 1}/{totalPages}
					</span>
					<button
						type="button"
						onClick={() => setPage(Math.min(totalPages - 1, clamped + 1))}
						disabled={clamped >= totalPages - 1}
						className="rounded-md border border-line px-2 py-1 text-ink hover:bg-surface-2 disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
					>
						Next
					</button>
				</div>
			)}
		</div>
	);
}

// ---------------------------------------------------------------------------
// AuditLedgerView — main export
// ---------------------------------------------------------------------------

/**
 * The audit-ledger surface. "Verify integrity" runs the SAME open-source verifier
 * IN THIS BROWSER over the exported ledger, and shows TWO DISTINCT claims, never
 * one blurred "integrity" status: (1) the hash chain (recompute every row hash +
 * prev-hash chain — strong, off-platform reproducible); (2) signature + public
 * anchor (ADR-062) — the verifier checks the bound Ed25519 attestation against
 * YOUR trusted key + the Rekor v2 inclusion proof + checkpoint OFFLINE. GREEN
 * only when `anchors_included > 0 && signatures_valid && !strip_detected`; RED on
 * any verification failure; honest neutral states otherwise. Never a vacuous check.
 */
export function AuditLedgerView({
	ndjson,
	tenantPubkeyB64,
	initialReport,
	range,
	retentionDays,
	summary,
	since,
	until,
	windowSince,
	windowUntil,
	windowTotal,
	canExport = true,
}: {
	ndjson: string;
	/**
	 * The tenant's TRUSTED Ed25519 audit pubkey (base64), resolved server-side
	 * (ADR-062 C2). Passed to the verifier as the single external trust root; the
	 * bundle's embedded key must match it or the anchor is rejected. Empty when
	 * the tenant has no audit key yet (verification is chain-only).
	 */
	tenantPubkeyB64?: string;
	/**
	 * Pre-computed verify result to hydrate the verdict cards. Defaults to null —
	 * the user clicks "Verify integrity" to run the in-browser verifier. Exists so
	 * a test (or a future SSR pre-verify) can render the already-verified state
	 * without driving a click; the verdict UI stays purely a function of this
	 * report (green iff `hash_chain_valid`), never a static string.
	 */
	initialReport?: VerifyReport;
	/** Active date-range window key (renders the range control). Absent on the
	 * e2e fixture path (no live query to re-scope). */
	range?: string;
	/** The plan's trace-retention days — shown as a contrast to the ledger's own
	 * (append-only) retention. Absent on the fixture path. */
	retentionDays?: number;
	/** Server-computed aggregate (total + per-day + per-type). Exact for a large
	 * ledger. Absent on the fixture path (and if the summary fetch failed) — the
	 * "About" panel then falls back to an approximate breakdown from loaded rows. */
	summary?: AuditSummary;
	/** Explicit since/until ISO strings — present when ?since=&until= in URL
	 * (custom date range wins over ?range= preset). */
	since?: string;
	until?: string;
	/** Server-computed window bounds (ISO) for CLIENT-SIDE filtering of the
	 * browsable chain list — used on the free self-verify path, where the gateway
	 * returns the whole retention window and the range control filters what's
	 * shown in-browser. Deterministic (server-provided strings) → no hydration
	 * drift. The verifier still runs over the FULL chain; only the displayed rows
	 * are scoped. Absent on the export path (the server already windowed). */
	windowSince?: string;
	windowUntil?: string;
	/** EXACT uncapped count of chain rows in the (retention) window, from the free
	 * self-verify endpoint (`total_in_window`). Lets the tile read honestly —
	 * "Showing N of {this}" — so the loaded render-cap never reads as the whole
	 * ledger. Absent on the paid path (uses `summary.total`) + the fixture path. */
	windowTotal?: number;
	/** ADR-066: whether the paid Article-12 evidence-pack export is available
	 * (f_audit_addon). Default true. When false (free self-verify tenants) the
	 * export card is replaced by the upgrade CTA — the chain + in-browser verify
	 * stay fully available; only the export is the upsell. */
	canExport?: boolean;
}) {
	const rows = useMemo(() => parseRows(ndjson), [ndjson]);
	// CLIENT-SIDE window filter for the browsable chain list (free self-verify
	// path). `windowSince`/`windowUntil` are server-provided ISO strings, so this
	// is deterministic (no `Date.now()` → no hydration drift). Normalizes the
	// ClickHouse "YYYY-MM-DD HH:MM:SS" and ISO forms before comparing. The verify
	// pass below still runs over the FULL `ndjson`; only the DISPLAY is scoped.
	const visibleRows = useMemo(() => {
		if (!windowSince && !windowUntil) return rows;
		const tsMs = (s: string): number =>
			Date.parse(s.includes("T") ? s : `${s.replace(" ", "T")}Z`);
		const lo = windowSince ? Date.parse(windowSince) : Number.NEGATIVE_INFINITY;
		const hi = windowUntil ? Date.parse(windowUntil) : Number.POSITIVE_INFINITY;
		return rows.filter((r) => {
			const t = tsMs(r.event_time);
			return Number.isNaN(t) ? true : t >= lo && t <= hi;
		});
	}, [rows, windowSince, windowUntil]);
	const anchorRecords = useMemo(() => parseAnchors(ndjson), [ndjson]);
	const tenantPubkey = useMemo(
		() => b64ToBytes(tenantPubkeyB64 ?? ""),
		[tenantPubkeyB64],
	);
	const anchoredIndices = useMemo(
		() =>
			anchorRecords
				.filter((a) => a.anchor_state === "anchored" && a.rekor?.log_index)
				.map((a) => a.rekor?.log_index as string),
		[anchorRecords],
	);
	const [report, setReport] = useState<VerifyReport | null>(
		initialReport ?? null,
	);
	const [verifying, setVerifying] = useState(false);

	const brokenSeqs = useMemo(
		() =>
			new Set(
				(report?.errors ?? [])
					.map((e) => e.seq)
					.filter((s): s is number => s !== null),
			),
		[report],
	);
	const chainHead = rows.length ? (rows[rows.length - 1]?.row_hash ?? "") : "";
	const keyId = tenantPubkeyB64 ? `${tenantPubkeyB64.slice(0, 16)}…` : "";

	// EVERY derived stat below reads `visibleRows` (the selected window), NOT the
	// full loaded set — otherwise "First–last event" and "Events (window)" stay
	// frozen while the date filter changes, which reads as hardcoded. On the paid
	// path the server already windowed, so visibleRows === rows and this is a
	// no-op; on the free path it is what makes the filter actually take effect.
	const eventTypeCounts = useMemo<Array<[string, number]>>(() => {
		const m = new Map<string, number>();
		for (const r of visibleRows)
			m.set(r.event_type, (m.get(r.event_type) ?? 0) + 1);
		return [...m.entries()].sort((a, b) => b[1] - a[1]);
	}, [visibleRows]);

	// Per-day breakdown over the selected window — fallback when no server summary.
	const clientByDay = useMemo(() => {
		const m = new Map<string, number>();
		for (const r of visibleRows) {
			const d = r.event_time.slice(0, 10);
			if (d) m.set(d, (m.get(d) ?? 0) + 1);
		}
		return [...m.entries()]
			.sort((a, b) => (a[0] < b[0] ? -1 : 1))
			.map(([day, count]) => ({ day, count }));
	}, [visibleRows]);

	// Prefer an EXACT server count (paid summary, or the free self-verify
	// `windowTotal`), so the honest "N of {total}" label never lets the loaded cap
	// read as the whole ledger. Fall back to the windowed client set only when no
	// server count exists (fixture path). Never below what's actually loaded.
	const total = Math.max(
		summary?.total ?? windowTotal ?? visibleRows.length,
		visibleRows.length,
	);
	/** True when we have an EXACT server-side total (not a loaded-count proxy). */
	const hasServerTotal =
		summary?.total !== undefined || windowTotal !== undefined;
	const aboutByType: Array<[string, number]> = summary
		? summary.by_type.map((t) => [t.event_type, t.count])
		: eventTypeCounts;
	const aboutByDay = summary?.by_day ?? clientByDay;

	// Export scope label — states the window + the EXACT in-scope event count
	// (server `total`, not the loaded-row count) on the download card.
	const exportScopeLabel = useMemo(
		() => `complete chain from genesis · ${fmtCount(total)} events`,
		[total],
	);

	const verify = useCallback(async () => {
		setVerifying(true);
		try {
			// Runs the open-source verifier over bytes you can inspect — not a server
			// boolean. With your trusted audit key it verifies signatures + public
			// anchors offline (Rekor v2 needs no network — the proof is bundled).
			setReport(await verifyLedgerText(ndjson, { tenantPubkey }));
		} finally {
			setVerifying(false);
		}
	}, [ndjson, tenantPubkey]);

	function download() {
		// Download the COMPLETE, UNCAPPED ledger via the streaming proxy — NOT the
		// in-memory `ndjson`, which is the capped RENDER set. No `limit` param → the
		// gateway streams the whole chain (the compliance deliverable). The browser
		// saves the streamed file; nothing is buffered in this component.
		const p = new URLSearchParams();
		const s = since ?? windowSince;
		const u = until ?? windowUntil;
		if (s) p.set("since", s);
		if (u) p.set("until", u);
		const qs = p.toString();
		window.location.href = `/api/audit/export${qs ? `?${qs}` : ""}`;
	}

	return (
		<div className="space-y-5">
			{/* TRUST PANEL — dominant, top: anchor status + verify CTA + verdict.
			    The ONLY Lava CTA on the page. The ONLY large green element. */}
			<TrustPanel
				anchoredIndices={anchoredIndices}
				hasAnchorRecords={anchorRecords.length > 0}
				report={report}
				verifying={verifying}
				onVerify={verify}
				rowCount={visibleRows.length}
				windowTotal={total}
				chainHead={chainHead}
				keyId={keyId}
				tenantPubkeyB64={tenantPubkeyB64}
				anchorRecords={anchorRecords}
				isTruncated={total > visibleRows.length}
			/>

			{/* EXPORT / UPSELL — moved directly under the verdict so the "how do I get
			    the complete ledger" answer is impossible to miss (founder: the download
			    was buried below a long chain view). Download (paid) or Audit-add-on
			    upsell (free). */}
			{canExport ? (
				<Card className="p-5">
					<h2 className="text-sm font-semibold text-ink">
						Download the complete ledger
					</h2>
					<p className="mt-0.5 max-w-2xl text-[13px] text-ink-2">
						The chain above is a capped preview (first {fmtCount(rows.length)}
						). This downloads the <strong>complete</strong>, uncapped ledger as
						NDJSON — the EU AI Act Article 12 evidence pack — then verify it
						yourself with the open-source CLI (no account, no network).
					</p>
					<div
						className="mt-1 text-[11px] text-ink-3"
						data-testid="export-scope"
					>
						{exportScopeLabel}
					</div>
					<div className="mt-3 flex flex-wrap items-center gap-3">
						<Button variant="primary" onClick={download} className="cta-lava">
							Download evidence (NDJSON)
						</Button>
						<code className="font-mono text-[11px] text-ink-2">
							tlane verify --tenant-pubkey &lt;key&gt;
						</code>
					</div>
				</Card>
			) : (
				<div
					className="flex flex-col gap-4 rounded-xl bg-surface-inverse p-5 sm:flex-row sm:items-center sm:justify-between"
					data-testid="export-upsell"
				>
					<div>
						<div className="text-[11px] font-semibold uppercase tracking-wide text-ink-inverse opacity-60">
							Audit SKU · $999/mo add-on
						</div>
						<h2 className="mt-1 text-sm font-semibold text-ink-inverse">
							Download the complete ledger
						</h2>
						<p className="mt-0.5 max-w-2xl text-[13px] text-ink-inverse opacity-70">
							Seeing and verifying the first {fmtCount(rows.length)} events of
							your chain (from genesis) is <strong>free</strong> — that is
							everything above. The downloadable Article-12 evidence pack — the{" "}
							<strong>complete</strong> chain as independently-verifiable NDJSON
							with public-anchor proofs, for regulator hand-off — is the Audit
							add-on.
						</p>
					</div>
					<Link
						href="/settings/billing"
						className="cta-lava inline-flex h-9 shrink-0 items-center rounded-lg px-4 text-[13px] font-medium"
					>
						Add the Audit SKU
					</Link>
				</div>
			)}

			{/* ABOUT — supporting context: scope, types, time span, histogram.
			    Demoted below the trust panel. */}
			<AboutLedger
				total={total}
				loadedCount={rows.length}
				eventTypeCounts={aboutByType}
				byDay={aboutByDay}
				anchoredCount={anchoredIndices.length}
				retentionDays={retentionDays}
				serverTotal={hasServerTotal}
				loadCap={1000}
			/>

			{/* NEGATIVE SCENARIO — what a failed verification looks like */}
			<NegativeScenarioPanel />

			{/* CHAIN VIEW — white bg card so the chain spine renders on white, not the
			    blue canvas (item 4: white result surfaces). Collapsed by default. */}
			<Card className="bg-surface p-5">
				<ChainList
					rows={visibleRows}
					brokenSeqs={brokenSeqs}
					grandTotal={total}
					verifiedFromSeq={report?.verified_from_seq}
				/>
			</Card>
		</div>
	);
}
