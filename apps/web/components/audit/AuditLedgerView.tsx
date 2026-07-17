"use client";

import {
	type VerifyReport,
	verifyLedgerText,
} from "@tracelanedev/audit-verifier";
import { Button, Card, StatCard, cn } from "@tracelanedev/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
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
	since,
	until,
}: {
	byDay: Array<{ day: string; count: number }>;
	since?: string;
	until?: string;
}) {
	const router = useRouter();
	const [shiftAnchor, setShiftAnchor] = useState<string | null>(null);
	const [rangeEnd, setRangeEnd] = useState<string | null>(null);

	const useWeeks = byDay.length > 30;
	const buckets = useWeeks
		? aggregateToWeeks(byDay)
		: byDay.map((d) => ({ ...d, label: d.day }));

	if (buckets.length === 0) return null;

	const maxCount = Math.max(...buckets.map((b) => b.count), 1);
	const maxH = 48; // px

	/** Compute selected range from current URL since/until. */
	function isSelected(day: string): boolean {
		if (!since || !until) return false;
		return day >= since.slice(0, 10) && day <= until.slice(0, 10);
	}

	/** Compute the day or week-range "until" (exclusive end becomes inclusive day). */
	function dayUntil(day: string): string {
		const d = new Date(`${day}T00:00:00Z`);
		d.setUTCDate(d.getUTCDate() + (useWeeks ? 6 : 0));
		return `${d.toISOString().slice(0, 10)}T23:59:59Z`;
	}

	function handleClick(day: string, evt: React.MouseEvent) {
		if (evt.shiftKey && shiftAnchor) {
			// Range: shiftAnchor to clicked day (lexicographic sort for ISO dates)
			const sorted = [shiftAnchor, day].sort();
			const lo = sorted[0] ?? day;
			const hi = sorted[1] ?? day;
			router.push(
				`/audit?since=${encodeURIComponent(`${lo}T00:00:00Z`)}&until=${encodeURIComponent(dayUntil(hi))}`,
			);
			setRangeEnd(day);
		} else {
			setShiftAnchor(day);
			setRangeEnd(null);
			router.push(
				`/audit?since=${encodeURIComponent(`${day}T00:00:00Z`)}&until=${encodeURIComponent(dayUntil(day))}`,
			);
		}
	}

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
					const selected = isSelected(b.day);
					// ISO date string comparison is safe as lexicographic order = temporal order
					const loDay =
						rangeEnd && shiftAnchor
							? ([shiftAnchor, rangeEnd].sort()[0] ?? shiftAnchor)
							: null;
					const hiDay =
						rangeEnd && shiftAnchor
							? ([shiftAnchor, rangeEnd].sort()[1] ?? rangeEnd)
							: null;
					const inRange =
						loDay && hiDay ? b.day >= loDay && b.day <= hiDay : false;
					return (
						<button
							key={b.day}
							type="button"
							title={`${b.label}: ${fmtCount(b.count)} events (√-scaled)`}
							onClick={(e) => handleClick(b.day, e)}
							className={cn(
								"group/col relative shrink-0 rounded-sm transition-colors focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-seal",
								// Selection is a filter affordance, not provenance — neutral
								// ink, never Verify-green (which is rationed to verification).
								selected || inRange
									? "bg-ink-2 hover:bg-ink"
									: "bg-surface-3 hover:bg-line-2",
							)}
							style={{ width: "8px", height: `${h}px` }}
							aria-pressed={selected}
						>
							<span className="sr-only">
								{b.label}: {fmtCount(b.count)} events
							</span>
						</button>
					);
				})}
			</div>
			<p className="mt-1 text-[10px] text-ink-3">
				Click a bar to filter to that {useWeeks ? "week" : "day"} · shift-click
				for a range · heights are √-scaled
			</p>
		</details>
	);
}

// ---------------------------------------------------------------------------
// RangeControl — preset tabs + "Custom" date-range escape hatch
// ---------------------------------------------------------------------------

/** Date-range windows (keys must match `app/audit/page.tsx` RANGES). */
const RANGE_OPTS: Array<{ key: string; label: string }> = [
	{ key: "24h", label: "24h" },
	{ key: "7d", label: "7d" },
	{ key: "30d", label: "30d" },
	{ key: "90d", label: "90d" },
	{ key: "all", label: "All" },
];

function RangeControl({
	range,
	since,
	until,
}: {
	range?: string;
	since?: string;
	until?: string;
}) {
	const router = useRouter();
	const isCustom = Boolean(since && until);
	const [showCustom, setShowCustom] = useState(isCustom);
	const [fromDate, setFromDate] = useState(since ? since.slice(0, 10) : "");
	const [toDate, setToDate] = useState(until ? until.slice(0, 10) : "");

	function applyCustom() {
		if (!fromDate || !toDate) return;
		router.push(
			`/audit?since=${encodeURIComponent(`${fromDate}T00:00:00Z`)}&until=${encodeURIComponent(`${toDate}T23:59:59Z`)}`,
		);
	}

	return (
		<div className="flex shrink-0 flex-col items-end gap-1.5 text-[11px]">
			<div className="flex items-center gap-1 rounded-md border border-line p-0.5">
				{RANGE_OPTS.map((o) => (
					<Link
						key={o.key}
						href={`/audit?range=${o.key}`}
						scroll={false}
						onClick={() => setShowCustom(false)}
						className={cn(
							"rounded px-2 py-0.5 font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal",
							!isCustom && range === o.key
								? "bg-surface-2 text-ink"
								: "text-ink-2 hover:text-ink",
						)}
					>
						{o.label}
					</Link>
				))}
				<button
					type="button"
					onClick={() => setShowCustom((v) => !v)}
					className={cn(
						"rounded px-2 py-0.5 font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal",
						isCustom || showCustom
							? "bg-surface-2 text-ink"
							: "text-ink-2 hover:text-ink",
					)}
				>
					Custom
				</button>
			</div>

			{showCustom && (
				<div className="flex items-center gap-1.5">
					<input
						type="date"
						value={fromDate}
						onChange={(e) => setFromDate(e.target.value)}
						className="rounded-md border border-line bg-surface px-2 py-0.5 font-mono text-[11px] text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						aria-label="From date"
					/>
					<span className="text-ink-3">→</span>
					<input
						type="date"
						value={toDate}
						onChange={(e) => setToDate(e.target.value)}
						className="rounded-md border border-line bg-surface px-2 py-0.5 font-mono text-[11px] text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						aria-label="To date"
					/>
					<button
						type="button"
						onClick={applyCustom}
						disabled={!fromDate || !toDate}
						className="rounded-md border border-line px-2 py-0.5 font-medium text-ink hover:bg-surface-2 disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
					>
						Apply
					</button>
				</div>
			)}
		</div>
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
	span,
	anchoredCount,
	retentionDays,
	range,
	since,
	until,
}: {
	total: number;
	loadedCount: number;
	eventTypeCounts: Array<[string, number]>;
	byDay: Array<{ day: string; count: number }>;
	span: { first: string; last: string } | null;
	anchoredCount: number;
	retentionDays?: number;
	range?: string;
	since?: string;
	until?: string;
}) {
	const day = (iso: string) => iso.slice(0, 10);
	const spanLabel = span
		? span.first === span.last || day(span.first) === day(span.last)
			? day(span.first)
			: `${day(span.first)} → ${day(span.last)}`
		: "—";
	return (
		<Card className="p-5">
			<div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
				<div className="max-w-3xl">
					<h2 className="text-sm font-semibold text-ink">About this ledger</h2>
					<p className="mt-1 text-[13px] text-ink-2">
						An <strong>append-only, tamper-evident</strong> record of what the
						gateway did — every proxied request and every guardrail / eval
						verdict — so you can prove to an auditor exactly what ran and that
						the record was not altered. It covers{" "}
						<strong>gateway-proxied traffic</strong>; full-fidelity spans sent
						via the SDK / OTLP live in{" "}
						<Link
							href="/traces"
							className="text-ink-2 underline-offset-2 hover:underline hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						>
							Traces
						</Link>{" "}
						and are not part of this chain.
					</p>
				</div>
				{(range || (since && until)) && (
					<RangeControl range={range} since={since} until={until} />
				)}
			</div>

			{/* Stat tiles — shared StatCard; anchored count is the headline stat (ok tone). */}
			<div className="mt-4 grid grid-cols-2 gap-3 border-t border-line pt-3 sm:grid-cols-4">
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
					sub="Sigstore Rekor v2"
					hint="Number of event batches independently anchored to the Sigstore public transparency log"
				/>
				<StatCard
					label="First–last event"
					value={spanLabel}
					sub="actual event range in this window"
				/>
				<StatCard
					label="Retention"
					value="Append-only"
					sub="no automatic expiry"
					hint="The audit ledger is append-only — it has no TTL and outlives your plan's trace-retention window"
				/>
				<StatCard
					label="Events (window)"
					value={<span className="tabular-nums">{fmtCount(total)}</span>}
					hint="Total events in the selected window, computed by the gateway — the chain view may show a capped subset"
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
			<CompactColumnChart byDay={byDay} since={since} until={until} />

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
					<span className="tabular-nums">{fmtCount(total)}</span> events in this
					window — narrow the window, or use the CLI for the complete ledger.
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
	chainHead,
	keyId,
	tenantPubkeyB64,
	anchorRecords,
}: {
	anchoredIndices: string[];
	hasAnchorRecords: boolean;
	report: VerifyReport | null;
	verifying: boolean;
	onVerify: () => void;
	rowCount: number;
	chainHead: string;
	keyId: string;
	tenantPubkeyB64?: string;
	anchorRecords: AnchorRec[];
}) {
	const verified =
		!!report &&
		report.anchors_included > 0 &&
		!report.strip_detected &&
		report.hash_chain_valid;
	const chainBroken = !!report && !report.hash_chain_valid;
	const stripped = !!report && report.strip_detected;
	const alarm = chainBroken || stripped;

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
					{!report && (
						<div className="flex items-start gap-3">
							<span aria-hidden className="mt-0.5 text-xl text-ink-3 shrink-0">
								◆
							</span>
							<div>
								<div className="text-base font-semibold text-ink">
									Ready to verify
								</div>
								<p className="mt-0.5 text-[13px] text-ink-2">
									Nothing here is trusted from our server. The open-source
									verifier runs <strong>in your browser</strong> over the
									exported ledger — recomputing every row hash (SHA-256,
									domain-separated) and the prev-hash chain.
								</p>
							</div>
						</div>
					)}

					{/* Post-verify: LARGE GREEN "Verified" */}
					{verified && (
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
									Hash chain intact · {report.rows_seen} rows · off-platform
									reproducible. Signed by your key, anchored in Sigstore&apos;s{" "}
									<span className="font-mono">{PUBLIC_LOG}</span> append-only
									log, checkpoint verified.
								</p>
							</div>
						</div>
					)}

					{/* Post-verify: broken chain */}
					{chainBroken && !verified && (
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
									The hash chain is broken — see the chain view below.
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
						<div className="flex flex-wrap gap-1.5">
							{anchoredIndices.map((i) => (
								<LogIndexChip key={i} index={i} />
							))}
						</div>
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
					<dt className="text-ink-3">Events</dt>
					<dd className="font-mono tabular-nums text-ink">{rowCount}</dd>
				</div>
				{chainHead && (
					<div className="flex items-center gap-1.5">
						<dt className="text-ink-3">Chain head</dt>
						<dd className="font-mono text-ink" title={chainHead}>
							{short(chainHead)}
						</dd>
						<CopyButton value={chainHead} label="chain head hash" />
					</div>
				)}
				{keyId && (
					<div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
						<dt className="text-ink-3">Signed by key</dt>
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
										{kinds.length > 0 ? `Reasons: ${kinds.join(", ")}.` : ""}
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
}: {
	rows: Row[];
	brokenSeqs: Set<number>;
	/** Server-computed total events in this window (may exceed rows.length). */
	grandTotal?: number;
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
						events in this window — use{" "}
						<code className="font-mono text-ink-2">tlane verify</code> CLI for
						the complete ledger.
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
							className="flex gap-3"
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
	/** ADR-066: whether the paid Article-12 evidence-pack export is available
	 * (f_audit_addon). Default true. When false (free self-verify tenants) the
	 * export card is replaced by the upgrade CTA — the chain + in-browser verify
	 * stay fully available; only the export is the upsell. */
	canExport?: boolean;
}) {
	const rows = useMemo(() => parseRows(ndjson), [ndjson]);
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

	// Event type breakdown from loaded rows (fallback when no server summary).
	const eventTypeCounts = useMemo<Array<[string, number]>>(() => {
		const m = new Map<string, number>();
		for (const r of rows) m.set(r.event_type, (m.get(r.event_type) ?? 0) + 1);
		return [...m.entries()].sort((a, b) => b[1] - a[1]);
	}, [rows]);

	// Time span the loaded events cover (first → last event_time).
	const span = useMemo(() => {
		if (rows.length === 0) return null;
		const times = rows
			.map((r) => r.event_time)
			.filter(Boolean)
			.sort();
		const first = times[0];
		const last = times[times.length - 1];
		return first && last ? { first, last } : null;
	}, [rows]);

	// Per-day breakdown from loaded rows — fallback when no server summary.
	const clientByDay = useMemo(() => {
		const m = new Map<string, number>();
		for (const r of rows) {
			const d = r.event_time.slice(0, 10);
			if (d) m.set(d, (m.get(d) ?? 0) + 1);
		}
		return [...m.entries()]
			.sort((a, b) => (a[0] < b[0] ? -1 : 1))
			.map(([day, count]) => ({ day, count }));
	}, [rows]);

	// Prefer server aggregate (exact for any size); fall back to client.
	const total = summary?.total ?? rows.length;
	const aboutByType: Array<[string, number]> = summary
		? summary.by_type.map((t) => [t.event_type, t.count])
		: eventTypeCounts;
	const aboutByDay = summary?.by_day ?? clientByDay;
	const aboutSpan =
		summary?.first_event && summary?.last_event
			? { first: summary.first_event, last: summary.last_event }
			: span;

	// Export scope label — states the window + the EXACT in-scope event count
	// (server `total`, not the loaded-row count) on the download card.
	const exportScopeLabel = useMemo(() => {
		if (since && until) {
			return `${since.slice(0, 10)} → ${until.slice(0, 10)} · ${fmtCount(total)} events`;
		}
		if (range) {
			const rangeLabel =
				RANGE_OPTS.find((o) => o.key === range)?.label ?? range;
			return `last ${rangeLabel} · ${fmtCount(total)} events`;
		}
		return `${fmtCount(total)} events`;
	}, [since, until, range, total]);

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
		const url = URL.createObjectURL(
			new Blob([ndjson], { type: "application/x-ndjson" }),
		);
		const a = document.createElement("a");
		a.href = url;
		a.download = "tracelane-audit-evidence.ndjson";
		a.click();
		URL.revokeObjectURL(url);
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
				rowCount={rows.length}
				chainHead={chainHead}
				keyId={keyId}
				tenantPubkeyB64={tenantPubkeyB64}
				anchorRecords={anchorRecords}
			/>

			{/* ABOUT — supporting context: scope, types, time span, histogram.
			    Demoted below the trust panel. */}
			<AboutLedger
				total={total}
				loadedCount={rows.length}
				eventTypeCounts={aboutByType}
				byDay={aboutByDay}
				span={aboutSpan}
				anchoredCount={anchoredIndices.length}
				retentionDays={retentionDays}
				range={range}
				since={since}
				until={until}
			/>

			{/* NEGATIVE SCENARIO — what a failed verification looks like */}
			<NegativeScenarioPanel />

			{/* CHAIN VIEW — collapsed by default; expands to paginated rows */}
			<ChainList rows={rows} brokenSeqs={brokenSeqs} grandTotal={total} />

			{/* EXPORT CARD — the paid Article-12 evidence pack (f_audit_addon).
			    ADR-066: for free self-verify tenants (canExport=false) the download
			    affordance is replaced by the upgrade CTA — the chain + in-browser
			    verify above remain fully available. */}
			{canExport ? (
				<Card className="p-5">
					<h2 className="text-sm font-semibold text-ink">
						EU AI Act Article 12 evidence export
					</h2>
					<p className="mt-0.5 max-w-2xl text-[13px] text-ink-2">
						Download the ledger and verify it yourself with our open-source CLI
						— no Tracelane account, no network needed.
					</p>
					<div
						className="mt-1 text-[11px] text-ink-3"
						data-testid="export-scope"
					>
						{exportScopeLabel}
					</div>
					{total > rows.length && (
						<div className="mt-0.5 text-[11px] text-warn">
							This download contains the first{" "}
							<span className="tabular-nums">{fmtCount(rows.length)}</span>{" "}
							events of the window — narrow the range, or use the CLI for the
							complete export.
						</div>
					)}
					<div className="mt-3 flex flex-wrap items-center gap-3">
						<Button variant="secondary" onClick={download}>
							Download evidence (NDJSON)
						</Button>
						<code className="font-mono text-[11px] text-ink-2">
							tlane verify --tenant-pubkey &lt;key&gt;
						</code>
					</div>
				</Card>
			) : (
				<Card provenance className="p-5" data-testid="export-upsell">
					<div className="text-[11px] font-semibold uppercase tracking-wide text-seal-ink">
						Audit SKU · $999/mo add-on
					</div>
					<h2 className="mt-1 text-sm font-semibold text-ink">
						EU AI Act Article 12 evidence export
					</h2>
					<p className="mt-0.5 max-w-2xl text-[13px] text-ink-2">
						You can see and verify your own recent chain for free. The
						downloadable Article-12 evidence pack — the full-window,
						independently-verifiable NDJSON with public-anchor proofs, built
						for regulator hand-off — is the Audit add-on.
					</p>
					<div className="mt-3">
						<Link
							href="/settings/billing"
							className="cta-lava inline-flex h-9 items-center rounded-lg px-4 text-[13px] font-medium"
						>
							Add the Audit SKU
						</Link>
					</div>
				</Card>
			)}
		</div>
	);
}
