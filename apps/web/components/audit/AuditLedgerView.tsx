"use client";
import { fmtCount } from "@/lib/metrics/format";
import {
	type AuditKeyContext,
	AuditWorkflow,
	platformSummary,
	workspaceKeyDate,
} from "./AuditWorkflow";

import {
	type AuditVerdict,
	deriveAuditVerdict,
	humanizeVerdictKind,
	isAlarm,
} from "@/app/audit/verdict";
import { anchoredRecords } from "@/lib/audit-trust-state";
import { formatDateTimeUtc, parseUtcMs } from "@/lib/format-date";
import type { VerifyReport } from "@tracelanedev/audit-verifier";
import { Button, cn } from "@tracelanedev/ui";
import { useCallback, useEffect, useMemo, useState } from "react";

export interface LedgerRange {
	total: number;
	from?: number;
	to?: number;
	latest_event_at?: string | null;
	latest_anchor_at?: string | null;
}
export interface AuditWindow {
	since: string;
	until: string;
}
interface Row {
	seq: number;
	event_time: string;
	event_type: string;
	row_hash: string;
	prev_hash: string;
	payload?: unknown;
}
interface Anchor {
	type: "anchor";
	batch_start_seq: number;
	batch_end_seq: number;
	anchor_state: string;
	ed25519?: { pubkey: string };
	merkle_root: string;
	rekor?: { log_index?: string };
}
const fmt = (n: number) => fmtCount(n);
const BATCH_PAGE = 8;
const ROW_PAGE = 50;
const PUBLIC_LOG = "log2025-1.rekor.sigstore.dev";
const linkClass =
	"text-sm font-medium underline underline-offset-4 hover:text-ink";

function parseEvidence(ndjson: string) {
	const rows: Row[] = [];
	const anchors: Anchor[] = [];
	for (const line of ndjson.split(/\r?\n/)) {
		if (!line.trim()) continue;
		try {
			const record = JSON.parse(line);
			if (record.type === "anchor") anchors.push(record);
			else if (Number.isSafeInteger(record.seq)) rows.push(record);
		} catch {
			/* The verifier reports malformed evidence; never derive a pass here. */
		}
	}
	return { rows, anchors };
}
function publicKey(b64?: string) {
	try {
		return b64 ? Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)) : undefined;
	} catch {
		return undefined;
	}
}

/** Each remedy follows the failing layer; an unknown cause never becomes an accusation. */
function outcome(verdict: AuditVerdict, report: VerifyReport | null) {
	const kinds = new Set(report?.errors.map((e) => e.kind));
	switch (verdict.state) {
		case "ready":
			return {
				title: "Checking this window…",
				detail:
					"Recomputing row hashes and checking the available batch proofs in your browser.",
				next: "The result will apply only to the rows loaded below.",
			};
		case "empty":
			return {
				title: "No rows to check in this window",
				detail: "No verification result is available.",
				next: "Review the window dates or contact support if you expected records here.",
			};
		case "chain_broken":
			if (
				[
					"parse_error",
					"bad_tenant_id",
					"bad_row_hash_encoding",
					"v2_1_payload_not_string",
				].some((k) => kinds.has(k))
			)
				return {
					title: "Evidence could not be verified",
					detail:
						"The loaded evidence contains invalid data. This does not establish what happened to the stored ledger.",
					next: "Ask support to investigate the invalid record identified in the check report.",
				};
			return {
				title: "Record integrity check failed",
				detail:
					"A recorded hash, sequence or link does not match in this window. The check cannot determine the cause.",
				next: "Treat a repeated mismatch as a potential integrity incident. Ask support to investigate the first failing sequence. Nothing in the app can repair a broken chain.",
			};
		case "stripped":
			return {
				title: "A public proof is missing",
				detail:
					"A batch claims public anchoring, but its proof is absent from this evidence.",
				next: "Ask support to investigate the missing batch proof. Do not treat that batch as publicly verified.",
			};
		case "signature_failed":
			if (kinds.has("platform_key_after_workspace_key"))
				return {
					title: "Platform key used after workspace signing began",
					detail:
						"A platform-signed batch follows a workspace-signed batch. This violates the signing-key trust order.",
					next: "Ask support to investigate the later platform-signed batch. Do not treat it as a trusted continuation of your workspace ledger.",
				};
			if (
				verdict.reasons.every(
					(k) => k === "anchor_rows_missing" || k === "unrooted_window",
				)
			)
				return {
					title: "The proof needs rows outside this window",
					detail:
						"A batch refers to rows that were not loaded. Its proof cannot be checked here.",
					next: "Request evidence covering the full batch range. A missing row in this view is not evidence that the stored row changed.",
				};
			if (kinds.has("untrusted_tenant_key") || kinds.has("bad_tenant_pubkey"))
				return {
					title: "Batch signing key does not match",
					detail:
						"A batch’s signing key could not be matched to this workspace’s trusted key.",
					next: "Ask support to confirm the workspace signing key and its history. Do not replace your trusted key with a key taken from the evidence.",
				};
			if (kinds.has("merkle_root_mismatch") || kinds.has("bad_merkle_root"))
				return {
					title: "Batch fingerprint check failed",
					detail:
						"A batch fingerprint is invalid or does not match the row hashes in this window.",
					next: "Ask support to compare the batch record with its covered rows. Keep the original report for the investigation.",
				};
			if (kinds.has("bad_attestation_sig") || kinds.has("attestation_invalid"))
				return {
					title: "Batch signature check failed",
					detail:
						"A batch’s signed attestation did not verify against the trusted workspace key.",
					next: "Ask support to investigate the batch signature. Do not rely on that attestation until the mismatch is explained.",
				};
			return {
				title: "Public proof check failed",
				detail:
					"A public-log entry, inclusion proof or signed checkpoint did not verify.",
				next: "Ask support to investigate the batch’s public proof. A passing row-hash check does not make this proof valid.",
			};
		case "anchors_unverifiable":
			return {
				title: "A trusted signing key is missing",
				detail:
					"Batch records are present, but their signatures and public proofs could not be checked.",
				next: "Ask your workspace administrator or support to check access to the trusted audit public key, then reload. Do not take the key from the evidence being checked.",
			};
		case "unrooted_window":
			return {
				title: "This window has no verified starting point",
				detail:
					"The first ledger row is outside this view, and no verified public anchor roots the loaded rows. Their hashes have not been established here.",
				next: "Request a window containing the chain’s first row or a complete publicly anchored batch. Reloading the same bytes will not add that evidence.",
			};
		case "anchor_hole":
			return {
				title: "There is a gap in batch coverage",
				detail: `${fmt(verdict.rows)} loaded rows fall outside every recorded batch before a later batch. Public coverage is not established for those rows.`,
				next: "Reload to check whether anchoring has caught up. If the gap remains, send support the report so they can investigate the uncovered range.",
			};
		case "chain_only":
			return {
				title: "Hashes match. Public proof is not established.",
				detail:
					"The loaded chain is internally consistent, but this check verified no public anchor.",
				next: "Reload later to check for public proofs. If you need evidence now, ask support to investigate anchoring for this window.",
			};
		case "verified":
		case "verified_windowed":
			return {
				title: report?.rows_unanchored_tail
					? "Hashes match. Some public proof is pending."
					: verdict.state === "verified_windowed"
						? "The anchored range passed"
						: "This window passed",
				detail:
					"The checked row hashes match, and the included public proofs verified against the trusted workspace key.",
				next: "Save this check report if you need a record of the result. Rows outside this check have no verdict here.",
			};
	}
}

function Pager({
	page,
	pages,
	onChange,
	label,
}: {
	page: number;
	pages: number;
	onChange: (n: number) => void;
	label: string;
}) {
	if (pages <= 1) return null;
	return (
		<nav
			aria-label={label}
			className="mt-4 flex items-center justify-between gap-3 text-xs text-ink-2"
		>
			<Button
				variant="secondary"
				size="sm"
				disabled={page === 0}
				onClick={() => onChange(page - 1)}
			>
				Previous
			</Button>
			<span>
				Page {page + 1} of {pages}
			</span>
			<Button
				variant="secondary"
				size="sm"
				disabled={page + 1 >= pages}
				onClick={() => onChange(page + 1)}
			>
				Next
			</Button>
		</nav>
	);
}

function EvidenceExport({
	window,
	tenantPubkeyB64,
	canExport,
	platformPubkeyB64,
	workspaceKeySinceSeq,
}: {
	window?: AuditWindow;
	tenantPubkeyB64?: string;
	canExport: boolean;
	platformPubkeyB64?: string;
	workspaceKeySinceSeq?: number;
}) {
	const [since, setSince] = useState("");
	const [until, setUntil] = useState(window?.until.slice(0, 10) ?? "");
	const valid = Boolean(since && until && since <= until);
	function download() {
		if (!valid) return;
		const params = new URLSearchParams({
			since: `${since}T00:00:00Z`,
			until: `${until}T23:59:59.999Z`,
		});
		globalThis.location.href = `/api/audit/export?${params}`;
	}
	return (
		<details className="surface-card p-5">
			<summary className="cursor-pointer text-sm font-semibold">
				Export evidence{" "}
				<span className="ml-2 text-xs font-normal text-ink-3">Enterprise</span>
			</summary>
			<div className="mt-4 space-y-4 text-sm text-ink-2">
				<p>
					Viewing and checking the ledger is included on every plan. The
					Article-12 bulk evidence export requires Enterprise.
				</p>
				{canExport ? (
					<>
						<p>
							Select the UTC dates to download. This streams rows and batch
							records for those dates; it does not verify the download. A date
							boundary can exclude rows needed by a batch proof.
						</p>
						<div className="flex flex-wrap items-end gap-3">
							<label className="min-w-0">
								From (UTC)
								<input
									aria-label="Export from date"
									type="date"
									required
									value={since}
									onChange={(e) => setSince(e.target.value)}
									className="mt-1 block w-full rounded-control border border-line bg-surface px-3 py-2 text-ink"
								/>
							</label>
							<label className="min-w-0">
								Through (UTC)
								<input
									aria-label="Export through date"
									type="date"
									required
									value={until}
									onChange={(e) => setUntil(e.target.value)}
									className="mt-1 block w-full rounded-control border border-line bg-surface px-3 py-2 text-ink"
								/>
							</label>
							<Button variant="secondary" disabled={!valid} onClick={download}>
								Download selected dates (NDJSON)
							</Button>
						</div>
						{since && until && since > until && (
							<p role="alert" className="text-danger-ink">
								The end date must be on or after the start date.
							</p>
						)}
						<p>
							For large ledgers, choose manageable date ranges. A successful
							download alone does not prove completeness or integrity.
						</p>
					</>
				) : (
					<a className={linkClass} href="/settings/billing">
						View Enterprise plan
					</a>
				)}
				{tenantPubkeyB64 && (
					<div>
						<p className="mb-1">Workspace public key supplied to this check</p>
						<code className="block select-all break-all rounded bg-surface-2 p-3 text-xs text-ink">
							{tenantPubkeyB64}
						</code>
					</div>
				)}
				{tenantPubkeyB64 && platformPubkeyB64 && (
					<div>
						<p className="mb-1">
							Verify the downloaded file offline (the platform key is pinned in
							the verifier)
						</p>
						<code className="block select-all whitespace-pre-wrap break-all rounded bg-surface-2 p-3 text-xs text-ink">{`tlane verify ./audit.ndjson --tenant-pubkey '${tenantPubkeyB64}'${workspaceKeySinceSeq !== undefined ? ` --workspace-key-since-seq ${workspaceKeySinceSeq}` : ""}`}</code>
					</div>
				)}
				<a
					className={linkClass}
					href="https://docs.tracelane.dev/audit-ledger#verify"
				>
					How to verify exported evidence ↗
				</a>
			</div>
		</details>
	);
}

function ActivityTime({ at, now }: { at?: string | null; now: number | null }) {
	const ms = at ? parseUtcMs(at) : Number.NaN;
	if (!at || !Number.isFinite(ms)) return <span>Unknown</span>;
	const seconds = now === null ? null : Math.floor((now - ms) / 1000);
	const relative =
		seconds === null
			? formatDateTimeUtc(at)
			: seconds < 0
				? "Timestamp is in the future"
				: seconds < 60
					? "Less than a minute ago"
					: seconds < 3600
						? `${Math.floor(seconds / 60)} min ago`
						: seconds < 86400
							? `${Math.floor(seconds / 3600)} hr ago`
							: `${Math.floor(seconds / 86400)} days ago`;
	return (
		<time dateTime={at} title={formatDateTimeUtc(at)}>
			{relative}
		</time>
	);
}

export function AuditLedgerView({
	ndjson,
	tenantPubkeyB64,
	initialReport,
	ledgerRange,
	window,
	canExport = false,
	platformPubkeyB64,
	platformKeySource,
	platformFingerprint,
	workspaceFingerprint,
	workspaceKeyCreatedAt,
	workspaceKeySinceSeq,
	platformCrossCheck,
}: AuditKeyContext & {
	ndjson: string;
	tenantPubkeyB64?: string;
	initialReport?: VerifyReport;
	ledgerRange?: LedgerRange;
	window?: AuditWindow;
	canExport?: boolean;
}) {
	const { rows, anchors } = useMemo(() => parseEvidence(ndjson), [ndjson]);
	const [result, setResult] = useState<{
		bytes: string;
		key?: string;
		platformKey?: string;
		report: VerifyReport;
		at?: string;
	} | null>(
		initialReport
			? {
					bytes: ndjson,
					key: tenantPubkeyB64,
					platformKey: platformPubkeyB64,
					report: initialReport,
				}
			: null,
	);
	const report =
		result?.bytes === ndjson &&
		result.key === tenantPubkeyB64 &&
		result.platformKey === platformPubkeyB64
			? result.report
			: null;
	const [verifying, setVerifying] = useState(false);
	const [verifyError, setVerifyError] = useState(false);
	const [batchPage, setBatchPage] = useState(0);
	const [rowPage, setRowPage] = useState(0);
	const [showRows, setShowRows] = useState(false);
	const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
	const [now, setNow] = useState<number | null>(null);
	useEffect(() => {
		setNow(Date.now());
		const timer = globalThis.setInterval(() => setNow(Date.now()), 60_000);
		return () => globalThis.clearInterval(timer);
	}, []);
	const [saveError, setSaveError] = useState(false);
	const verify = useCallback(async () => {
		setVerifying(true);
		setVerifyError(false);
		setResult(null);
		try {
			const { verifyLedgerText } = await import("@tracelanedev/audit-verifier");
			const checked = await verifyLedgerText(ndjson, {
				tenantPubkey: publicKey(tenantPubkeyB64),
				platformPubkey: publicKey(platformPubkeyB64),
				workspaceKeySinceSeq,
			});
			setResult({
				bytes: ndjson,
				key: tenantPubkeyB64,
				platformKey: platformPubkeyB64,
				report: checked,
				at: new Date().toISOString(),
			});
		} catch {
			setVerifyError(true);
		} finally {
			setVerifying(false);
		}
	}, [ndjson, tenantPubkeyB64, platformPubkeyB64, workspaceKeySinceSeq]);
	useEffect(() => {
		if (!initialReport && ndjson.trim()) void verify();
	}, [verify, initialReport, ndjson]);
	const verdict = deriveAuditVerdict(report);
	const platformVerified =
		!!report &&
		report.platform_signed_batches > 0 &&
		report.hash_chain_valid &&
		report.signatures_valid &&
		report.anchors_unverified === 0 &&
		report.trust_established &&
		report.rows_uncovered_by_anchors === 0 &&
		report.rows_unanchored_tail === 0;
	const copy = platformVerified
		? {
				title:
					report.platform_signed_batches === anchors.length
						? "Verified — platform-signed"
						: "Verified — part platform-signed",
				detail: platformSummary(report, anchors.length, workspaceKeyCreatedAt),
				next: "Save this check report. Platform signatures attest to unchanged rows under Tracelane’s shared key; public inclusion is checked separately below.",
			}
		: outcome(verdict, report);
	const alarm = isAlarm(verdict);
	const windowPassed =
		(verdict.state === "verified" || verdict.state === "verified_windowed") &&
		report?.rows_unanchored_tail === 0;
	const hashChecked = Boolean(
		report?.trust_established && report.hash_chain_valid,
	);
	const first = rows[0]?.seq;
	const last = rows.at(-1)?.seq;
	const rangeValid =
		ledgerRange &&
		Number.isSafeInteger(ledgerRange.total) &&
		ledgerRange.total >= rows.length &&
		(last === undefined ||
			(ledgerRange.to !== undefined && ledgerRange.to >= last))
			? ledgerRange
			: undefined;
	const checkedRows = report?.trust_established
		? rows.filter((r) => r.seq >= report.verified_from_seq).length
		: 0;
	const passed =
		windowPassed && rangeValid?.total === checkedRows && !platformVerified;
	const coverageTitle =
		windowPassed && !passed
			? rangeValid
				? `${fmt(checkedRows)} of ${fmt(rangeValid.total)} rows checked`
				: `${fmt(checkedRows)} rows checked · total unknown`
			: undefined;
	const outside = rangeValid ? rangeValid.total - rows.length : undefined;
	const empty = !ndjson.trim() && rangeValid?.total === 0;
	const noWindowRows = !ndjson.trim() && !empty;
	const publicBatches = anchoredRecords(anchors);
	const firstFinding =
		report?.errors.find((e) => e.seq !== null) ?? report?.errors[0];
	const findingIndex =
		firstFinding?.seq == null
			? -1
			: rows.findIndex((r) => r.seq === firstFinding.seq);
	const anchoredRowsChanged =
		report &&
		!report.hash_chain_valid &&
		publicBatches.length > 0 &&
		report.anchors_included === publicBatches.length &&
		report.errors.some(
			(e) =>
				e.kind === "row_hash_mismatch" &&
				e.seq !== null &&
				publicBatches.some(
					(a) =>
						e.seq !== null &&
						e.seq >= a.batch_start_seq &&
						e.seq <= a.batch_end_seq,
				),
		);
	const firstBatch = firstFinding?.detail.match(/^batch (\d+-\d+):/)?.[1];
	const batchPages = Math.max(1, Math.ceil(anchors.length / BATCH_PAGE));
	const currentBatchPage = Math.min(batchPage, batchPages - 1);
	const rowPages = Math.max(1, Math.ceil(rows.length / ROW_PAGE));
	const currentRowPage = Math.min(rowPage, rowPages - 1);
	const checkedFrom = report?.trust_established
		? report.verified_from_seq
		: undefined;
	useEffect(() => {
		if (
			selectedSeq === null ||
			!showRows ||
			!rows
				.slice(currentRowPage * ROW_PAGE, (currentRowPage + 1) * ROW_PAGE)
				.some((r) => r.seq === selectedSeq)
		)
			return;
		const event = document.getElementById(`audit-event-${selectedSeq}`);
		event?.scrollIntoView({ block: "center" });
		event?.focus({ preventScroll: true });
	}, [selectedSeq, showRows, currentRowPage, rows]);
	function openFinding() {
		if (findingIndex < 0 || firstFinding?.seq == null) return;
		setRowPage(Math.floor(findingIndex / ROW_PAGE));
		setShowRows(true);
		setSelectedSeq(firstFinding.seq);
		// A repeated click can target an event already rendered on this page.
		const event = document.getElementById(`audit-event-${firstFinding.seq}`);
		if (event instanceof HTMLDetailsElement) event.open = true;
		event?.scrollIntoView({ block: "center" });
		event?.focus({ preventScroll: true });
	}
	function saveReport() {
		if (!report) return;
		try {
			const blob = new Blob(
				[
					JSON.stringify(
						{
							checked_at: result?.at ?? null,
							scope: {
								loaded_from_seq: first,
								loaded_through_seq: last,
								loaded_rows: rows.length,
								read_window: window,
								workspace_inventory_snapshot: rangeValid,
								workspace_integrity: "not_evaluated",
								outside_loaded_window: outside ?? null,
							},
							verification: report,
							trust_roots: {
								workspace_pubkey_b64: tenantPubkeyB64 ?? null,
								platform_pubkey_b64: platformPubkeyB64 ?? null,
								platform_source: platformKeySource ?? null,
								workspace_fingerprint_sha256: workspaceFingerprint ?? null,
								platform_fingerprint_sha256: platformFingerprint ?? null,
							},
						},
						null,
						2,
					),
				],
				{ type: "application/json" },
			);
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			a.href = url;
			a.download = "tracelane-audit-check.json";
			a.click();
			setTimeout(() => URL.revokeObjectURL(url), 0);
			setSaveError(false);
		} catch {
			setSaveError(true);
		}
	}

	return (
		<div className="space-y-5">
			<section
				className={cn(
					"surface-card overflow-hidden border",
					alarm
						? "border-danger/40"
						: platformVerified
							? "border-warn/40"
							: passed
								? "border-seal-line"
								: "border-line",
				)}
				aria-label="Evidence check"
			>
				<div
					className={cn(
						"p-5 sm:p-7",
						alarm
							? "bg-danger-soft"
							: platformVerified
								? "bg-warn-soft"
								: passed
									? "bg-seal-soft"
									: "bg-surface",
					)}
				>
					<div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest">
						<span
							aria-hidden="true"
							className={cn(
								"h-2 w-2 rounded-full",
								alarm
									? "bg-danger"
									: platformVerified
										? "bg-warn"
										: passed
											? "bg-seal-ink"
											: "bg-ink-3",
							)}
						/>
						{empty
							? "Start your evidence trail"
							: alarm
								? "Action required · these rows"
								: passed
									? "Verified · these rows only"
									: "Evidence check · these rows"}
					</div>
					<div aria-live="polite" className="mt-3">
						<h2
							className={cn(
								"text-2xl font-semibold tracking-tight sm:text-3xl",
								alarm && "text-danger-ink",
							)}
						>
							{empty
								? "No events in this ledger"
								: noWindowRows
									? "No evidence loaded. Integrity is unknown."
									: verifyError
										? "CANNOT DETERMINE — the check could not finish"
										: verifying
											? "Checking this window…"
											: platformVerified
												? copy.title
												: (coverageTitle ?? copy.title)}
						</h2>
						<p className="mt-3 max-w-3xl text-sm leading-relaxed text-ink-2">
							{empty
								? "Send a call through the Tracelane gateway to start a tamper-evident record."
								: noWindowRows
									? "This read returned no rows. That does not establish that your workspace ledger is empty."
									: verifyError
										? "No new verdict is available. Retry the check, or reload the evidence if the problem continues."
										: copy.detail}
						</p>
					</div>
					<details className="mt-3 text-xs text-ink-2">
						<summary className="cursor-pointer">
							Check scope and recorder activity
						</summary>
						{!empty && (
							<div className="mt-4 border-t border-line pt-3 text-xs text-ink-2">
								<p>
									<strong className="text-ink">
										{fmt(rows.length)} rows loaded
									</strong>
									{first !== undefined &&
										last !== undefined &&
										` · sequence ${fmt(first)}–${fmt(last)}`}
								</p>
								{report && (
									<p className="mt-1">
										Hash-check range:{" "}
										{checkedFrom !== undefined && last !== undefined
											? `sequence ${fmt(checkedFrom)}–${fmt(last)}`
											: "Not established"}
									</p>
								)}
								<p className="mt-1">
									Total recorded rows:{" "}
									<strong className="text-ink">
										{rangeValid ? fmt(rangeValid.total) : "Unavailable"}
									</strong>
								</p>
								<p className="mt-1">
									{outside !== undefined
										? `${fmt(outside)} rows outside this check`
										: "Rows outside this window are not counted here"}
								</p>
							</div>
						)}
						<dl
							className="mt-4 grid gap-3 border-t border-line pt-4 text-xs sm:grid-cols-2"
							aria-label="Recorder activity"
						>
							<div>
								<dt className="text-ink-3">Last event recorded</dt>
								<dd className="mt-1 font-medium">
									<ActivityTime at={ledgerRange?.latest_event_at} now={now} />
								</dd>
							</div>
							<div>
								<dt className="text-ink-3">Last anchored</dt>
								<dd className="mt-1 font-medium">
									<ActivityTime at={ledgerRange?.latest_anchor_at} now={now} />
								</dd>
							</div>
						</dl>
						<p className="mt-2 text-xs text-ink-3">
							Activity as of this read. Refresh to check for new events and
							anchors.
						</p>
					</details>
					{alarm && firstFinding && (
						<p className="mt-3 text-sm font-medium text-danger-ink">
							{findingIndex >= 0 && firstFinding.seq !== null ? (
								<a
									href={`#audit-event-${firstFinding.seq}`}
									className="underline underline-offset-4"
									onClick={(event) => {
										event.preventDefault();
										openFinding();
									}}
								>
									First finding · sequence {fmt(firstFinding.seq)}
								</a>
							) : (
								<>
									First finding
									{firstFinding.seq !== null
										? ` · sequence ${fmt(firstFinding.seq)} (not in this read)`
										: firstBatch
											? ` · batch ${firstBatch}`
											: ""}
								</>
							)}
							: {humanizeVerdictKind(firstFinding.kind)}
						</p>
					)}

					{!empty && !noWindowRows && (
						<div className="mt-5 flex flex-wrap gap-2">
							{report && (
								<Button
									variant={alarm ? "primary" : "secondary"}
									onClick={saveReport}
									disabled={!report}
								>
									Save check report
								</Button>
							)}
							<Button
								variant={alarm ? "secondary" : "primary"}
								onClick={() => globalThis.location.reload()}
								disabled={verifying}
							>
								{verifying
									? "Checking recent evidence…"
									: "Refresh & check latest"}
							</Button>
						</div>
					)}
					{(empty || noWindowRows) && (
						<div className="mt-5 flex flex-wrap gap-4">
							{empty && (
								<a
									href="/onboarding"
									className="inline-flex min-h-9 items-center rounded-control bg-selected px-4 text-sm font-medium text-selected-on"
								>
									Connect the gateway
								</a>
							)}
							<a href="/audit" className={linkClass}>
								Reload evidence
							</a>
							{noWindowRows && (
								<a href="/support" className={linkClass}>
									Contact support
								</a>
							)}
						</div>
					)}
				</div>
			</section>

			<AuditWorkflow
				report={report}
				rows={rows.length}
				first={first}
				last={last}
				batches={anchors.length}
				ledgerRange={rangeValid}
				window={window}
				empty={empty}
				readError={verifyError || noWindowRows}
				platformPubkeyB64={platformPubkeyB64}
				platformKeySource={platformKeySource}
				platformFingerprint={platformFingerprint}
				workspaceFingerprint={workspaceFingerprint}
				workspaceKeyCreatedAt={workspaceKeyCreatedAt}
				workspaceKeySinceSeq={workspaceKeySinceSeq}
				platformCrossCheck={platformCrossCheck}
			/>
			<section className="space-y-3" aria-label="Your evidence">
				<h2 className="text-base font-semibold">Your evidence</h2>
				<Button variant="secondary" disabled={!report} onClick={saveReport}>
					Save check report
				</Button>
				<EvidenceExport
					window={window}
					tenantPubkeyB64={tenantPubkeyB64}
					platformPubkeyB64={platformPubkeyB64}
					workspaceKeySinceSeq={workspaceKeySinceSeq}
					canExport={canExport}
				/>
			</section>

			{empty ? (
				<section
					className="grid gap-4 sm:grid-cols-2"
					aria-label="Getting started"
				>
					<div className="surface-card p-5">
						<p className="text-xs font-medium text-ink-3">01 · RECORD</p>
						<h2 className="mt-2 font-semibold">
							Route a call through the gateway
						</h2>
						<p className="mt-2 text-sm text-ink-2">
							SDK or OTLP capture alone does not add a call to the hash chain.
						</p>
					</div>
					<div className="surface-card p-5">
						<p className="text-xs font-medium text-ink-3">02 · CHECK</p>
						<h2 className="mt-2 font-semibold">
							Return here to check the evidence
						</h2>
						<p className="mt-2 text-sm text-ink-2">
							Row hashes and batch proofs have separate results. Public
							anchoring is per batch and best-effort.
						</p>
					</div>
				</section>
			) : (
				report && (
					<details className="surface-card p-5 sm:p-6" aria-label="Next steps">
						<summary className="cursor-pointer text-sm font-semibold">
							Findings and next steps
						</summary>
						<h2 className="text-base font-semibold">
							{alarm ? "What to do now" : "Your next step"}
						</h2>
						{alarm ? (
							<ol className="mt-4 space-y-3 text-sm text-ink-2">
								<li>
									<strong className="text-ink">1. Preserve this result.</strong>{" "}
									Save the check report before reloading. It includes the check
									scope and failure details.
								</li>
								<li>
									<strong className="text-ink">2. Check a fresh read.</strong>{" "}
									Use “Refresh & check latest” and compare the new result with
									this report.
								</li>
								<li>
									<strong className="text-ink">
										3. Investigate this failure.
									</strong>{" "}
									{copy.next}{" "}
									<a className={linkClass} href="/support">
										Contact support →
									</a>
								</li>
							</ol>
						) : (
							<>
								<p className="mt-2 max-w-3xl text-sm leading-relaxed text-ink-2">
									{copy.next}
								</p>
								<div className="mt-4 flex flex-wrap gap-4">
									<Button
										variant="bare"
										className={linkClass}
										type="button"
										onClick={saveReport}
									>
										Save check report
									</Button>
									{!windowPassed && !platformVerified && (
										<a href="/support" className={linkClass}>
											Contact support →
										</a>
									)}
								</div>
							</>
						)}
						{saveError && (
							<p role="alert" className="mt-2 text-sm text-danger-ink">
								The report could not be saved. Retry or copy the details below.
							</p>
						)}
						<div className="mt-5 grid gap-3 border-t border-line pt-4 text-sm sm:grid-cols-2">
							<p>
								<span className="text-ink-3">Row hashes</span>
								<br />
								<strong>
									{!report.hash_chain_valid
										? "Check failed"
										: hashChecked
											? `Match from sequence ${fmt(report.verified_from_seq)}`
											: "Not established in this window"}
								</strong>
							</p>
							<p>
								<span className="text-ink-3">Public proofs</span>
								<br />
								<strong>
									{!report.hash_chain_valid
										? anchoredRowsChanged
											? "The anchored root no longer matches these rows"
											: "Public proofs do not establish integrity for these rows"
										: `${fmt(report.anchors_included)} verified in this window${report.signatures_valid && !report.strip_detected ? "" : " · a batch check failed"}`}
								</strong>
							</p>
						</div>
						{report.rows_unanchored_tail > 0 && (
							<p className="mt-3 text-sm text-ink-2">
								{fmt(report.rows_unanchored_tail)} loaded rows follow the last
								recorded batch, or have no batch yet. Their public anchoring is
								not established here.
							</p>
						)}
						{report.errors.length > 0 && (
							<details className="mt-4 text-sm">
								<summary className="cursor-pointer font-medium">
									Check details · {fmt(report.errors.length)} finding
									{report.errors.length === 1 ? "" : "s"}
								</summary>
								<ul className="mt-3 space-y-3">
									{report.errors.slice(0, ROW_PAGE).map((error, i) => (
										<li
											key={`${error.kind}-${error.seq}-${i}`}
											className="break-words rounded-control bg-surface-2 p-3 text-xs text-ink-2"
										>
											<strong>{humanizeVerdictKind(error.kind)}</strong>
											{error.seq !== null && (
												<span> · sequence {fmt(error.seq)}</span>
											)}
											<pre className="mt-1 whitespace-pre-wrap break-all">
												{error.detail}
											</pre>
										</li>
									))}
								</ul>
								{report.errors.length > ROW_PAGE && (
									<p className="mt-3 text-xs">
										First {ROW_PAGE} findings shown. Save the check report for
										all {fmt(report.errors.length)} findings.
									</p>
								)}
							</details>
						)}
					</details>
				)
			)}

			{!empty && (
				<div className="surface-card p-5 sm:px-6">
					<p className="text-xs text-ink-2">
						Workspace-wide integrity:{" "}
						<strong className="text-ink">Not established by this check</strong>.
						No verdict for rows or proofs outside this window.
					</p>
					<details className="mt-4 text-xs text-ink-2">
						<summary className="cursor-pointer underline underline-offset-4">
							What exactly was checked?
						</summary>
						<div className="mt-3 space-y-2 leading-relaxed">
							<p>
								The browser receives at most 1,000 of the newest rows within
								your plan’s ledger retention window, ordered by sequence. Only
								complete batch records for those rows are returned. Hash
								checking starts at genesis or a fully included public anchor.
								Without either, these rows remain unrooted.
							</p>
							{window && (
								<p>
									Read window: {formatDateTimeUtc(window.since)} →{" "}
									{formatDateTimeUtc(window.until)}.
								</p>
							)}
							{checkedFrom !== undefined && last !== undefined && (
								<p>
									Row-hash verification starts at sequence {fmt(checkedFrom)}{" "}
									and ends at {fmt(last)}. Loaded rows before that starting
									point are not verified.
								</p>
							)}
							<p>
								Counts and evidence are separate reads and can change as new
								events arrive. Refresh to read again.
							</p>
							{report && result?.at && (
								<p>
									Checked at {formatDateTimeUtc(result.at)}. This is a saved
									view, not a live monitor.
								</p>
							)}
						</div>
					</details>
				</div>
			)}
			{!empty && !noWindowRows && (
				<section
					className="surface-card p-5 sm:p-6"
					aria-label="Batch evidence"
				>
					<div className="flex flex-wrap items-baseline justify-between gap-2">
						<h2 className="text-base font-semibold">Batch evidence</h2>
						<span className="text-xs text-ink-3">
							{fmt(anchors.length)}{" "}
							{anchors.length === 1 ? "record" : "records"} loaded ·{" "}
							{fmt(publicBatches.length)} with public proof attached
						</span>
					</div>
					<p className="mt-2 text-sm text-ink-2">
						Each batch covers a range of events. These are the records available
						in this window; attached proof is not a verification result.
					</p>
					{anchors.length === 0 ? (
						<p className="mt-4 rounded-card bg-surface-2 p-4 text-sm text-ink-2">
							No batch records were returned for these rows. This does not
							establish whether other batches exist.
						</p>
					) : (
						<>
							<div className="mt-4 divide-y divide-line border-y border-line">
								{anchors
									.slice(
										currentBatchPage * BATCH_PAGE,
										(currentBatchPage + 1) * BATCH_PAGE,
									)
									.map((a, i) => (
										<details key={`${a.batch_start_seq}-${i}`} className="py-3">
											<summary className="cursor-pointer text-sm">
												<span className="font-mono font-medium">
													{fmt(a.batch_start_seq)}–{fmt(a.batch_end_seq)}
												</span>
												<span className="ml-3 text-xs text-ink-2">
													{anchoredRecords([a]).length
														? "Public proof attached"
														: a.anchor_state === "anchored"
															? "Claims anchoring · proof missing"
															: "Signed record · no public anchor"}
												</span>
											</summary>
											<dl className="mt-3 space-y-2 break-all rounded bg-surface-2 p-3 text-xs text-ink-2">
												<div>
													<dt>Signer</dt>
													<dd>
														{a.ed25519?.pubkey === tenantPubkeyB64 &&
														tenantPubkeyB64
															? "Your workspace key"
															: a.ed25519?.pubkey === platformPubkeyB64 &&
																	platformPubkeyB64
																? `Tracelane platform key${platformVerified && workspaceKeyDate(workspaceKeyCreatedAt) ? ` (before your workspace key existed on ${workspaceKeyDate(workspaceKeyCreatedAt)})` : " (workspace key creation date unavailable)"}`
																: "Unknown key"}
														.{" "}
														{report
															? "See Sign above for the verification result."
															: "Not yet checked."}
													</dd>
												</div>
												<div>
													<dt>Batch fingerprint</dt>
													<dd className="font-mono">{a.merkle_root}</dd>
												</div>
												{a.rekor?.log_index && (
													<div>
														<dt>Public log coordinate</dt>
														<dd>
															{PUBLIC_LOG} · index {a.rekor.log_index}
														</dd>
													</div>
												)}
											</dl>
											<details className="mt-3 text-xs text-ink-2">
												<summary className="cursor-pointer">
													Inspect batch proof record
												</summary>
												<pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-2 p-3">
													{JSON.stringify(a, null, 2)}
												</pre>
											</details>
										</details>
									))}
							</div>
							<Pager
								page={currentBatchPage}
								pages={batchPages}
								onChange={setBatchPage}
								label="Loaded batches"
							/>
							<p className="mt-3 text-xs text-ink-3">
								Showing {currentBatchPage * BATCH_PAGE + 1}–
								{Math.min((currentBatchPage + 1) * BATCH_PAGE, anchors.length)}{" "}
								of {fmt(anchors.length)} loaded batch records. Batches outside
								this window are not listed or checked.
							</p>
						</>
					)}
					<details
						className="mt-5 border-t border-line pt-4"
						open={showRows}
						onToggle={(e) => setShowRows(e.currentTarget.open)}
					>
						<summary className="cursor-pointer text-sm font-medium">
							Inspect individual events · {fmt(rows.length)} loaded
						</summary>
						{showRows && (
							<div className="mt-4">
								<p className="mb-3 text-xs text-ink-3">
									Only loaded events are browsable. No additional ledger rows
									are fetched by pagination.
								</p>
								{rows
									.slice(
										currentRowPage * ROW_PAGE,
										(currentRowPage + 1) * ROW_PAGE,
									)
									.map((r, i) => (
										<details
											key={`${r.seq}-${i}`}
											id={`audit-event-${r.seq}`}
											tabIndex={-1}
											open={selectedSeq === r.seq ? true : undefined}
											data-highlighted={
												selectedSeq === r.seq ? "true" : undefined
											}
											className={cn(
												"scroll-mt-24 border-b border-line p-3 text-xs",
												selectedSeq === r.seq &&
													"rounded-control bg-danger-soft ring-2 ring-danger/40",
											)}
										>
											<summary className="cursor-pointer break-words">
												<span className="font-mono">#{fmt(r.seq)}</span> ·{" "}
												{r.event_type} · {formatDateTimeUtc(r.event_time)}
												{report?.errors.some((e) => e.seq === r.seq) && (
													<strong className="ml-2 text-danger-ink">
														Finding
													</strong>
												)}
											</summary>
											<pre className="mt-3 whitespace-pre-wrap break-all rounded bg-surface-2 p-3">
												{JSON.stringify(r, null, 2)}
											</pre>
										</details>
									))}
								<Pager
									page={currentRowPage}
									pages={rowPages}
									onChange={setRowPage}
									label="Loaded events"
								/>
							</div>
						)}
					</details>
				</section>
			)}
		</div>
	);
}
