import { LedgerCoverage } from "@/app/audit/LedgerCoverage";
import { absoluteDate, formatDateTimeUtc, parseUtcMs } from "@/lib/format-date";
import { fmtCount } from "@/lib/metrics/format";
import type { VerifyReport } from "@tracelanedev/audit-verifier";
import { Badge, Skeleton } from "@tracelanedev/ui";
import type { ReactNode } from "react";
import type { AuditWindow, LedgerRange } from "./AuditLedgerView";

export interface AuditKeyContext {
	platformPubkeyB64?: string;
	platformKeySource?: "gateway" | "pinned";
	platformFingerprint?: string;
	workspaceFingerprint?: string;
	workspaceKeyCreatedAt?: string;
	/** AUD-29: the pinned root agrees with the key the gateway publishes? */
	platformCrossCheck?: "match" | "mismatch" | "unavailable";
	/** AUD-29: the first seq the workspace key signed (canonical anchor records). */
	workspaceKeySinceSeq?: number;
}
export function workspaceKeyDate(value?: string) {
	if (!value || !Number.isFinite(parseUtcMs(value))) return undefined;
	return absoluteDate(value).replace(
		/^(\w+) (\d+), (\d+)$/,
		(_, month: string, day: string, year: string) => `${day} ${month} ${year}`,
	);
}
export function platformSummary(
	report: VerifyReport,
	batches: number,
	createdAt?: string,
) {
	const merged: { start_seq: number; end_seq: number }[] = [];
	for (const range of [...report.platform_signed_ranges].sort(
		(a, b) => a.start_seq - b.start_seq,
	)) {
		const last = merged.at(-1);
		if (last && range.start_seq <= last.end_seq + 1)
			last.end_seq = Math.max(last.end_seq, range.end_seq);
		else merged.push({ ...range });
	}
	const ranges = merged
		.map((r) => `${fmtCount(r.start_seq)}–${fmtCount(r.end_seq)}`)
		.join(", ");
	const date = workspaceKeyDate(createdAt);
	return `${fmtCount(report.platform_signed_batches)} ${report.platform_signed_batches === 1 ? "batch" : "batches"} (seq ${ranges}) signed by Tracelane’s platform key${date ? ` before your workspace key was created on ${date}` : "; workspace key creation date unavailable"}; ${fmtCount(batches - report.platform_signed_batches)} ${batches - report.platform_signed_batches === 1 ? "batch" : "batches"} signed by your key`;
}
const publicErrors = new Set([
	"anchor_stripped",
	"anchor_body_invalid",
	"entry_signature_invalid",
	"inclusion_proof_invalid",
]);
function Step({
	number,
	title,
	status,
	tone = "neutral",
	children,
	loading = false,
}: {
	number: number;
	title: string;
	status: string;
	tone?: "neutral" | "ok" | "warn" | "danger";
	children?: ReactNode;
	loading?: boolean;
}) {
	return (
		<section
			className="surface-card p-5 sm:p-6"
			aria-label={`${number} · ${title}`}
		>
			<div className="flex flex-wrap items-center justify-between gap-3">
				<h2 className="text-base font-semibold">
					{number} · {title}
				</h2>
				<Badge tone={tone}>{status}</Badge>
			</div>
			{loading ? (
				<Skeleton className="mt-4 h-16 w-full rounded-control" />
			) : (
				<div className="mt-3 space-y-2 text-sm text-ink-2">{children}</div>
			)}
		</section>
	);
}
export function AuditWorkflow({
	report,
	rows,
	first,
	last,
	batches,
	ledgerRange,
	window,
	empty = false,
	readError = false,
	loading = false,
	...keys
}: AuditKeyContext & {
	report: VerifyReport | null;
	rows: number;
	first?: number;
	last?: number;
	batches: number;
	ledgerRange?: LedgerRange;
	window?: AuditWindow;
	empty?: boolean;
	readError?: boolean;
	loading?: boolean;
}) {
	const waiting = "Waits for the first recorded event";
	const unknown = "CANNOT DETERMINE";
	const checking = loading || (!report && rows > 0 && !readError);
	const errors = report?.errors ?? [];
	const signatureFailed = errors.some(
		(e) =>
			!publicErrors.has(e.kind) &&
			![
				"row_hash_mismatch",
				"chain_break",
				"prev_hash_mismatch",
				"seq_out_of_order",
				"unrooted_window",
				"anchor_coverage_gap",
			].includes(e.kind),
	);
	const publicFailed =
		!!report?.strip_detected || errors.some((e) => publicErrors.has(e.kind));
	const signaturesKnown =
		!!report && report.anchors_unverified === 0 && batches > 0;
	const signed = signaturesKnown && !signatureFailed;
	const intact = !!report?.hash_chain_valid && report.trust_established;
	const platform = report?.platform_signed_batches ?? 0;
	const collect = readError
		? unknown
		: empty
			? "No rows yet"
			: !ledgerRange
				? unknown
				: ledgerRange.total > rows
					? "Partial · rows outside this window"
					: "Complete";
	const link = readError
		? unknown
		: empty
			? waiting
			: !report
				? "Checking…"
				: !report.hash_chain_valid
					? `Broken${errors.find((e) => e.seq !== null)?.seq != null ? ` at seq ${errors.find((e) => e.seq !== null)?.seq}` : ""}`
					: intact
						? "Intact"
						: unknown;
	const sign = readError
		? unknown
		: empty
			? waiting
			: !report
				? "Checking…"
				: signatureFailed
					? "Failed"
					: !signed
						? unknown
						: platform > 0
							? "Verified — platform-signed"
							: "Verified";
	const anchor = readError
		? unknown
		: empty
			? waiting
			: !report
				? "Checking…"
				: publicFailed
					? "Failed"
					: !signed
						? unknown
						: report.anchors_included > 0
							? "Anchored"
							: "Signed-only";
	return (
		<div className="space-y-3" aria-label="Audit workflow">
			<Step
				number={1}
				title="Collect"
				status={loading ? "Loading…" : collect}
				loading={loading}
				tone={
					!readError && ledgerRange && rows > 0 && ledgerRange.total === rows
						? "ok"
						: "neutral"
				}
			>
				<p className="font-medium text-ink">What was recorded</p>
				<p>
					{readError
						? "The ledger read failed. Its contents and integrity are unknown here."
						: empty
							? "No rows yet. Route a call through the gateway to start recording."
							: `${fmtCount(rows)} rows loaded${first !== undefined && last !== undefined ? ` · sequence ${fmtCount(first)}–${fmtCount(last)}` : ""}.`}
				</p>
				{!readError && ledgerRange && (
					<p>
						{fmtCount(Math.max(0, ledgerRange.total - rows))} rows outside this
						check
					</p>
				)}
				{!readError && !ledgerRange && (
					<p>
						The workspace inventory read is unavailable; the loaded rows are
						still checked below.
					</p>
				)}
				{window && (
					<p>
						Read window: {formatDateTimeUtc(window.since)} →{" "}
						{formatDateTimeUtc(window.until)}.
					</p>
				)}
				{ledgerRange?.latest_event_at && (
					<p>Last event: {formatDateTimeUtc(ledgerRange.latest_event_at)}.</p>
				)}
				<LedgerCoverage />
			</Step>
			<Step
				number={2}
				title="Link"
				status={loading ? "Loading…" : link}
				loading={checking || loading}
				tone={
					readError || empty
						? "neutral"
						: report && !report.hash_chain_valid
							? "danger"
							: intact
								? "ok"
								: "neutral"
				}
			>
				<p className="font-medium text-ink">
					Nothing was edited, inserted or removed
				</p>
				<p>
					{empty
						? "No evidence yet."
						: readError
							? "The hash chain cannot be checked without the ledger rows."
							: intact
								? `Row hashes and links match from sequence ${fmtCount(report?.verified_from_seq ?? 0)} through ${fmtCount(last ?? report?.verified_from_seq ?? 0)}. This claim applies only to that checked range.`
								: "Hash, sequence and previous-hash checks did not establish an intact chain for this window."}
				</p>
			</Step>
			<Step
				number={3}
				title="Sign"
				status={loading ? "Loading…" : sign}
				loading={checking || loading}
				tone={
					readError || empty
						? "neutral"
						: signatureFailed
							? "danger"
							: signed
								? platform > 0
									? "warn"
									: "ok"
								: "neutral"
				}
			>
				<p className="font-medium text-ink">Who vouches for each batch</p>
				<p>
					{empty
						? "No evidence yet."
						: readError
							? "Signing evidence could not be read."
							: signatureFailed
								? errors.some(
										(e) => e.kind === "platform_key_after_workspace_key",
									)
									? "Platform key used after workspace signing began. A platform signature is accepted only before the first workspace-signed batch."
									: "A batch signature or signing key did not verify. Inspect the finding and batch record below."
								: signed && report
									? platform > 0
										? platformSummary(
												report,
												batches,
												keys.workspaceKeyCreatedAt,
											)
										: `${fmtCount(batches)} batches signed by your workspace key.`
									: "A trusted workspace key and complete batch evidence are required. No signature verdict is available."}
				</p>
				{!empty && (
					<>
						<p>
							Workspace key fingerprint (SHA-256):{" "}
							<code className="break-all">
								{keys.workspaceFingerprint || "Unavailable"}
							</code>
						</p>
						<p>
							Platform key fingerprint (SHA-256):{" "}
							<code className="break-all">
								{keys.platformFingerprint || "Unavailable"}
							</code>
						</p>
						<p>
							Platform trust root:{" "}
							{keys.platformKeySource === "gateway"
								? "gateway public-key endpoint"
								: keys.platformKeySource === "pinned"
									? "the key pinned in this verifier release"
									: "not supplied"}
							. Keys are supplied independently of this evidence.
						</p>
						{keys.platformKeySource === "pinned" && (
							<p
								className={
									keys.platformCrossCheck === "mismatch"
										? "font-medium text-danger-ink"
										: undefined
								}
							>
								{keys.platformCrossCheck === "match"
									? "Cross-check: the gateway publishes the same key."
									: keys.platformCrossCheck === "mismatch"
										? "Cross-check FAILED: the gateway publishes a different platform key than the one pinned in this release. Report it to security@tracelane.dev."
										: "Cross-check unavailable: the gateway's published key could not be read."}
							</p>
						)}
						{keys.workspaceKeySinceSeq !== undefined && (
							<p>
								Your workspace key took over at sequence{" "}
								{keys.workspaceKeySinceSeq}; a platform-signed batch at or after
								it would fail this check.
							</p>
						)}
						{platform > 0 && (
							<p>
								Tracelane’s shared key attests to those rows; they were not
								signed by your workspace key.
							</p>
						)}
					</>
				)}
			</Step>
			<Step
				number={4}
				title="Anchor"
				status={loading ? "Loading…" : anchor}
				loading={checking || loading}
				tone={
					readError || empty
						? "neutral"
						: publicFailed
							? "danger"
							: signed && report && report.anchors_included > 0
								? "ok"
								: "neutral"
				}
			>
				<p className="font-medium text-ink">
					Published where no one can rewrite it
				</p>
				<p>
					{empty
						? "No evidence yet."
						: readError
							? "Public inclusion evidence could not be read."
							: publicFailed
								? "A public inclusion proof or signed checkpoint failed, or a claimed public proof is missing."
								: signed && report
									? `${fmtCount(report.anchors_included)} of ${fmtCount(batches)} batches publicly anchored. ${fmtCount(batches - report.anchors_included)} signed-only batches have no verified public inclusion proof in this window.`
									: "Public inclusion could not be established from the available evidence."}
				</p>
				<p>
					Public anchoring checks Rekor inclusion proofs and signed checkpoints.
					Signed-only is a valid recording state, without a public witness.
				</p>
			</Step>
		</div>
	);
}
