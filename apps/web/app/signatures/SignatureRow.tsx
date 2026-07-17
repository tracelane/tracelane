/**
 * SignatureRow — one live AFT-1 detection, expandable to its evidence story.
 *
 * `spans.aft_ids` carries the CANONICAL AFT-1 id, so `sig.signature_id` IS the
 * canonical id (one vocabulary — see aft-taxonomy.ts). Summary columns:
 * Signature (name in ink + mono canonical id) | AFT-1 id | Severity |
 * Occurrences | Traces | First/Last seen.
 *
 * This component is used ONLY for live-detected signatures (detectorStatus ===
 * "live"). Roadmap taxonomy entries are split out in page.tsx and rendered in
 * their own simpler section — never routed through this component. That keeps
 * the expanded view honest: description, detection method, affected-traces link,
 * and audit-ledger note are all real live-detector evidence.
 *
 * Expanding shows crisp bullet points — what the pattern is, how it is detected,
 * the link to affected traces, and the tamper-evident ledger note.
 *
 * Colour discipline (ADR-053): names are INK; red is reserved for a real Block
 * severity. Links use --accent-ink; the AFT-1 id is the violet data hue.
 */
"use client";

import { aftFor } from "@/lib/aft-taxonomy";
import { absoluteDate } from "@/lib/format-date";
import { Badge } from "@tracelanedev/ui";
import Link from "next/link";
import { useId, useState } from "react";

export type SignatureHit = {
	signature_id: string;
	your_hits: number;
	action: "blocking" | "flag-only";
	/** RFC3339 UTC of the first/most-recent span that hit this signature. */
	first_seen: string;
	last_seen: string;
	/** Distinct traces this signature appears in. */
	traces_affected: number;
};

/** AFT-1 intervention type (observe-first): Block would halt under enforcement. */
function severity(action: SignatureHit["action"]): {
	label: string;
	tone: "danger" | "warn";
} {
	return action === "blocking"
		? { label: "Block", tone: "danger" }
		: { label: "Warn", tone: "warn" };
}

export function SignatureRow({ sig }: { sig: SignatureHit }) {
	const [open, setOpen] = useState(false);
	const detailId = useId();
	const t = aftFor(sig.signature_id);
	const name = t?.name ?? sig.signature_id;
	const sev = severity(sig.action);
	// range=30d so the destination window matches the 30-day signature aggregate
	// (the traces list now defaults to 24h, which would show fewer rows than the count).
	const tracesHref = `/traces?signature_id=${encodeURIComponent(sig.signature_id)}&range=30d`;

	return (
		<>
			{/* biome-ignore lint/a11y/useKeyWithClickEvents: keyboard users toggle via the focusable chevron button (first cell, aria-expanded/aria-controls); the row onClick is a mouse-only convenience. */}
			<tr
				className="cursor-pointer align-top transition-colors hover:bg-surface-2/30"
				onClick={() => setOpen((v) => !v)}
			>
				{/* DISCLOSURE — real button, the keyboard-accessible toggle */}
				<td className="py-2 pl-4 pr-1">
					<button
						type="button"
						aria-expanded={open}
						aria-controls={detailId}
						aria-label={open ? "Hide detail" : "Show detail"}
						onClick={(e) => {
							e.stopPropagation();
							setOpen((v) => !v);
						}}
						className="grid h-5 w-5 place-items-center rounded text-ink-3 outline-none transition-colors hover:text-ink focus-visible:ring-2 focus-visible:ring-seal"
					>
						<span aria-hidden className="text-[9px]">
							{open ? "▼" : "▶"}
						</span>
					</button>
				</td>

				{/* SIGNATURE — name in INK; mono canonical id beneath */}
				<td className="py-2 pr-4">
					<div className="font-medium text-ink">{name}</div>
					<div className="font-mono text-xs text-ink-3">{sig.signature_id}</div>
				</td>

				{/* AFT-1 — the canonical id (violet data hue); tooltip carries name + detection */}
				<td className="px-4 py-2">
					{t ? (
						<Badge
							tone="info"
							className="font-mono"
							title={`${t.name} — ${t.detection}  ·  AFT-1 taxonomy (CC0)`}
						>
							{sig.signature_id}
						</Badge>
					) : (
						<Badge
							tone="neutral"
							className="font-mono"
							title="This id is not in the AFT-1 taxonomy map — unmapped detection."
						>
							{sig.signature_id}
						</Badge>
					)}
				</td>

				{/* SEVERITY — AFT-1 intervention type (observe-first: recorded, not enforced) */}
				<td className="px-4 py-2">
					<Badge
						tone={sev.tone}
						title="AFT-1 intervention type · observe-first — the decision is recorded, not enforced."
					>
						{sev.label}
					</Badge>
				</td>

				{/* OCCURRENCES — tabular body font */}
				<td className="px-4 py-2 text-right tabular-nums text-ink">
					{sig.your_hits.toLocaleString()}
				</td>

				{/* TRACES — the functional link to the affected traces (--accent-ink) */}
				<td className="px-4 py-2 text-right">
					<Link
						href={tracesHref}
						onClick={(e) => e.stopPropagation()}
						className="font-medium tabular-nums text-accent-ink hover:underline"
					>
						{sig.traces_affected.toLocaleString()}
						<span aria-hidden> →</span>
					</Link>
				</td>

				{/* FIRST / LAST SEEN — both absolute UTC dates in the SAME format, so the
				    pair is directly comparable and never a misleading relative value
				    (RCA-signatures-first-last-seen-dates). Full timestamp on hover. */}
				<td className="px-4 py-2 whitespace-nowrap tabular-nums text-ink-2">
					<time dateTime={sig.first_seen} title={sig.first_seen}>
						{absoluteDate(sig.first_seen)}
					</time>
				</td>
				<td className="px-4 py-2 whitespace-nowrap tabular-nums text-ink-2">
					<time dateTime={sig.last_seen} title={sig.last_seen}>
						{absoluteDate(sig.last_seen)}
					</time>
				</td>
			</tr>

			{/* DETAIL — evidence story as scannable bullet points: what it is, how
			    it is detected (live), the affected-traces link, the ledger note. */}
			{open && (
				<tr id={detailId} className="bg-surface-2/20">
					<td />
					<td colSpan={7} className="px-4 pb-4 pt-2">
						<ul className="max-w-3xl space-y-1.5 text-sm">
							{t?.description && (
								<li className="flex gap-2">
									<span className="mt-0.5 shrink-0 select-none text-ink-3">
										·
									</span>
									<span className="text-ink-2">{t.description}</span>
								</li>
							)}
							{t?.detection && (
								<li className="flex gap-2">
									<span className="mt-0.5 shrink-0 select-none text-ink-3">
										·
									</span>
									<span className="text-ink-2">
										<span className="font-medium text-ink">Detection: </span>
										{t.detection}
									</span>
								</li>
							)}
							<li className="flex gap-2">
								<span className="mt-0.5 shrink-0 select-none text-ink-3">
									·
								</span>
								<Link
									href={tracesHref}
									onClick={(e) => e.stopPropagation()}
									className="font-medium text-accent-ink hover:underline"
								>
									View {sig.traces_affected.toLocaleString()}{" "}
									{sig.traces_affected === 1
										? "affected trace"
										: "affected traces"}{" "}
									→
								</Link>
							</li>
							<li className="flex gap-2 text-xs">
								<span className="mt-0.5 shrink-0 select-none text-ink-3">
									·
								</span>
								<span className="text-seal-ink">
									Matches recorded in tamper-evident audit ledger — open a trace
									to see its chain status.
								</span>
							</li>
						</ul>
					</td>
				</tr>
			)}
		</>
	);
}
