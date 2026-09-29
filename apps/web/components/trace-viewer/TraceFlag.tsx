"use client";
import { Button } from "@tracelanedev/ui";

/**
 * OBS-18 — flag a trace `good` / `bad` / `needs review`, with an optional note.
 *
 * The cheapest possible ground truth: every later eval and failure-signature
 * feature needs a human verdict to learn from, and until now nothing recorded
 * one.
 *
 * **States, all four rendered rather than assumed:** unflagged · flagged (with
 * who and when) · saving · error. A viewer sees the control DISABLED with the
 * reason, not hidden — hiding it would leave them wondering whether the feature
 * exists, and the gateway refuses the write anyway, so this is the honest
 * mirror of a gate that is enforced server-side.
 */

import { apiFetchRaw } from "@/lib/api-fetch";
import { absoluteDate } from "@/lib/format-date";
import {
	announcePopoverOpen,
	onOtherPopoverOpen,
} from "@/lib/popover-coordination";
import { useEffect, useState } from "react";

/** This popover's id — see `lib/popover-coordination.ts`. */
const POPOVER_ID = "trace-flag";

export type Annotation = {
	trace_id: string;
	span_id: string;
	label: "good" | "bad" | "needs_review";
	note: string;
	author_sub: string;
	created_at: string;
	updated_at: string;
};

const LABELS: { value: Annotation["label"]; text: string }[] = [
	{ value: "good", text: "Good" },
	{ value: "bad", text: "Bad" },
	{ value: "needs_review", text: "Needs review" },
];

function labelText(l: Annotation["label"]): string {
	return LABELS.find((x) => x.value === l)?.text ?? l;
}

export function TraceFlag({
	traceId,
	initial,
	canWrite,
	embedded = false,
}: {
	embedded?: boolean;
	traceId: string;
	initial: Annotation | null;
	/** False for a viewer. The gateway enforces it too; this only reflects it. */
	canWrite: boolean;
}) {
	const [current, setCurrent] = useState<Annotation | null>(initial);
	const [open, setOpen] = useState(embedded);
	const [note, setNote] = useState(initial?.note ?? "");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	// Close THIS popover when a sibling (Share) announces it opened, and
	// announce our own opens the same way — item 8.
	useEffect(() => onOtherPopoverOpen(POPOVER_ID, () => setOpen(false)), []);
	function toggleOpen(): void {
		setOpen((v) => {
			const next = !v;
			if (next) announcePopoverOpen(POPOVER_ID);
			return next;
		});
	}

	async function save(label: Annotation["label"]) {
		setBusy(true);
		setError(null);
		try {
			const res = await apiFetchRaw(
				`/api/traces/${encodeURIComponent(traceId)}/annotations`,
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ label, note }),
				},
			);
			if (!res.ok) {
				// Keep the server's meaning. A 403 here means "your role cannot do
				// this", which is a different thing from "it broke", and the user
				// can act on the first.
				setError(
					res.status === 403
						? "Your role can view flags but not set them."
						: "Couldn't save the flag. It was not recorded.",
				);
				return;
			}
			setCurrent((await res.json()) as Annotation);
			setOpen(false);
		} catch {
			setError("Couldn't reach the server. The flag was not recorded.");
		} finally {
			setBusy(false);
		}
	}

	async function remove() {
		setBusy(true);
		setError(null);
		try {
			const res = await apiFetchRaw(
				`/api/traces/${encodeURIComponent(traceId)}/annotations`,
				{ method: "DELETE" },
			);
			if (!res.ok && res.status !== 404) {
				setError("Couldn't remove the flag. It is still recorded.");
				return;
			}
			setCurrent(null);
			setNote("");
			setOpen(false);
		} catch {
			setError("Couldn't reach the server. The flag is still recorded.");
		} finally {
			setBusy(false);
		}
	}

	return (
		<div className="relative inline-flex flex-col items-start gap-1">
			<div className="inline-flex items-center gap-2">
				{current ? (
					<span className="inline-flex items-center gap-1.5 rounded-card border border-line bg-surface-2 px-2 py-1 text-sm">
						{/* Glyph AND text: state must never be conveyed by symbol or
						    colour alone — a screen reader has to get the same answer. */}
						<span aria-hidden="true">⚑</span>
						<span className="font-medium">{labelText(current.label)}</span>
						<span className="text-ink-3">
							· {absoluteDate(current.updated_at)}
						</span>
					</span>
				) : (
					<span className="text-sm text-ink-3">Not flagged</span>
				)}

				<Button
					variant="bare"
					type="button"
					disabled={!canWrite || busy}
					onClick={toggleOpen}
					title={
						canWrite ? undefined : "Your role can view flags but not set them."
					}
					className="rounded-control border border-line px-2 py-1 text-sm disabled:opacity-50"
				>
					{busy ? "Saving…" : current ? "Edit" : "⚑ Flag"}
				</Button>

				{current && canWrite && (
					<Button
						variant="bare"
						type="button"
						disabled={busy}
						onClick={remove}
						className="rounded-control border border-line px-2 py-1 text-sm disabled:opacity-50"
					>
						Remove
					</Button>
				)}
			</div>

			{/* ERROR is stated, never swallowed: a failed save that looks like a
			    success is how a verdict silently goes unrecorded. */}
			{error && (
				<p role="alert" className="text-sm text-ink-2">
					{error}
				</p>
			)}

			{/* Anchored popover, same shape as `ShareDialog` — `absolute`, out of
			    flow, so opening this never grows the header's height (item 8:
			    it used to add ~200px inline). `onOtherPopoverOpen`/
			    `announcePopoverOpen` above keep this and Share mutually
			    exclusive so their popovers never overlap. */}
			{open && canWrite && (
				<div
					className={
						embedded
							? "mt-3 space-y-2"
							: "absolute left-0 top-full z-10 mt-1.5 w-72 space-y-2 rounded-card border border-line bg-surface p-3 shadow-[var(--shadow-card)]"
					}
				>
					<div className="flex gap-2">
						{LABELS.map((l) => (
							<Button
								variant="bare"
								key={l.value}
								type="button"
								disabled={busy}
								aria-pressed={current?.label === l.value}
								onClick={() => save(l.value)}
								className="rounded-control border border-line px-2 py-1 text-sm disabled:opacity-50"
							>
								{current?.label === l.value ? "✓ " : ""}
								{l.text}
							</Button>
						))}
					</div>
					<label className="mt-2 block text-sm text-ink-3" htmlFor="flag-note">
						Note (optional)
					</label>
					<textarea
						id="flag-note"
						value={note}
						onChange={(e) => setNote(e.target.value)}
						maxLength={2000}
						rows={2}
						className="mt-1 w-full rounded-control border border-line bg-transparent p-2 text-sm"
					/>
				</div>
			)}
		</div>
	);
}
