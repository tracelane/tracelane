"use client";

/**
 * CeilingSheet — the monthly spend ceiling dialog (spec §8 `#ceiling`).
 *
 * OFF by default; AUTO-AGE is the default overflow mode (spec §0.4). Copy is
 * verbatim from the wireframe: "Ingest never stops. Auto-age moves the
 * oldest days to cold early; nothing is lost."
 *
 * Disabled for non-admins (spec §4 "Permission-denied": a member can VIEW
 * usage; the ceiling control is disabled with "workspace admins can change
 * this"). The server-side gate is `PUT /api/billing/ceiling`'s own
 * `canAdmin` check — this is UI-only, matching every other admin-gated
 * control in this app.
 *
 * Built on the shared `<Modal>` (native `<dialog>` + `showModal()`) rather
 * than a hand-rolled `role="dialog"` div — the same accessibility argument
 * `Modal.tsx` makes for every other dialog in the app: focus trap, Escape,
 * and a real modal boundary from the platform, not asserted and left unmet.
 */

import { Modal } from "@/components/Modal";
import { useState } from "react";

export function CeilingSheet({
	initialUsd,
	initialMode,
	canManage,
	onClose,
	onSaved,
}: {
	initialUsd: number | null;
	initialMode: "auto_age" | "auto_overage";
	canManage: boolean;
	onClose: () => void;
	onSaved: (usd: number | null, mode: "auto_age" | "auto_overage") => void;
}) {
	const [enabled, setEnabled] = useState(initialUsd !== null);
	const [amount, setAmount] = useState(initialUsd ?? 500);
	const [mode, setMode] = useState(initialMode);
	const [saving, setSaving] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const save = async () => {
		setSaving(true);
		setError(null);
		const usd = enabled ? amount : null;
		try {
			const res = await fetch("/api/billing/ceiling", {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ usd, overflow_mode: mode }),
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => ({}))) as { error?: string };
				setError(body.error ?? "Could not save the ceiling.");
				return;
			}
			onSaved(usd, mode);
		} catch {
			setError("Network error — try again.");
		} finally {
			setSaving(false);
		}
	};

	return (
		<Modal title="Monthly spend ceiling" onClose={onClose}>
			<div
				aria-disabled={!canManage || undefined}
				className={canManage ? undefined : "pointer-events-none opacity-55"}
			>
				<div className="mb-4 flex items-center justify-between">
					<span className="text-xs text-ink-2">Spend ceiling</span>
					<button
						type="button"
						role="switch"
						aria-checked={enabled}
						disabled={!canManage}
						onClick={() => setEnabled((v) => !v)}
						className={`relative h-6 w-10 flex-shrink-0 rounded-full border transition-colors ${
							enabled
								? "border-action-line bg-action-soft"
								: "border-line bg-surface-2"
						}`}
					>
						<span
							className={`absolute top-0.5 h-[1.15rem] w-[1.15rem] rounded-full shadow-[var(--shadow-card)] transition-[left] ${
								enabled
									? "left-[calc(100%-1.25rem)] bg-action"
									: "left-0.5 bg-surface"
							}`}
						/>
					</button>
				</div>

				<label
					htmlFor="ceiling-amount"
					className="mb-1 block text-xs text-ink-2"
				>
					Amount (USD / month)
				</label>
				<input
					id="ceiling-amount"
					type="number"
					min={0}
					disabled={!canManage || !enabled}
					value={amount}
					onChange={(e) => setAmount(Number(e.target.value))}
					className="mb-4 w-32 rounded-[var(--radius-control)] border border-line bg-surface px-2.5 py-1.5 font-mono text-sm tabular-nums text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring disabled:opacity-50"
				/>

				<p className="mb-2 text-xs text-ink-2">At the ceiling:</p>
				<div className="mb-4 flex flex-col gap-1.5">
					<label className="flex items-center gap-2 text-xs text-ink">
						<input
							type="radio"
							name="overflow-mode"
							disabled={!canManage}
							checked={mode === "auto_age"}
							onChange={() => setMode("auto_age")}
						/>
						Auto-age
					</label>
					<label className="flex items-center gap-2 text-xs text-ink-2">
						<input
							type="radio"
							name="overflow-mode"
							disabled={!canManage}
							checked={mode === "auto_overage"}
							onChange={() => setMode("auto_overage")}
						/>
						Auto-overage
					</label>
				</div>
				<p className="mb-4 text-xs text-ink-2">
					Ingest never stops. Auto-age moves the oldest days to cold early;
					nothing is lost.
				</p>

				{!canManage && (
					<p className="mb-3 text-xs text-ink-3">
						workspace admins can change this
					</p>
				)}
				{error && <p className="mb-3 text-xs text-danger-ink">{error}</p>}

				<div className="flex gap-2">
					<button
						type="button"
						disabled={!canManage || saving}
						onClick={save}
						className="flex-1 rounded-[var(--radius-control)] bg-action px-3 py-1.5 text-xs font-medium text-action-on transition-colors hover:bg-action/90 disabled:opacity-50"
					>
						{saving ? "Saving…" : "Save"}
					</button>
					<button
						type="button"
						onClick={onClose}
						className="flex-1 rounded-[var(--radius-control)] border border-line bg-surface px-3 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink"
					>
						Cancel
					</button>
				</div>
			</div>
		</Modal>
	);
}
