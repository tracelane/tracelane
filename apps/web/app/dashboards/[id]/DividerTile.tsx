"use client";

/**
 * DividerTile — a full-width (12-column) section header: an optional label,
 * a hairline rule, nothing else. Spec §9 (2026-09-07, founder request: "add
 * divider on page so that when some metrics or tiles are added, they are
 * aligned and of right shape and size").
 *
 * It has no metric, no data fetch, no width/height picker (`TileFrame` pins
 * it to width=12/height="compact") and never shows a chart skeleton — a
 * loading state for a value that is never fetched would be a decoration, not
 * a state (spec §9.5). Move/remove live one level up in `TileFrame`'s shared
 * overlay; this component owns only the inline rename.
 *
 * Rename is a PATCH `{ title }` — the only field a divider tile may change
 * besides `position`. A failed PATCH reverts the label and shows the same
 * inline-toast pattern `TileFrame` uses for a failed resize, so a keystroke
 * is never silently lost.
 */

import { useRef, useState } from "react";

interface Props {
	dashboardId: string;
	tileId: string;
	label: string;
	canEdit: boolean;
}

const MAX_LABEL_LEN = 60;

export function DividerTile({ dashboardId, tileId, label, canEdit }: Props) {
	const [editing, setEditing] = useState(false);
	const [value, setValue] = useState(label);
	const [saving, setSaving] = useState(false);
	const [toast, setToast] = useState<string | null>(null);
	const toastTimer = useRef<ReturnType<typeof setTimeout> | undefined>(
		undefined,
	);
	const lastSaved = useRef(label);

	function flash(message: string) {
		setToast(message);
		clearTimeout(toastTimer.current);
		toastTimer.current = setTimeout(() => setToast(null), 4000);
	}

	async function save() {
		setEditing(false);
		const next = value.trim();
		if (next === lastSaved.current) return; // no-op — nothing to persist
		setSaving(true);
		try {
			const res = await fetch(
				`/api/dashboards/${dashboardId}/tiles/${tileId}`,
				{
					method: "PATCH",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ title: next }),
				},
			);
			if (!res.ok) throw new Error("patch failed");
			lastSaved.current = next;
			setValue(next);
		} catch {
			setValue(lastSaved.current);
			flash("Couldn't rename — reverted");
		} finally {
			setSaving(false);
		}
	}

	return (
		// No `role="separator"` wrapper: the `<hr>` below already carries the
		// browser's own implicit separator semantics, so an extra ARIA role on
		// a non-focusable `<div>` would add nothing a screen reader doesn't
		// already get from the `<hr>` itself.
		<div className="group/divider flex items-center gap-3 py-1">
			{editing ? (
				<input
					// biome-ignore lint/a11y/noAutofocus: opened by an explicit click/Enter on the rename button — the input IS the action just taken.
					autoFocus
					value={value}
					onChange={(e) => setValue(e.target.value)}
					onBlur={save}
					onKeyDown={(e) => {
						if (e.key === "Enter") e.currentTarget.blur();
						if (e.key === "Escape") {
							setValue(lastSaved.current);
							setEditing(false);
						}
					}}
					maxLength={MAX_LABEL_LEN}
					aria-label="Section label"
					placeholder="Section label"
					className="w-48 shrink-0 rounded-[var(--radius-control)] border border-line bg-surface px-2 py-0.5 text-xs font-medium uppercase tracking-wide text-ink-2 focus:border-action focus:"
				/>
			) : canEdit ? (
				<button
					type="button"
					onClick={() => setEditing(true)}
					disabled={saving}
					aria-label={
						value ? `Rename section "${value}"` : "Add a section label"
					}
					className="shrink-0 whitespace-nowrap rounded px-1 text-xs font-medium uppercase tracking-wide text-ink-2 transition-colors hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring disabled:cursor-not-allowed disabled:opacity-50"
				>
					{value || (
						<span className="italic normal-case text-ink-3 opacity-0 transition-opacity group-hover/divider:opacity-100 group-focus-within/divider:opacity-100">
							+ Add label
						</span>
					)}
				</button>
			) : value ? (
				<span className="shrink-0 whitespace-nowrap text-xs font-medium uppercase tracking-wide text-ink-2">
					{value}
				</span>
			) : null}
			<hr className="h-px min-w-8 flex-1 border-0 bg-line" />
			{toast && (
				<output className="shrink-0 rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1 text-2xs text-danger-ink shadow-[var(--shadow-overlay)]">
					{toast}
				</output>
			)}
		</div>
	);
}
