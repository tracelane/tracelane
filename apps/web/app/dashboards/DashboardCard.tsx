"use client";

/**
 * DashboardCard — a single dashboard in the list, with rename + delete
 * actions. Client component: owns the confirmation state for deletion and
 * the inline-edit state for rename.
 *
 * Rename PATCHes `/api/dashboards/[id]` with `{ name }` — the ONLY field
 * that route accepts (`apps/web/app/api/dashboards/[id]/route.ts`, `PatchBody`);
 * it is not exposing anything the route does not already validate (non-empty,
 * trimmed, ≤60 chars — `MAX_TITLE_LEN` in that same file). Optimistic: the
 * card shows the new name immediately, reverts to the last-saved name and
 * surfaces the server's own error message on failure, matching the pattern
 * `TileFrame`'s resize controls already use on the tile-detail page.
 *
 * 2026-09-07: this component's own comment used to claim "rename + delete
 * actions" while only delete had ever shipped — a write API
 * (`PATCH /api/dashboards/[id]`) with no UI caller. This is the fix.
 */

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";

interface Props {
	dashboard: {
		id: string;
		name: string;
		createdBy: string;
		tileCount: number;
		updatedAt: Date | string;
	};
	canEdit: boolean;
}

const MAX_NAME_LEN = 60;

function relativeDate(d: Date | string): string {
	const ms = new Date(d).getTime();
	const diff = Date.now() - ms;
	if (diff < 60_000) return "just now";
	if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
	if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
	return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function DashboardCard({ dashboard: d, canEdit }: Props) {
	const router = useRouter();
	const [deleting, setDeleting] = useState(false);
	const [confirmDelete, setConfirmDelete] = useState(false);

	const [renaming, setRenaming] = useState(false);
	const [saving, setSaving] = useState(false);
	const [name, setName] = useState(d.name);
	const [nameError, setNameError] = useState<string | null>(null);
	const lastSaved = useRef(d.name);

	async function handleDelete() {
		if (!confirmDelete) {
			setConfirmDelete(true);
			return;
		}
		setDeleting(true);
		try {
			await fetch(`/api/dashboards/${d.id}`, { method: "DELETE" });
			router.refresh();
		} finally {
			setDeleting(false);
			setConfirmDelete(false);
		}
	}

	function startRename() {
		setName(lastSaved.current);
		setNameError(null);
		setRenaming(true);
	}

	function cancelRename() {
		setName(lastSaved.current);
		setNameError(null);
		setRenaming(false);
	}

	async function saveRename() {
		const trimmed = name.trim();
		if (trimmed.length === 0) {
			setNameError("Name can't be empty");
			return;
		}
		if (trimmed === lastSaved.current) {
			setRenaming(false);
			return; // no-op — nothing changed
		}
		setSaving(true);
		setNameError(null);
		try {
			const res = await fetch(`/api/dashboards/${d.id}`, {
				method: "PATCH",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ name: trimmed }),
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => ({}))) as {
					error?: string;
				};
				setName(lastSaved.current);
				setNameError(body.error ?? "Couldn't rename — try again");
				return;
			}
			lastSaved.current = trimmed;
			setName(trimmed);
			setRenaming(false);
			router.refresh();
		} catch {
			setName(lastSaved.current);
			setNameError("Network error — try again");
		} finally {
			setSaving(false);
		}
	}

	return (
		<div className="stat-tile group relative flex flex-col gap-3 p-4 transition-shadow hover:shadow-md">
			<div className="flex items-start justify-between gap-2">
				{renaming ? (
					<div className="min-w-0 flex-1">
						<input
							// biome-ignore lint/a11y/noAutofocus: opened by an explicit click on the rename button — the input IS the action just taken.
							autoFocus
							value={name}
							onChange={(e) => setName(e.target.value)}
							onKeyDown={(e) => {
								if (e.key === "Enter") saveRename();
								if (e.key === "Escape") cancelRename();
							}}
							disabled={saving}
							maxLength={MAX_NAME_LEN}
							aria-label={`Rename dashboard "${lastSaved.current}"`}
							className="w-full rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1 text-sm font-medium text-ink focus:border-action focus: disabled:opacity-60"
						/>
						{nameError && (
							<p className="mt-1 text-2xs text-danger-ink">{nameError}</p>
						)}
						<div className="mt-1 flex gap-2">
							<button
								type="button"
								onClick={saveRename}
								disabled={saving}
								className="text-2xs font-medium text-action hover:underline disabled:cursor-not-allowed disabled:opacity-50"
							>
								{saving ? "Saving…" : "Save"}
							</button>
							<button
								type="button"
								onClick={cancelRename}
								disabled={saving}
								className="text-2xs text-ink-3 hover:text-ink-2 disabled:cursor-not-allowed disabled:opacity-50"
							>
								Cancel
							</button>
						</div>
					</div>
				) : (
					<Link
						href={`/dashboards/${d.id}`}
						className="min-w-0 flex-1 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
					>
						<p className="truncate font-medium text-ink">{name}</p>
					</Link>
				)}
				{canEdit && !renaming && (
					<div className="flex shrink-0 items-center gap-1">
						<button
							type="button"
							onClick={startRename}
							className="rounded text-xs text-ink-3 opacity-0 transition-colors hover:text-ink-2 focus-visible:opacity-100 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring group-hover:opacity-100"
							aria-label={`Rename dashboard ${name}`}
						>
							Rename
						</button>
						<button
							type="button"
							onClick={handleDelete}
							disabled={deleting}
							className={`rounded text-xs transition-colors focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring ${
								confirmDelete
									? "text-danger hover:text-danger-ink"
									: "text-ink-3 opacity-0 group-hover:opacity-100 hover:text-ink-2"
							}`}
							aria-label={`Delete dashboard ${name}`}
						>
							{deleting ? "…" : confirmDelete ? "Confirm" : "Delete"}
						</button>
					</div>
				)}
			</div>
			<div className="mt-auto flex items-center justify-between text-xs text-ink-3">
				<span>
					{d.tileCount === 0
						? "No tiles"
						: `${d.tileCount} tile${d.tileCount === 1 ? "" : "s"}`}
				</span>
				<span>Updated {relativeDate(d.updatedAt)}</span>
			</div>
		</div>
	);
}
