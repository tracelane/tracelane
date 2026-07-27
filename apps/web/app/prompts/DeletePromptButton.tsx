"use client";

/**
 *
 * Confirms, then calls DELETE /api/prompts/[name] (the per-user-JWT proxy) and
 * refreshes the RSC list so the archived prompt drops out. Builder-allowed —
 * the inverse of authoring; the gateway archives it + stops serving it.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

export function DeletePromptButton({ name }: { name: string }) {
	const router = useRouter();
	const [busy, setBusy] = useState(false);
	const [err, setErr] = useState<string | null>(null);

	async function onDelete() {
		// ponytail: native confirm is a real, accessible, blocking guard — swap for
		// a styled dialog later if the design calls for it.
		if (
			!window.confirm(
				`Delete prompt "${name}"? It is removed from the dashboard and the gateway stops serving it. This can't be undone from the UI.`,
			)
		) {
			return;
		}
		setBusy(true);
		setErr(null);
		try {
			const res = await fetch(`/api/prompts/${encodeURIComponent(name)}`, {
				method: "DELETE",
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => ({}))) as { error?: string };
				throw new Error(body.error ?? `delete failed (${res.status})`);
			}
			router.refresh();
		} catch (e) {
			setErr(e instanceof Error ? e.message : "delete failed");
			setBusy(false);
		}
	}

	return (
		<button
			type="button"
			onClick={onDelete}
			disabled={busy}
			aria-label={`Delete prompt ${name}`}
			title={err ?? "Delete prompt"}
			className="rounded-md border border-line px-2 py-1 text-xs font-medium text-ink-3 transition-colors hover:border-danger hover:text-danger disabled:cursor-not-allowed disabled:opacity-40"
		>
			{busy ? "Deleting…" : "Delete"}
		</button>
	);
}
