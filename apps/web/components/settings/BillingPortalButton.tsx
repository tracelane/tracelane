"use client";

/**
 * BillingPortalButton — calls POST /api/billing/portal and redirects to the
 * Polar-hosted billing portal. Handles loading + error state inline.
 */

import { useState } from "react";

export function BillingPortalButton() {
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const open = async () => {
		setLoading(true);
		setError(null);
		try {
			const res = await fetch("/api/billing/portal", { method: "POST" });
			if (!res.ok) {
				const body = (await res.json().catch(() => ({}))) as { error?: string };
				setError(body.error ?? "Failed to open billing portal.");
				return;
			}
			const { url } = (await res.json()) as { url: string };
			window.location.href = url;
		} catch {
			setError("Network error — try again.");
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="flex flex-col items-end gap-1">
			<button
				type="button"
				onClick={open}
				disabled={loading}
				className="px-3 py-1.5 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 disabled:opacity-50 transition-colors"
			>
				{loading ? "Opening…" : "Manage billing"}
			</button>
			{error && <p className="text-xs text-danger">{error}</p>}
		</div>
	);
}
