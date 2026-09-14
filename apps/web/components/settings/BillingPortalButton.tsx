"use client";

/**
 * BillingPortalButton — calls POST /api/billing/portal and redirects to the
 * Polar-hosted billing portal. Handles loading + error state inline.
 *
 * The proxy answers with a `reason` code rather than the upstream body (the
 * body can echo provider error JSON), so the copy here is decided by the
 * code, not by whatever text came back. Founder, 2026-09-14: "Manage billing
 * throws error 'billing portal unavailable'" — every failure used to render
 * that one sentence, including the two that are not failures of the portal
 * at all (no billing account yet; not the workspace owner).
 */

import { useState } from "react";

type PortalFailure = {
	error?: string;
	reason?: "no_billing_account" | "owner_required" | "not_configured" | string;
};

function messageFor(status: number, body: PortalFailure): string {
	switch (body.reason) {
		case "no_billing_account":
			return "No billing account yet — one is created with your first paid plan. Invoices appear here after that.";
		case "owner_required":
			return "Only a workspace owner can open the billing portal. Ask an owner, or change your role under Team.";
		case "not_configured":
			return "Billing is not configured for this deployment.";
		default:
			break;
	}
	if (status === 401) return "Your session has expired — sign in again.";
	return "The billing portal did not respond. Try again in a minute; if it keeps failing, email support@tracelane.dev.";
}

export function BillingPortalButton() {
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const open = async () => {
		setLoading(true);
		setError(null);
		try {
			const res = await fetch("/api/billing/portal", { method: "POST" });
			if (!res.ok) {
				const body = (await res.json().catch(() => ({}))) as PortalFailure;
				setError(messageFor(res.status, body));
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
				className="px-3 py-1.5 rounded text-sm bg-action text-action-on hover:bg-action/90 disabled:opacity-50 transition-colors"
			>
				{loading ? "Opening…" : "Manage billing"}
			</button>
			{error && (
				<p className="max-w-xs text-right text-xs text-danger-ink">{error}</p>
			)}
		</div>
	);
}
