"use client";

/**
 * WorkspaceManager — in-app org rename + WorkOS Admin Portal launchers.
 *
 * Replaces the old dead `dashboard.workos.com` link (that was OUR project
 * console — customers can't sign in there). Rename hits PATCH
 * /api/settings/workspace (WorkOS + Postgres mirror); the portal buttons mint a
 * single-use WorkOS Admin Portal link per click and open it. Org id always
 * derives from the session server-side, never the UI.
 */

import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

async function renameOrg(name: string): Promise<{ name: string }> {
	const res = await fetch("/api/settings/workspace", {
		method: "PATCH",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ name }),
	});
	if (!res.ok) {
		const e = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(e.error ?? `HTTP ${res.status}`);
	}
	return res.json() as Promise<{ name: string }>;
}

async function openPortal(intent: string): Promise<void> {
	const res = await fetch("/api/settings/workspace/portal", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ intent }),
	});
	if (!res.ok) {
		const e = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(e.error ?? `HTTP ${res.status}`);
	}
	const { link } = (await res.json()) as { link: string };
	// Defense in depth: only ever open an https link, so a compromised/spoofed
	// generate_link response can't hand us a `javascript:` URL to open.
	if (!link?.startsWith("https://")) throw new Error("invalid portal link");
	window.open(link, "_blank", "noopener,noreferrer");
}

// Order matters: SSO can't activate without a verified domain (WorkOS
// precondition), so "Verify domains" leads. `audit_logs` opens WorkOS's own
// audit-log streaming setup (distinct from Tracelane's audit ledger).
const PORTAL_ACTIONS = [
	{ intent: "domain_verification", label: "Verify domains" },
	{ intent: "sso", label: "Configure SSO" },
	{ intent: "dsync", label: "Directory sync (SCIM)" },
	{ intent: "audit_logs", label: "Audit log streaming" },
] as const;

export function WorkspaceManager({ initialName }: { initialName: string }) {
	const [name, setName] = useState(initialName);
	const [saved, setSaved] = useState(false);

	const rename = useMutation({
		mutationFn: renameOrg,
		onSuccess: () => {
			setSaved(true);
			setTimeout(() => setSaved(false), 2500);
		},
	});
	const portal = useMutation({ mutationFn: openPortal });

	const trimmed = name.trim();
	const dirty = trimmed.length > 0 && trimmed !== initialName;

	return (
		<div className="space-y-6">
			{/* Rename */}
			<div className="space-y-2">
				<label
					htmlFor="org-name"
					className="block text-xs font-medium text-ink"
				>
					Organization name
				</label>
				<div className="flex items-center gap-2">
					<input
						id="org-name"
						type="text"
						value={name}
						maxLength={255}
						onChange={(e) => setName(e.target.value)}
						className="w-full max-w-sm rounded-lg border border-line bg-surface-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent-ink"
						placeholder="Acme, Inc."
					/>
					<button
						type="button"
						disabled={!dirty || rename.isPending}
						onClick={() => rename.mutate(trimmed)}
						className="rounded-lg bg-accent px-3 py-2 text-sm font-medium text-accent-on transition-colors hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-40"
					>
						{rename.isPending ? "Saving…" : "Save"}
					</button>
					{saved && <span className="text-xs text-ok">Saved</span>}
				</div>
				{rename.error && (
					<p className="text-xs text-danger">
						{(rename.error as Error).message}
					</p>
				)}
			</div>

			{/* Admin Portal launchers */}
			<div className="space-y-2">
				<p className="text-xs font-medium text-ink">
					SSO, domains &amp; directory
				</p>
				<p className="text-xs text-ink-2">
					Manage single sign-on, verified domains, and SCIM directory sync in
					the secure WorkOS admin portal.
				</p>
				<div className="flex flex-wrap gap-2 pt-1">
					{PORTAL_ACTIONS.map((a) => (
						<button
							key={a.intent}
							type="button"
							disabled={portal.isPending}
							onClick={() => portal.mutate(a.intent)}
							className="rounded-lg border border-line px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:bg-surface-2 disabled:opacity-40"
						>
							{portal.isPending && portal.variables === a.intent
								? "Opening…"
								: `${a.label} →`}
						</button>
					))}
				</div>
				{portal.error && (
					<p className="text-xs text-danger">
						{(portal.error as Error).message}
					</p>
				)}
			</div>
		</div>
	);
}
