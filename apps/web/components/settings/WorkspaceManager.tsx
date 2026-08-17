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

/**
 * SET-04. Writes `tenants.slack_webhook_url` — the destination the gateway
 * POSTs to when a tenant crosses its quota. Before this existed the column had
 * a reader and no writer, so the alert could never fire for anyone.
 */
async function saveNotifyWebhook(url: string): Promise<{ url: string | null }> {
	const res = await fetch("/api/settings/notify-webhook", {
		method: url ? "PUT" : "DELETE",
		headers: { "Content-Type": "application/json" },
		...(url ? { body: JSON.stringify({ url }) } : {}),
	});
	if (!res.ok) {
		const e = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(e.error ?? `HTTP ${res.status}`);
	}
	return res.json() as Promise<{ url: string | null }>;
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

export function WorkspaceManager({
	initialName,
	initialNotifyWebhook,
}: {
	initialName: string;
	initialNotifyWebhook: string;
}) {
	const [name, setName] = useState(initialName);
	const [saved, setSaved] = useState(false);
	const [hook, setHook] = useState(initialNotifyWebhook);
	const [hookSaved, setHookSaved] = useState(false);

	const rename = useMutation({
		mutationFn: renameOrg,
		onSuccess: () => {
			setSaved(true);
			setTimeout(() => setSaved(false), 2500);
		},
	});
	const saveHook = useMutation({
		mutationFn: saveNotifyWebhook,
		onSuccess: () => {
			setHookSaved(true);
			setTimeout(() => setHookSaved(false), 2500);
		},
	});
	const portal = useMutation({ mutationFn: openPortal });

	const trimmed = name.trim();
	const dirty = trimmed.length > 0 && trimmed !== initialName;
	const hookTrimmed = hook.trim();
	const hookDirty = hookTrimmed !== initialNotifyWebhook;

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
						className="w-full max-w-sm rounded-sm border border-line bg-surface-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-action-ink"
						placeholder="Acme, Inc."
					/>
					<button
						type="button"
						disabled={!dirty || rename.isPending}
						onClick={() => rename.mutate(trimmed)}
						className="rounded-lg bg-action px-3 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90 disabled:cursor-not-allowed disabled:opacity-40"
					>
						{rename.isPending ? "Saving…" : "Save"}
					</button>
					{saved && <span className="text-xs text-ok-ink">Saved</span>}
				</div>
				{rename.error && (
					<p className="text-xs text-danger-ink">
						{(rename.error as Error).message}
					</p>
				)}
			</div>

			{/* Quota alert webhook (SET-04) */}
			<div className="space-y-2">
				<label
					htmlFor="notify-webhook"
					className="block text-xs font-medium text-ink"
				>
					Quota alert webhook
				</label>
				<p className="text-xs text-ink-2">
					HTTPS endpoint the gateway POSTs to when this workspace crosses its
					monthly trace quota. Works with a Slack or Discord incoming webhook,
					or any receiver you control. Leave empty to disable.
				</p>
				<div className="flex items-center gap-2">
					<input
						id="notify-webhook"
						type="url"
						value={hook}
						maxLength={2048}
						onChange={(e) => setHook(e.target.value)}
						className="w-full max-w-sm rounded-sm border border-line bg-surface-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-action-ink"
						placeholder="https://hooks.slack.com/services/…"
					/>
					<button
						type="button"
						disabled={!hookDirty || saveHook.isPending}
						onClick={() => saveHook.mutate(hookTrimmed)}
						className="rounded-lg bg-action px-3 py-2 text-sm font-medium text-action-on transition-colors hover:bg-action/90 disabled:cursor-not-allowed disabled:opacity-40"
					>
						{saveHook.isPending ? "Saving…" : "Save"}
					</button>
					{hookSaved && <span className="text-xs text-ok-ink">Saved</span>}
				</div>
				{saveHook.error && (
					<p className="text-xs text-danger-ink">
						{(saveHook.error as Error).message}
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
					<p className="text-xs text-danger-ink">
						{(portal.error as Error).message}
					</p>
				)}
			</div>
		</div>
	);
}
