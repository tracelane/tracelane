"use client";

/**
 * ProfileManager — display-name edit + danger zone (IDENTITY_TEAM_SPEC §5).
 *
 * Name → PATCH /api/settings/account (WorkOS + mirror). Email is read-only.
 * Danger zone: delete account (type-email confirm) and, for owners, delete the
 * whole organization (type-org-name confirm, 30-day soft-delete). Both are
 * server-gated; the confirms are the launch compensating control for no re-auth.
 */

import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";

async function saveName(name: string): Promise<void> {
	const res = await fetch("/api/settings/account", {
		method: "PATCH",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ name }),
	});
	if (!res.ok) {
		const e = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(e.error ?? `HTTP ${res.status}`);
	}
}

async function deleteAccount(confirmEmail: string): Promise<void> {
	const res = await fetch("/api/settings/account", {
		method: "DELETE",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ confirmEmail }),
	});
	if (!res.ok) {
		const e = (await res.json().catch(() => ({}))) as {
			error?: string;
			detail?: string;
		};
		throw new Error(e.detail ?? e.error ?? `HTTP ${res.status}`);
	}
}

async function deleteOrg(confirmName: string): Promise<void> {
	const res = await fetch("/api/settings/workspace", {
		method: "DELETE",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ confirmName }),
	});
	if (!res.ok) {
		const e = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(e.error ?? `HTTP ${res.status}`);
	}
}

export function ProfileManager({
	initialName,
	email,
	canDeleteOrg,
}: {
	initialName: string;
	email: string;
	canDeleteOrg: boolean;
}) {
	const router = useRouter();
	const [name, setName] = useState(initialName);
	const [confirmEmail, setConfirmEmail] = useState("");
	const [confirmOrg, setConfirmOrg] = useState("");

	const save = useMutation({ mutationFn: saveName });
	const delAccount = useMutation({
		mutationFn: deleteAccount,
		onSuccess: () => router.push("/sign-out"),
	});
	const delOrg = useMutation({
		mutationFn: deleteOrg,
		onSuccess: () => router.push("/organization-deleted"),
	});

	return (
		<div className="space-y-8 max-w-md">
			{/* Profile */}
			<section className="space-y-2">
				<label htmlFor="profile-name" className="block text-xs text-ink-2">
					Display name
				</label>
				<input
					id="profile-name"
					value={name}
					onChange={(e) => setName(e.target.value)}
					placeholder="Your name"
					className="w-full rounded-lg bg-surface-2 border border-line px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
				/>
				<label
					htmlFor="profile-email"
					className="block text-xs text-ink-2 pt-2"
				>
					Email
				</label>
				<input
					id="profile-email"
					value={email}
					readOnly
					className="w-full rounded-lg bg-surface border border-line px-3 py-2 text-sm text-ink-2 font-mono cursor-not-allowed"
				/>
				<div className="flex items-center gap-3 pt-1">
					<button
						type="button"
						disabled={!name.trim() || name === initialName || save.isPending}
						onClick={() => save.mutate(name.trim())}
						className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-accent-on hover:bg-accent/90 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
					>
						{save.isPending ? "Saving…" : "Save"}
					</button>
					{save.isSuccess && <span className="text-xs text-ok">Saved</span>}
					{save.error && (
						<span className="text-xs text-danger">
							{(save.error as Error).message}
						</span>
					)}
				</div>
			</section>

			{/* Danger zone */}
			<section className="space-y-4 rounded-lg border border-danger/40 p-4">
				<h3 className="text-xs font-semibold text-danger">Danger zone</h3>

				<div className="space-y-2">
					<p className="text-xs text-ink-2">
						Delete your account. Type your email{" "}
						<span className="font-mono">{email}</span> to confirm. If you are
						the sole member, this also deletes the organization.
					</p>
					<input
						aria-label="confirm email"
						value={confirmEmail}
						onChange={(e) => setConfirmEmail(e.target.value)}
						placeholder={email}
						className="w-full rounded-lg bg-surface-2 border border-line px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
					/>
					<button
						type="button"
						disabled={
							confirmEmail.trim().toLowerCase() !== email.toLowerCase() ||
							delAccount.isPending
						}
						onClick={() => delAccount.mutate(confirmEmail.trim())}
						className="rounded-lg border border-danger/60 px-3 py-1.5 text-xs font-medium text-danger hover:bg-danger/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
					>
						{delAccount.isPending ? "Deleting…" : "Delete my account"}
					</button>
					{delAccount.error && (
						<p className="text-xs text-danger">
							{(delAccount.error as Error).message}
						</p>
					)}
				</div>

				{canDeleteOrg && (
					<div className="space-y-2 border-t border-line pt-4">
						<p className="text-xs text-ink-2">
							Delete the entire organization (30-day soft-delete, then
							permanent). Revokes all API keys and dashboard access immediately.
							Type the organization name to confirm.
						</p>
						<input
							aria-label="confirm org name"
							value={confirmOrg}
							onChange={(e) => setConfirmOrg(e.target.value)}
							placeholder="organization name"
							className="w-full rounded-lg bg-surface-2 border border-line px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
						/>
						<button
							type="button"
							disabled={!confirmOrg.trim() || delOrg.isPending}
							onClick={() => delOrg.mutate(confirmOrg.trim())}
							className="rounded-lg border border-danger/60 px-3 py-1.5 text-xs font-medium text-danger hover:bg-danger/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
						>
							{delOrg.isPending ? "Deleting…" : "Delete organization"}
						</button>
						{delOrg.error && (
							<p className="text-xs text-danger">
								{(delOrg.error as Error).message}
							</p>
						)}
					</div>
				)}
			</section>
		</div>
	);
}
