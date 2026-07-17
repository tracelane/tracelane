"use client";

/**
 * TeamManager — org members + pending invitations (IDENTITY_TEAM_SPEC §1–§3).
 *
 * Reads:  GET /api/settings/team              (memberships)
 *         GET /api/settings/team/invitations  (pending invites)
 * Writes (owner-only, `canManage`): invite (role picker), resend/revoke invite,
 *         change role, remove member. The UI hides these for non-owners; the
 *         gateway + WorkOS-management routes are the authoritative gates.
 * Tenant-scoped: tenantId always comes from the session, never the UI.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Skeleton } from "@tracelanedev/ui";
import { useState } from "react";

type Role = "owner" | "member" | "viewer";

interface MemberRow {
	id: string;
	userId: string;
	email: string;
	name: string;
	role: string;
	joinedAt: string;
}

interface PendingRow {
	id: string;
	email: string;
	role: string;
	invitedAt: string;
}

async function fetchMembers(): Promise<MemberRow[]> {
	const res = await fetch("/api/settings/team");
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
	return res.json() as Promise<MemberRow[]>;
}

async function fetchPending(): Promise<PendingRow[]> {
	const res = await fetch("/api/settings/team/invitations");
	if (!res.ok) throw new Error(`HTTP ${res.status}`);
	return res.json() as Promise<PendingRow[]>;
}

async function jsonError(res: Response): Promise<string> {
	const err = (await res.json().catch(() => ({}))) as { error?: string };
	return err.error ?? `HTTP ${res.status}`;
}

async function sendInvite(input: { email: string; role: Role }): Promise<void> {
	const res = await fetch("/api/settings/team/invite", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(input),
	});
	if (!res.ok) throw new Error(await jsonError(res));
}

async function removeMember(membershipId: string): Promise<void> {
	const res = await fetch(
		`/api/settings/team/${encodeURIComponent(membershipId)}`,
		{
			method: "DELETE",
		},
	);
	if (!res.ok) throw new Error(await jsonError(res));
}

async function changeRole(input: {
	membershipId: string;
	role: Role;
}): Promise<void> {
	const res = await fetch(
		`/api/settings/team/${encodeURIComponent(input.membershipId)}`,
		{
			method: "PATCH",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ role: input.role }),
		},
	);
	if (!res.ok) throw new Error(await jsonError(res));
}

async function revokeInvite(id: string): Promise<void> {
	const res = await fetch(
		`/api/settings/team/invitations/${encodeURIComponent(id)}`,
		{
			method: "DELETE",
		},
	);
	if (!res.ok) throw new Error(await jsonError(res));
}

async function resendInvite(id: string): Promise<void> {
	const res = await fetch(
		`/api/settings/team/invitations/${encodeURIComponent(id)}/resend`,
		{ method: "POST" },
	);
	if (!res.ok) throw new Error(await jsonError(res));
}

function RoleBadge({ role }: { role: string }) {
	const privileged = role === "admin" || role === "owner";
	return (
		<Badge
			tone="neutral"
			className={privileged ? "bg-surface-3 text-ink" : undefined}
		>
			{role}
		</Badge>
	);
}

function InviteModal({
	onClose,
	onInvited,
}: {
	onClose: () => void;
	onInvited: () => void;
}) {
	const [email, setEmail] = useState("");
	const [role, setRole] = useState<Role>("member");
	const [sent, setSent] = useState(false);

	const mutation = useMutation({
		mutationFn: sendInvite,
		onSuccess: () => {
			setSent(true);
			onInvited();
		},
	});

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
			<div className="bg-surface border border-line rounded-xl p-6 w-full max-w-md shadow-2xl">
				{sent ? (
					<>
						<h3 className="text-sm font-semibold text-ink mb-2">
							Invitation sent
						</h3>
						<p className="text-xs text-ink-2 mb-4">
							An invitation email has been dispatched to{" "}
							<span className="font-mono text-ink">{email}</span>.
						</p>
						<button
							type="button"
							onClick={onClose}
							className="w-full rounded-lg bg-surface-2 py-2 text-sm text-ink hover:bg-surface-3 transition-colors"
						>
							Done
						</button>
					</>
				) : (
					<>
						<h3 className="text-sm font-semibold text-ink mb-4">
							Invite team member
						</h3>
						<label
							htmlFor="team-invite-email"
							className="block text-xs text-ink-2 mb-1"
						>
							Email address
						</label>
						<input
							id="team-invite-email"
							type="email"
							value={email}
							onChange={(e) => setEmail(e.target.value)}
							placeholder="colleague@company.com"
							className="w-full rounded-lg bg-surface-2 border border-line px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal mb-4"
						/>
						<label
							htmlFor="team-invite-role"
							className="block text-xs text-ink-2 mb-1"
						>
							Role
						</label>
						<select
							id="team-invite-role"
							value={role}
							onChange={(e) => setRole(e.target.value as Role)}
							className="w-full rounded-lg bg-surface-2 border border-line px-3 py-2 text-sm text-ink focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal mb-1"
						>
							<option value="member">Member — full product access</option>
							<option value="viewer">Viewer — read-only</option>
						</select>
						<p className="text-xs text-ink-3 mb-4">
							Owners are promoted after they join, from their member row.
						</p>
						{mutation.error && (
							<p className="text-xs text-danger mb-3">
								{(mutation.error as Error).message}
							</p>
						)}
						<div className="flex gap-2">
							<button
								type="button"
								onClick={onClose}
								className="flex-1 rounded-lg border border-line py-2 text-sm text-ink-2 hover:bg-surface-2 transition-colors"
							>
								Cancel
							</button>
							<button
								type="button"
								disabled={!email.includes("@") || mutation.isPending}
								onClick={() =>
									mutation.mutate({ email: email.trim().toLowerCase(), role })
								}
								className="flex-1 rounded-lg bg-accent py-2 text-sm font-medium text-accent-on hover:bg-accent/90 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
							>
								{mutation.isPending ? "Sending…" : "Send invite"}
							</button>
						</div>
					</>
				)}
			</div>
		</div>
	);
}

export function TeamManager({
	membersMax,
	currentUserId,
	canManage,
}: {
	membersMax: number;
	currentUserId: string;
	/** Owner-only controls (invite / remove / role-change / resend / revoke). */
	canManage: boolean;
}) {
	const queryClient = useQueryClient();
	const [showInvite, setShowInvite] = useState(false);
	// Transient success banner (matches the WorkspaceManager saved-state pattern).
	const [notice, setNotice] = useState<string | null>(null);
	const flash = (msg: string) => {
		setNotice(msg);
		setTimeout(() => setNotice(null), 4000);
	};

	const invalidate = () => {
		void queryClient.invalidateQueries({ queryKey: ["team-members"] });
		void queryClient.invalidateQueries({ queryKey: ["team-invitations"] });
	};

	const {
		data: members,
		isLoading,
		error,
	} = useQuery({
		queryKey: ["team-members"],
		queryFn: fetchMembers,
	});
	// Pending invites count toward the seat cap, so fetch them for both the count
	// and the pending list. Owners manage them; everyone sees the count.
	const { data: pending } = useQuery({
		queryKey: ["team-invitations"],
		queryFn: fetchPending,
	});

	const remove = useMutation({
		mutationFn: removeMember,
		onSettled: invalidate,
	});
	const role = useMutation({
		mutationFn: changeRole,
		onSuccess: (_data, vars) => {
			const m = members?.find((x) => x.id === vars.membershipId);
			flash(
				`Role updated to "${vars.role}"${m ? ` for ${m.email}` : ""} — applies on their next sign-in.`,
			);
		},
		onSettled: invalidate,
	});
	const revoke = useMutation({
		mutationFn: revokeInvite,
		onSettled: invalidate,
	});
	const resend = useMutation({
		mutationFn: resendInvite,
		onSettled: invalidate,
	});

	const seatsUsed = (members?.length ?? 0) + (pending?.length ?? 0);
	const atLimit = membersMax > 0 && seatsUsed >= membersMax;

	return (
		<div className="space-y-4">
			{notice && (
				<output className="block rounded-lg border border-ok/30 bg-ok-soft px-3 py-2 text-xs text-ok">
					✓ {notice}
				</output>
			)}
			<div className="flex items-center justify-between">
				<p className="text-xs text-ink-2">
					{membersMax < 0
						? `${seatsUsed} members · unlimited`
						: `${seatsUsed} / ${membersMax} seats used`}
				</p>
				{canManage &&
					(atLimit ? (
						<span className="text-xs text-warn">
							Seat limit reached — upgrade to add more
						</span>
					) : (
						<button
							type="button"
							onClick={() => setShowInvite(true)}
							className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-accent-on hover:bg-accent/90 transition-colors"
						>
							+ Invite member
						</button>
					))}
			</div>

			{isLoading && <Skeleton className="h-10 w-full" />}
			{error && (
				<p className="text-xs text-danger">
					Failed to load team members.{" "}
					{error instanceof Error && error.message.includes("503")
						? "WorkOS API not configured."
						: ""}
				</p>
			)}

			{members && members.length > 0 && (
				<div className="rounded-lg border border-line overflow-hidden">
					<table className="w-full text-sm">
						<thead className="bg-surface/60">
							<tr>
								<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Member
								</th>
								<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Role
								</th>
								<th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Joined
								</th>
								<th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									<span className="sr-only">Actions</span>
								</th>
							</tr>
						</thead>
						<tbody className="divide-y divide-line">
							{members.map((m) => {
								const isSelf = m.userId === currentUserId;
								return (
									<tr
										key={m.id}
										className="hover:bg-surface-2/40 transition-colors"
									>
										<td className="px-4 py-3">
											<p className="text-xs font-medium text-ink">{m.name}</p>
											<p className="text-xs text-ink-2 font-mono">{m.email}</p>
										</td>
										<td className="px-4 py-3">
											{canManage && !isSelf ? (
												<div className="flex items-center gap-2">
													<select
														aria-label={`Role for ${m.email}`}
														value={
															["owner", "member", "viewer"].includes(m.role)
																? m.role
																: "member"
														}
														disabled={role.isPending}
														onChange={(e) =>
															role.mutate({
																membershipId: m.id,
																role: e.target.value as Role,
															})
														}
														className="rounded bg-surface-2 border border-line px-1.5 py-0.5 text-xs text-ink focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-40"
													>
														<option value="owner">owner</option>
														<option value="member">member</option>
														<option value="viewer">viewer</option>
													</select>
													{/* Auto-saves on select — surface it per row so there's no
													    "did it save?" ambiguity (no separate Save button). */}
													{role.variables?.membershipId === m.id &&
														(role.isPending ? (
															<span className="text-xs text-ink-3">
																Saving…
															</span>
														) : role.isSuccess ? (
															<span className="text-xs text-ok">Saved ✓</span>
														) : role.isError ? (
															<span className="text-xs text-danger">
																Failed
															</span>
														) : null)}
												</div>
											) : (
												<RoleBadge role={m.role} />
											)}
										</td>
										<td className="px-4 py-3 text-xs text-ink-2">
											{new Date(m.joinedAt).toLocaleDateString()}
										</td>
										<td className="px-4 py-3 text-right">
											{canManage && !isSelf && (
												<button
													type="button"
													disabled={remove.isPending}
													onClick={() => {
														if (
															window.confirm(
																`Remove ${m.email} from this workspace?`,
															)
														) {
															remove.mutate(m.id);
														}
													}}
													className="text-xs text-ink-2 transition-colors hover:text-danger disabled:opacity-40"
												>
													Remove
												</button>
											)}
										</td>
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}

			{canManage && (role.isPending || role.isSuccess) && (
				<p className="text-xs text-ink-3">
					Role changes take effect on the member&apos;s next sign-in (their
					session token is reissued on refresh).
				</p>
			)}

			{(remove.error || role.error) && (
				<p className="text-xs text-danger">
					{((remove.error ?? role.error) as Error).message}
				</p>
			)}

			{pending && pending.length > 0 && (
				<div className="space-y-2">
					<p className="text-xs font-medium text-ink-2">Pending invitations</p>
					<div className="rounded-lg border border-line overflow-hidden">
						<table className="w-full text-sm">
							<tbody className="divide-y divide-line">
								{pending.map((p) => (
									<tr
										key={p.id}
										className="hover:bg-surface-2/40 transition-colors"
									>
										<td className="px-4 py-3">
											<p className="text-xs font-mono text-ink">{p.email}</p>
										</td>
										<td className="px-4 py-3">
											<RoleBadge role={p.role} />
										</td>
										<td className="px-4 py-3 text-xs text-ink-2">
											invited {new Date(p.invitedAt).toLocaleDateString()}
										</td>
										<td className="px-4 py-3 text-right space-x-3">
											{canManage && (
												<>
													<button
														type="button"
														disabled={resend.isPending}
														onClick={() => resend.mutate(p.id)}
														className="text-xs text-ink-2 transition-colors hover:text-ink disabled:opacity-40"
													>
														Resend
													</button>
													<button
														type="button"
														disabled={revoke.isPending}
														onClick={() => revoke.mutate(p.id)}
														className="text-xs text-ink-2 transition-colors hover:text-danger disabled:opacity-40"
													>
														Revoke
													</button>
												</>
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</div>
			)}

			{showInvite && (
				<InviteModal
					onClose={() => setShowInvite(false)}
					onInvited={invalidate}
				/>
			)}
		</div>
	);
}
