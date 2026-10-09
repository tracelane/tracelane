"use client";
/**
 * OG-60 Security — `OG-36` admin IP allowlist + SSO-required
 * (`GET/PUT /v1/security/admin-access`) and the `OG-34` role matrix.
 *
 * The page shows the address the gateway sees for THIS session, so an allowlist cannot
 * silently lock its own author out: the gateway refuses such a save with `409
 * would_lock_you_out` and this page offers the explicit, typed override the gateway
 * requires (`acknowledge_lockout`). The break-glass script is the way back for an operator.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import type { AdminAccessView } from "@/lib/gateway-controls";
import {
	type CapabilitySlug,
	ROLE_CAPABILITIES,
} from "@/lib/role-capabilities.generated";
import {
	Badge,
	Button,
	ConfirmDialog,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import {
	Boundary,
	RefusalNote,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, monoInput } from "./fields";

export const LOCKOUT_PHRASE = "lock me out";

type SaveBody = {
	admin_ip_allowlist: string[];
	sso_required: boolean;
	acknowledge_lockout?: boolean;
};

const lines = (s: string) =>
	s
		.split(/[\n,]/)
		.map((x) => x.trim())
		.filter(Boolean);

function AccessForm({
	a,
	allowed,
	reason,
}: { a: AdminAccessView; allowed: boolean; reason: string | null }) {
	const [list, setList] = useState(a.admin_ip_allowlist.join("\n"));
	const [sso, setSso] = useState(a.sso_required);
	const [override, setOverride] = useState<SaveBody | null>(null);
	const key = `${a.updated_at}|${a.admin_ip_allowlist.join(",")}|${a.sso_required}`;
	// biome-ignore lint/correctness/useExhaustiveDependencies: reseed only when the stored state changes
	useEffect(() => {
		setList(a.admin_ip_allowlist.join("\n"));
		setSso(a.sso_required);
	}, [key]);
	const save = useControlWrite<AdminAccessView, SaveBody>(
		"PUT",
		"security/admin-access",
		["security/admin-access"],
	);
	const lockout = save.error?.refusal.code === "would_lock_you_out";
	const entries = lines(list);
	const body: SaveBody = { admin_ip_allowlist: entries, sso_required: sso };
	const myCidr = a.your_ip
		? `${a.your_ip}/${a.your_ip.includes(":") ? 128 : 32}`
		: null;
	const dirty =
		entries.join(",") !== a.admin_ip_allowlist.join(",") ||
		sso !== a.sso_required;
	return (
		<div className="space-y-4">
			<div className="rounded-control bg-surface-2 p-3 text-sm">
				<p>
					The gateway sees your address as{" "}
					<code className="font-mono">{a.your_ip ?? "unknown"}</code>
					{a.your_ip ? (
						a.your_ip_attested ? (
							<>
								{" "}
								<Badge tone="ok">attested by the dashboard</Badge>
							</>
						) : (
							<>
								{" "}
								<Badge tone="warn">not attested</Badge>
							</>
						)
					) : null}
					.
				</p>
				<p className="mt-1 text-xs text-ink-3">
					{a.your_ip_attested
						? "This is the browser's address as the dashboard signed it for this request — the address the allowlist is checked against."
						: "The dashboard's signed address was not present, so this is the connection address the gateway itself derived. Check it is the address your browser uses before saving an allowlist."}
				</p>
			</div>
			{a.admin_ip_allowlist.length === 0 ? (
				<EmptyNote>
					No allowlist: admin actions are accepted from any address.
				</EmptyNote>
			) : null}
			<Field
				label="Admin IP allowlist (CIDR)"
				hint={`One range per line, e.g. 203.0.113.0/24. At most ${a.max_ip_allowlist_entries}. Applies to admin actions only (changing controls, keys, projects, security) — not to inference traffic.`}
				error={
					save.error?.refusal.code === "invalid_cidr"
						? save.error.refusal.message
						: null
				}
			>
				<textarea
					className={monoInput}
					rows={4}
					disabled={!allowed || save.isPending}
					value={list}
					onChange={(e) => setList(e.target.value)}
				/>
			</Field>
			{myCidr ? (
				<Button
					size="sm"
					disabled={!allowed || save.isPending || entries.includes(myCidr)}
					onClick={() =>
						setList((l) => (l.trim() ? `${l.trim()}\n${myCidr}` : myCidr))
					}
				>
					Add my address ({myCidr})
				</Button>
			) : null}
			<label className="flex items-start gap-2 text-sm">
				<input
					type="checkbox"
					className="mt-0.5"
					checked={sso}
					disabled={!allowed || save.isPending}
					onChange={(e) => setSso(e.target.checked)}
				/>
				<span>
					<span className="font-medium">Require SSO for admin actions.</span>{" "}
					<span className="text-ink-2">
						A session that did not sign in through your identity provider is
						refused for admin actions. The gateway checks that you are signed in
						through SSO before it lets you turn this on.
					</span>
				</span>
			</label>
			{lockout ? (
				<div
					role="alert"
					className="space-y-2 rounded-control border border-warn/40 bg-warn-soft/40 p-3 text-sm"
				>
					<p className="font-medium text-warn-ink">
						This would lock you out of admin actions.
					</p>
					<p className="text-ink-2">{save.error?.refusal.message}</p>
					<Button size="sm" onClick={() => setOverride(body)}>
						Save anyway…
					</Button>
				</div>
			) : (
				<RefusalNote error={save.error} />
			)}
			<div className="flex items-center gap-3">
				<Button
					variant="primary"
					size="sm"
					disabled={!allowed || save.isPending || !dirty}
					onClick={() => save.mutate(body)}
				>
					{save.isPending ? "Saving…" : "Save access rules"}
				</Button>
				{save.isSuccess && !dirty ? (
					<output className="text-sm text-ok-ink">
						Saved
						{save.data?.updated_at
							? ` ${formatDateTimeUtc(save.data.updated_at)}`
							: ""}
						.
					</output>
				) : null}
			</div>
			<WhyDisabled reason={reason} />
			{a.updated_at ? (
				<p className="text-xs text-ink-3">
					Last changed {formatDateTimeUtc(a.updated_at)}
					{a.updated_by ? ` by ${a.updated_by}` : ""}.
				</p>
			) : null}
			<ConfirmDialog
				open={override !== null}
				onClose={() => setOverride(null)}
				title="Save and risk locking yourself out?"
				confirmLabel="Save anyway"
				confirmText={LOCKOUT_PHRASE}
				busy={save.isPending}
				error={null}
				onConfirm={() => {
					if (override)
						save.mutate(
							{ ...override, acknowledge_lockout: true },
							{ onSuccess: () => setOverride(null) },
						);
				}}
			>
				<p className="text-sm text-ink-2">
					After this, your own next admin action may be refused. An operator can
					restore access with the break-glass script on the gateway host.
				</p>
			</ConfirmDialog>
		</div>
	);
}

export function AdminAccess() {
	const q = useControlQuery<AdminAccessView>("security/admin-access");
	const { allowed, reason } = useCan("manage_security");
	return (
		<Panel
			id="admin-access"
			title="Admin access"
			description="Restrict who can change this workspace's controls: an IP allowlist and SSO-required, enforced by the gateway on every admin action."
		>
			<Boundary query={q} resource="admin access rules" rows={4}>
				{(a) => <AccessForm a={a} allowed={allowed} reason={reason} />}
			</Boundary>
		</Panel>
	);
}

const COLUMNS = [
	["admin", "Owner / admin"],
	["developer", "Developer"],
	["viewer", "Viewer"],
	["billing", "Billing"],
	["unrecognised", "Unrecognised"],
] as const;

const humanize = (s: string) => s.replace(/_/g, " ");

/** The gateway's role × capability matrix, read from the generated mirror. */
export function RoleMatrix() {
	const caps = Object.keys(ROLE_CAPABILITIES) as CapabilitySlug[];
	return (
		<Panel
			id="roles"
			title="Roles and capabilities"
			description="What each workspace role may do, as the gateway enforces it. Roles are assigned to people on the Team page; an API key never manages controls."
		>
			<div className="overflow-x-auto">
				<Table className="w-full text-left text-sm">
					<THead>
						<TR>
							<TH>Capability</TH>
							{COLUMNS.map(([, label]) => (
								<TH key={label}>{label}</TH>
							))}
						</TR>
					</THead>
					<TBody>
						{caps.map((c) => (
							<TR key={c}>
								<TD>{humanize(c)}</TD>
								{COLUMNS.map(([role, label]) => (
									<TD key={role}>
										{ROLE_CAPABILITIES[c][role] ? (
											<span aria-label={`${label} can ${humanize(c)}`}>✓</span>
										) : (
											<span
												className="text-ink-3"
												aria-label={`${label} cannot ${humanize(c)}`}
											>
												—
											</span>
										)}
									</TD>
								))}
							</TR>
						))}
					</TBody>
				</Table>
			</div>
		</Panel>
	);
}
