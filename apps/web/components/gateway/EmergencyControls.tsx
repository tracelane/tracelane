"use client";
/**
 * OG-60 Gateway › Emergency — `OG-25`: pause / resume the workspace, block a model,
 * provider or end user, revoke every API key. Each destructive action is behind a
 * confirm dialog; revoke-all needs the typed phrase the gateway itself requires
 * (`confirm: "revoke all keys"`). Everything works while the workspace is paused — the
 * control routes never run the admission pipeline.
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import type { ControlsState } from "@/lib/gateway-controls";
import { Badge, Button, ConfirmDialog } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import {
	Boundary,
	RefusalNote,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { Field, Panel, WhyDisabled, inputClass, monoInput } from "./fields";

export const REVOKE_ALL_PHRASE = "revoke all keys";

const toLines = (s: string) =>
	s
		.split("\n")
		.map((x) => x.trim())
		.filter(Boolean);

function Status({ c }: { c: ControlsState }) {
	return c.paused ? (
		<div className="space-y-1 rounded-control border border-danger/40 bg-danger-soft/40 p-3 text-sm">
			<p className="font-medium text-danger-ink">
				<Badge tone="danger">Paused</Badge>{" "}
				<span className="ml-1">
					Every inference request is being refused (423 workspace_paused).
				</span>
			</p>
			<p className="text-ink-2">
				{c.pausedAt
					? `Since ${formatDateTimeUtc(c.pausedAt)}`
					: "Since an unknown time"}
				{c.pausedBy ? ` by ${c.pausedBy}` : ""}
				{c.pauseReason ? ` — “${c.pauseReason}”` : "."}
			</p>
		</div>
	) : (
		<p className="text-sm">
			<Badge tone="ok">Running</Badge>{" "}
			<span className="ml-1 text-ink-2">
				The workspace is serving requests.
			</span>
		</p>
	);
}

function BlockLists({ c, allowed }: { c: ControlsState; allowed: boolean }) {
	const [models, setModels] = useState(c.blocks.models.join("\n"));
	const [providers, setProviders] = useState(c.blocks.providers.join("\n"));
	const [endUsers, setEndUsers] = useState(c.blocks.endUsers.join("\n"));
	const key = `${c.updatedAt}|${c.blocks.models}|${c.blocks.providers}|${c.blocks.endUsers}`;
	// biome-ignore lint/correctness/useExhaustiveDependencies: reseed only when the server state changes
	useEffect(() => {
		setModels(c.blocks.models.join("\n"));
		setProviders(c.blocks.providers.join("\n"));
		setEndUsers(c.blocks.endUsers.join("\n"));
	}, [key]);
	const save = useControlWrite<
		ControlsState,
		{ models: string[]; providers: string[]; endUsers: string[] }
	>("PUT", "controls/blocks", ["controls"]);
	const none =
		c.blocks.models.length +
			c.blocks.providers.length +
			c.blocks.endUsers.length ===
		0;
	return (
		<div className="space-y-3">
			{none ? (
				<p className="rounded-control bg-surface-2 px-3 py-2 text-sm text-ink-2">
					Nothing is blocked. Add a model, provider or end user to refuse it
					immediately, without deleting any key.
				</p>
			) : null}
			<div className="grid gap-3 sm:grid-cols-3">
				<Field label="Blocked models" hint="One per line; * globs allowed.">
					<textarea
						className={monoInput}
						rows={4}
						disabled={!allowed || save.isPending}
						value={models}
						onChange={(e) => setModels(e.target.value)}
					/>
				</Field>
				<Field label="Blocked providers" hint="Provider ids, one per line.">
					<textarea
						className={monoInput}
						rows={4}
						disabled={!allowed || save.isPending}
						value={providers}
						onChange={(e) => setProviders(e.target.value)}
					/>
				</Field>
				<Field
					label="Blocked end users"
					hint="The request's user id, one per line."
				>
					<textarea
						className={monoInput}
						rows={4}
						disabled={!allowed || save.isPending}
						value={endUsers}
						onChange={(e) => setEndUsers(e.target.value)}
					/>
				</Field>
			</div>
			<RefusalNote error={save.error} />
			<div className="flex items-center gap-3">
				<Button
					variant="primary"
					size="sm"
					disabled={!allowed || save.isPending}
					onClick={() =>
						save.mutate({
							models: toLines(models),
							providers: toLines(providers),
							endUsers: toLines(endUsers),
						})
					}
				>
					{save.isPending ? "Saving…" : "Save block lists"}
				</Button>
				{save.isSuccess ? (
					<output className="text-sm text-ok-ink">
						Saved. Takes effect on the next request.
					</output>
				) : null}
			</div>
		</div>
	);
}

export function EmergencyControls() {
	const controls = useControlQuery<ControlsState>("controls");
	const { allowed, reason } = useCan("manage_controls");
	const keys = useCan("manage_all_keys");
	const [pauseOpen, setPauseOpen] = useState(false);
	const [resumeOpen, setResumeOpen] = useState(false);
	const [revokeOpen, setRevokeOpen] = useState(false);
	const [pauseReason, setPauseReason] = useState("");
	const pause = useControlWrite<ControlsState, { reason?: string }>(
		"POST",
		"controls/pause",
		["controls"],
	);
	const resume = useControlWrite<ControlsState, Record<string, never>>(
		"POST",
		"controls/resume",
		["controls"],
	);
	const revoke = useControlWrite<
		{ revoked: number; keyIds: string[] },
		{ confirm: string }
	>("POST", "controls/revoke-all-keys");

	return (
		<div className="space-y-6">
			<Panel
				id="pause"
				title="Pause the workspace"
				description="Stops every inference request for this workspace at once (HTTP 423). Keys, settings and data are untouched; resume restores service."
			>
				<Boundary query={controls} resource="emergency controls" rows={2}>
					{(c) => (
						<div className="space-y-3">
							<Status c={c} />
							<div className="flex flex-wrap items-center gap-3">
								{c.paused ? (
									<Button
										variant="primary"
										size="sm"
										disabled={!allowed}
										onClick={() => setResumeOpen(true)}
									>
										Resume workspace
									</Button>
								) : (
									<Button
										variant="danger"
										size="sm"
										disabled={!allowed}
										onClick={() => setPauseOpen(true)}
									>
										Pause workspace
									</Button>
								)}
							</div>
							<WhyDisabled reason={reason} />
						</div>
					)}
				</Boundary>
			</Panel>

			<Panel
				id="blocks"
				title="Block a model, provider or end user"
				description="Each list you save replaces that list. A blocked name is refused before any provider is called."
			>
				<Boundary query={controls} resource="block lists" rows={2}>
					{(c) => (
						<>
							<BlockLists c={c} allowed={allowed} />
							<WhyDisabled reason={reason} />
						</>
					)}
				</Boundary>
			</Panel>

			<Panel
				id="revoke-all"
				tone="danger"
				title="Revoke every API key"
				description="Irreversible. Every key in this workspace stops working immediately and cannot be restored — you would mint new ones and update every client."
			>
				<div className="space-y-2">
					<Button
						variant="danger"
						size="sm"
						disabled={!keys.allowed}
						onClick={() => setRevokeOpen(true)}
					>
						Revoke all keys…
					</Button>
					<WhyDisabled reason={keys.reason} />
					{revoke.isSuccess ? (
						<output className="text-sm text-ok-ink">
							Revoked {revoke.data?.revoked ?? 0} key
							{revoke.data?.revoked === 1 ? "" : "s"}.
						</output>
					) : null}
				</div>
			</Panel>

			<ConfirmDialog
				open={pauseOpen}
				onClose={() => setPauseOpen(false)}
				title="Pause this workspace?"
				confirmLabel="Pause workspace"
				busy={pause.isPending}
				error={pause.error?.refusal.message ?? null}
				onConfirm={() =>
					pause.mutate(
						pauseReason.trim() ? { reason: pauseReason.trim() } : {},
						{
							onSuccess: () => {
								setPauseOpen(false);
								setPauseReason("");
							},
						},
					)
				}
			>
				<p className="text-sm text-ink-2">
					Every inference request will be refused until you resume. This is
					recorded in the control-change log.
				</p>
				<Field label="Reason (optional, shown to your team)">
					<input
						className={inputClass}
						maxLength={500}
						value={pauseReason}
						onChange={(e) => setPauseReason(e.target.value)}
					/>
				</Field>
			</ConfirmDialog>

			<ConfirmDialog
				open={resumeOpen}
				onClose={() => setResumeOpen(false)}
				title="Resume this workspace?"
				confirmLabel="Resume workspace"
				busy={resume.isPending}
				error={resume.error?.refusal.message ?? null}
				onConfirm={() =>
					resume.mutate({}, { onSuccess: () => setResumeOpen(false) })
				}
			>
				<p className="text-sm text-ink-2">
					Requests are admitted again straight away.
				</p>
			</ConfirmDialog>

			<ConfirmDialog
				open={revokeOpen}
				onClose={() => setRevokeOpen(false)}
				title="Revoke every API key?"
				confirmLabel="Revoke all keys"
				confirmText={REVOKE_ALL_PHRASE}
				busy={revoke.isPending}
				error={revoke.error?.refusal.message ?? null}
				onConfirm={() =>
					revoke.mutate(
						{ confirm: REVOKE_ALL_PHRASE },
						{ onSuccess: () => setRevokeOpen(false) },
					)
				}
			>
				<p className="text-sm text-ink-2">
					This cannot be undone. Every client using a key from this workspace
					will start failing with 401.
				</p>
			</ConfirmDialog>
		</div>
	);
}
