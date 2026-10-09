"use client";
/**
 * OG-60 Gateway › Keys — `OG-20` per-key policy, `OG-21` limits and `OG-22` budgets at the
 * key layer, and the `OG-23` project and environment a key belongs to, through
 * `PATCH /v1/keys/{id}` (the dashboard's existing key proxy, which forwards `policy`,
 * `projectId`, `environment` untouched).
 *
 * The key LIST is the existing `/api/settings/api-keys` read: the gateway has no list
 * route for keys (only `GET /v1/keys/{id}`), so there is no gateway-only list to call.
 */

import type { ProjectView } from "@/lib/gateway-controls";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Button, Dialog } from "@tracelanedev/ui";
import { useState } from "react";
import { PolicyCard } from "./PolicyEditor";
import { type ControlError, requestJson } from "./control";
import { Boundary, RefusalNote, useCan, useControlQuery } from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

interface KeyListRow {
	id: string;
	name: string;
	keyPrefix: string;
	revokedAt?: string | null;
}
interface KeyDetail {
	id: string;
	name: string;
	projectId: string | null;
	environment: string | null;
	policy: Record<string, unknown> | null;
	revokedAt?: string | null;
}

function KeyEditor({
	row,
	projects,
	onClose,
}: {
	row: KeyListRow;
	projects: ProjectView[] | null;
	onClose: () => void;
}) {
	const qc = useQueryClient();
	const { allowed, reason } = useCan("mint_keys");
	const url = `/api/settings/api-keys/${encodeURIComponent(row.id)}`;
	const detail = useQuery<KeyDetail, ControlError>({
		queryKey: ["gateway-control", "key", row.id],
		queryFn: () => requestJson<KeyDetail>("GET", url),
		retry: false,
	});
	const patch = useMutation<KeyDetail, ControlError, Record<string, unknown>>({
		mutationFn: (b) => requestJson<KeyDetail>("PATCH", url, b),
		onSuccess: (d) => {
			qc.setQueryData(["gateway-control", "key", row.id], d);
			void qc.invalidateQueries({ queryKey: ["gateway-control", "keys"] });
		},
	});
	const [project, setProject] = useState<string | null>(null);
	const [env, setEnv] = useState<string | null>(null);
	return (
		<Dialog open onClose={onClose} title={`Policy for ${row.name}`} drawer>
			<Boundary query={detail} resource="this key" rows={4}>
				{(k) => {
					const retiring = !!k.revokedAt;
					const editable = allowed && !retiring;
					const projectId = project ?? k.projectId ?? "";
					const chosen = projects?.find((p) => p.id === projectId);
					const environment = env ?? k.environment ?? "";
					return (
						<div className="space-y-6">
							{retiring ? (
								<EmptyNote>
									This key is retiring (rotated, in its grace window) and can no
									longer be edited.
								</EmptyNote>
							) : null}
							<div className="space-y-3">
								<h4 className="text-sm font-semibold">
									Project and environment
								</h4>
								<div className="grid gap-3 sm:grid-cols-2">
									<Field
										label="Project"
										error={
											patch.error?.refusal.field === "project_id"
												? patch.error.refusal.message
												: null
										}
									>
										<select
											className={inputClass}
											disabled={
												!editable || patch.isPending || projects === null
											}
											value={projectId}
											onChange={(e) => {
												setProject(e.target.value);
												setEnv("");
											}}
										>
											<option value="">No project</option>
											{(projects ?? []).map((p) => (
												<option key={p.id} value={p.id}>
													{p.name}
												</option>
											))}
										</select>
									</Field>
									<Field
										label="Environment"
										error={
											patch.error?.refusal.field === "environment"
												? patch.error.refusal.message
												: null
										}
									>
										<select
											className={inputClass}
											disabled={!editable || patch.isPending || !chosen}
											value={environment}
											onChange={(e) => setEnv(e.target.value)}
										>
											<option value="">None</option>
											{(chosen?.environments ?? []).map((e) => (
												<option key={e} value={e}>
													{e}
												</option>
											))}
										</select>
									</Field>
								</div>
								<Button
									variant="primary"
									size="sm"
									disabled={!editable || patch.isPending}
									onClick={() =>
										patch.mutate({
											projectId: projectId === "" ? null : projectId,
											environment: environment === "" ? null : environment,
										})
									}
								>
									{patch.isPending ? "Saving…" : "Save project and environment"}
								</Button>
							</div>
							<div className="space-y-2 border-t border-line pt-4">
								<h4 className="text-sm font-semibold">Key policy</h4>
								<p className="text-sm text-ink-2">
									{chosen
										? `Together with project “${chosen.name}” and the workspace policy: every layer must pass, so this key can narrow them, never widen them.`
										: "Together with the workspace policy: every layer must pass."}
								</p>
								<PolicyCard
									scope="key"
									doc={k.policy}
									canEdit={editable}
									reason={retiring ? null : reason}
									saving={patch.isPending}
									error={patch.error}
									onSave={(doc) => patch.mutate({ policy: doc })}
									saveLabel="Save key policy"
								/>
							</div>
							<RefusalNote error={patch.error} />
							{patch.isSuccess ? (
								<output className="text-sm text-ok-ink">
									Saved. The gateway applies it to the key's next request.
								</output>
							) : null}
						</div>
					);
				}}
			</Boundary>
		</Dialog>
	);
}

export function KeyPolicyManager() {
	const keys = useQuery<KeyListRow[], ControlError>({
		queryKey: ["gateway-control", "keys"],
		queryFn: () => requestJson<KeyListRow[]>("GET", "/api/settings/api-keys"),
		retry: false,
	});
	const projects = useControlQuery<{ projects: ProjectView[] }>("projects");
	const [open, setOpen] = useState<KeyListRow | null>(null);
	const { allowed, reason } = useCan("mint_keys");
	return (
		<Panel
			id="key-policy"
			title="Per-key policy"
			description="Limits, budgets, model and provider rules, source IPs and required labels for one key — and the project and environment it belongs to."
		>
			<Boundary query={keys} resource="API keys" rows={3}>
				{(rows) =>
					rows.length === 0 ? (
						<EmptyNote>
							No API keys yet. Mint one under{" "}
							<a className="underline" href="/settings/api-keys">
								API Keys
							</a>
							, then set its policy here.
						</EmptyNote>
					) : (
						<ul className="divide-y divide-line">
							{rows.map((r) => (
								<li
									key={r.id}
									className="flex flex-wrap items-center justify-between gap-2 py-2"
								>
									<div>
										<span className="font-medium">{r.name}</span>{" "}
										<code className="font-mono text-xs text-ink-3">
											{r.keyPrefix}…
										</code>{" "}
										{r.revokedAt ? <Badge tone="warn">retiring</Badge> : null}
									</div>
									<Button
										size="sm"
										aria-label={`Policy for ${r.name}`}
										onClick={() => setOpen(r)}
									>
										{allowed ? "Edit policy" : "View policy"}
									</Button>
								</li>
							))}
						</ul>
					)
				}
			</Boundary>
			<WhyDisabled reason={reason} />
			{open ? (
				<KeyEditor
					row={open}
					projects={projects.data?.projects ?? null}
					onClose={() => setOpen(null)}
				/>
			) : null}
		</Panel>
	);
}
