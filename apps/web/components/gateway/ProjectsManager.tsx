"use client";
/**
 * OG-60 Gateway › Projects — `OG-23`: a project groups API keys, names the environments
 * its keys may carry, and (`OG-20`/`21`/`22`) imposes a policy on every key in it.
 * `GET/POST /v1/projects`, `PATCH/DELETE /v1/projects/{id}` (archive; refused while live
 * keys remain).
 */

import { formatDateTimeUtc } from "@/lib/format-date";
import { type ProjectView, summarizePolicy } from "@/lib/gateway-controls";
import { Badge, Button, ConfirmDialog, Dialog } from "@tracelanedev/ui";
import { useState } from "react";
import { PolicyCard } from "./PolicyEditor";
import {
	Boundary,
	RefusalNote,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

const parseEnvs = (s: string) =>
	s
		.split(/[\n,]/)
		.map((x) => x.trim())
		.filter(Boolean);

function EditProject({
	p,
	allowed,
	reason,
	onClose,
}: {
	p: ProjectView;
	allowed: boolean;
	reason: string | null;
	onClose: () => void;
}) {
	const [name, setName] = useState(p.name);
	const [envs, setEnvs] = useState(p.environments.join(", "));
	const patch = useControlWrite<ProjectView, Record<string, unknown>>(
		"PATCH",
		`projects/${p.id}`,
		["projects"],
	);
	const fieldError = (f: string) =>
		patch.error?.refusal.field === f ? patch.error.refusal.message : null;
	return (
		<Dialog open onClose={onClose} title={`Edit ${p.name}`} drawer>
			<div className="space-y-6">
				<div className="space-y-3">
					<Field label="Name" error={fieldError("name")}>
						<input
							className={inputClass}
							disabled={!allowed || patch.isPending}
							value={name}
							maxLength={128}
							onChange={(e) => setName(e.target.value)}
						/>
					</Field>
					<Field
						label="Environments"
						hint="Comma-separated labels a key in this project may carry: lower-case letters, digits, _ and -."
						error={fieldError("environments")}
					>
						<input
							className={inputClass}
							disabled={!allowed || patch.isPending}
							value={envs}
							onChange={(e) => setEnvs(e.target.value)}
						/>
					</Field>
					<Button
						variant="primary"
						size="sm"
						disabled={!allowed || patch.isPending}
						onClick={() =>
							patch.mutate({ name: name.trim(), environments: parseEnvs(envs) })
						}
					>
						{patch.isPending ? "Saving…" : "Save details"}
					</Button>
				</div>
				<div className="space-y-2 border-t border-line pt-4">
					<h4 className="text-sm font-semibold">Project policy</h4>
					<p className="text-sm text-ink-2">
						Binds every key in this project, together with the workspace policy
						and the key's own.
					</p>
					<PolicyCard
						scope="project"
						doc={p.policy}
						canEdit={allowed}
						reason={reason}
						saving={patch.isPending}
						error={patch.error}
						resetKey={p.updatedAt}
						onSave={(doc) => patch.mutate({ policy: doc })}
						saveLabel="Save project policy"
					/>
				</div>
				<RefusalNote error={patch.error} />
				{patch.isSuccess ? (
					<output className="text-sm text-ok-ink">Saved.</output>
				) : null}
			</div>
		</Dialog>
	);
}

function ProjectRow({
	p,
	allowed,
	reason,
}: { p: ProjectView; allowed: boolean; reason: string | null }) {
	const [editing, setEditing] = useState(false);
	const [archiving, setArchiving] = useState(false);
	const archive = useControlWrite<void, void>("DELETE", `projects/${p.id}`, [
		"projects",
	]);
	return (
		<li className="space-y-2 rounded-card border border-line p-4">
			<div className="flex flex-wrap items-start justify-between gap-2">
				<div>
					<h4 className="font-medium">{p.name}</h4>
					<p className="font-mono text-xs text-ink-3">{p.id}</p>
				</div>
				<div className="flex gap-2">
					<Button
						size="sm"
						aria-label={`Edit ${p.name}`}
						onClick={() => setEditing(true)}
					>
						{allowed ? "Edit" : "View"}
					</Button>
					<Button
						size="sm"
						disabled={!allowed}
						aria-label={`Archive ${p.name}`}
						onClick={() => setArchiving(true)}
					>
						Archive
					</Button>
				</div>
			</div>
			<p className="flex flex-wrap items-center gap-1 text-sm">
				{p.environments.map((e) => (
					<Badge key={e} tone="neutral">
						{e}
					</Badge>
				))}
			</p>
			<p className="text-sm text-ink-2">{summarizePolicy(p.policy)}</p>
			<p className="text-xs text-ink-3">
				Updated {formatDateTimeUtc(p.updatedAt)}
			</p>
			{editing ? (
				<EditProject
					p={p}
					allowed={allowed}
					reason={reason}
					onClose={() => setEditing(false)}
				/>
			) : null}
			<ConfirmDialog
				open={archiving}
				onClose={() => setArchiving(false)}
				title={`Archive ${p.name}?`}
				confirmLabel="Archive project"
				confirmText={p.name}
				busy={archive.isPending}
				error={archive.error?.refusal.message ?? null}
				onConfirm={() =>
					archive.mutate(undefined, { onSuccess: () => setArchiving(false) })
				}
			>
				<p className="text-sm text-ink-2">
					Archiving is refused while live keys still belong to the project —
					move or revoke them first.
				</p>
			</ConfirmDialog>
		</li>
	);
}

function CreateProject({
	allowed,
	reason,
}: { allowed: boolean; reason: string | null }) {
	const [name, setName] = useState("");
	const [envs, setEnvs] = useState("production");
	const create = useControlWrite<
		ProjectView,
		{ name: string; environments: string[] }
	>("POST", "projects", ["projects"]);
	const fieldError = (f: string) =>
		create.error?.refusal.field === f ? create.error.refusal.message : null;
	return (
		<div className="space-y-3">
			<div className="grid gap-3 sm:grid-cols-2">
				<Field label="New project name" error={fieldError("name")}>
					<input
						className={inputClass}
						disabled={!allowed || create.isPending}
						value={name}
						maxLength={128}
						onChange={(e) => setName(e.target.value)}
					/>
				</Field>
				<Field
					label="Environments"
					hint="Comma-separated, e.g. production, staging."
					error={fieldError("environments")}
				>
					<input
						className={inputClass}
						disabled={!allowed || create.isPending}
						value={envs}
						onChange={(e) => setEnvs(e.target.value)}
					/>
				</Field>
			</div>
			<RefusalNote error={create.error} />
			<Button
				variant="primary"
				size="sm"
				disabled={!allowed || create.isPending || !name.trim()}
				onClick={() =>
					create.mutate(
						{ name: name.trim(), environments: parseEnvs(envs) },
						{ onSuccess: () => setName("") },
					)
				}
			>
				{create.isPending ? "Creating…" : "Create project"}
			</Button>
			<WhyDisabled reason={reason} />
		</div>
	);
}

export function ProjectsManager() {
	const projects = useControlQuery<{ projects: ProjectView[] }>("projects");
	const { allowed, reason } = useCan("edit_projects");
	return (
		<Panel
			id="projects"
			title="Projects and environments"
			description="Group keys by project, label them by environment, and set limits, budgets and rules once for every key in a project."
		>
			<Boundary query={projects} resource="projects" rows={3}>
				{({ projects: rows }) =>
					rows.length === 0 ? (
						<EmptyNote>
							No projects: every key stands alone and only the workspace policy
							and each key's own policy apply.
						</EmptyNote>
					) : (
						<ul className="space-y-3">
							{rows.map((p) => (
								<ProjectRow
									key={p.id}
									p={p}
									allowed={allowed}
									reason={reason}
								/>
							))}
						</ul>
					)
				}
			</Boundary>
			<CreateProject allowed={allowed} reason={reason} />
		</Panel>
	);
}
