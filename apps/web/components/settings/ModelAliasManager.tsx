"use client";
import { Button } from "@tracelanedev/ui";

import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";

/**
 * ModelAliasManager — GWY-27, the workspace's own model aliases
 * (`specs/GWY-27-model-aliases.md` §4, §8).
 *
 * "Swap the model behind my app without a deploy": call `model: "fast"` from code,
 * point `fast` at a real model here. The gateway owns every rule — validation (only
 * it knows the routing map), the owner-only write gate and the cap — and reports
 * `can_edit` so this component never guesses a role. Every number shown is the
 * gateway's: the count is `items.length`, the limit is `max` (`null` → "limit
 * unavailable", create disabled), and a row whose target stopped routing shows
 * `provider: null` → "no longer routable" (the hot path refuses it, fail-closed).
 */

import { ApiError, apiFetch, apiFetchRaw } from "@/lib/api-fetch";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

interface AliasRow {
	alias: string;
	target_model: string;
	provider: string | null;
}

interface AliasList {
	items: AliasRow[];
	max: number | null;
	can_edit: boolean;
}

const ENDPOINT = "/api/settings/model-aliases";
const QUERY_KEY = ["model-aliases"];

/** The gateway's typed refusal codes → the sentence shown at the field. */
const REFUSAL_COPY: Record<string, string> = {
	invalid_alias:
		"Use letters, digits and . _ : / - only, starting with a letter or digit (max 64).",
	invalid_target: "Enter the model the alias should call.",
	unroutable_target:
		"That model does not route to any provider — check the exact model name.",
	target_is_alias:
		"That is one of your aliases. Point at a real model name — aliases resolve one hop.",
	self_alias: "An alias cannot point at itself.",
	alias_cap_reached: "You are at the alias limit — delete one to add another.",
	alias_exists: "That alias already exists — edit it in the table instead.",
	alias_limit_unavailable:
		"The alias limit could not be read right now. Try again shortly.",
	role_forbidden: "Only a workspace owner can change aliases.",
	not_found: "That alias no longer exists.",
};

function refusalText(err: unknown): string {
	if (err instanceof ApiError) {
		return (
			REFUSAL_COPY[err.message] ??
			`The gateway refused the change (HTTP ${err.status}).`
		);
	}
	return "The change could not be saved. Try again.";
}

async function putAlias(input: {
	alias: string;
	target_model: string;
	create: boolean;
}): Promise<AliasRow> {
	return apiFetch<AliasRow>("/api/settings/model-aliases", {
		method: "PUT",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(input),
	});
}

async function deleteAlias(alias: string): Promise<void> {
	const res = await apiFetchRaw(
		`/api/settings/model-aliases?alias=${encodeURIComponent(alias)}`,
		{ method: "DELETE" },
	);
	if (res.status === 204) return;
	const body = (await res.json().catch(() => null)) as {
		error?: string;
	} | null;
	throw new ApiError(res.status, body?.error);
}

const inputClass =
	"w-full rounded border border-line bg-surface px-2 py-1.5 font-mono text-sm text-ink placeholder:text-ink-3 focus-visible:border-line-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-action";
const primaryButton =
	"rounded bg-action px-3 py-1.5 text-sm text-action-on transition-colors hover:bg-action/90 disabled:opacity-40";
const quietButton =
	"rounded border border-line px-2 py-1 text-xs text-ink-2 transition-colors hover:bg-surface-2 disabled:opacity-40";

export function ModelAliasManager() {
	const qc = useQueryClient();
	const { data, error, isLoading, refetch } = useQuery({
		queryKey: QUERY_KEY,
		queryFn: () => apiFetch<AliasList>(ENDPOINT),
		staleTime: 30_000,
	});

	const [alias, setAlias] = useState("");
	const [target, setTarget] = useState("");
	const [editing, setEditing] = useState<string | null>(null);
	const [editTarget, setEditTarget] = useState("");

	const create = useMutation({
		mutationFn: putAlias,
		onSuccess: () => {
			setAlias("");
			setTarget("");
			void qc.invalidateQueries({ queryKey: QUERY_KEY });
		},
	});
	const update = useMutation({
		mutationFn: putAlias,
		onSuccess: () => {
			setEditing(null);
			void qc.invalidateQueries({ queryKey: QUERY_KEY });
		},
	});
	const remove = useMutation({
		mutationFn: deleteAlias,
		onSuccess: () => void qc.invalidateQueries({ queryKey: QUERY_KEY }),
	});

	if (isLoading) {
		return (
			<div className="space-y-1.5" aria-busy="true">
				<div className="h-8 w-full animate-pulse rounded bg-surface-2" />
				<div className="h-8 w-4/5 animate-pulse rounded bg-surface-2" />
			</div>
		);
	}

	if (error) {
		// Error is never the empty state (TRAPS §18): say what failed and offer a retry.
		const forbidden = error instanceof ApiError && error.status === 403;
		return (
			<div
				className="rounded border border-line p-3 text-sm text-ink-2"
				role="alert"
			>
				{forbidden
					? "Only a workspace owner can view model aliases."
					: `Model aliases could not be loaded${error instanceof ApiError ? ` (HTTP ${error.status})` : ""}.`}{" "}
				{!forbidden && (
					<Button
						variant="bare"
						type="button"
						className={quietButton}
						onClick={() => refetch()}
					>
						Retry
					</Button>
				)}
			</div>
		);
	}

	const list = data ?? { items: [], max: null, can_edit: false };
	const atCap = list.max !== null && list.items.length >= list.max;
	const canCreate = list.can_edit && list.max !== null && !atCap;

	return (
		<div className="space-y-3">
			<div className="flex items-baseline justify-between gap-2">
				<h4 className="font-medium">Your model aliases</h4>
				<span className="text-xs text-ink-3" data-testid="alias-count">
					{list.max === null
						? `${list.items.length} · limit unavailable`
						: `${list.items.length} of ${list.max}`}
				</span>
			</div>
			<p className="text-sm text-ink-2">
				Call an alias as <code className="font-mono">model</code> on{" "}
				<code className="font-mono">/v1/chat/completions</code> or{" "}
				<code className="font-mono">/v1/embeddings</code>. Changes apply to your
				next request (on a deployment running several gateways, the others pick
				them up within 15 minutes). Traces record both the alias and the model
				that served it.
			</p>

			{list.items.length === 0 ? (
				<p className="text-sm text-ink-2">
					No aliases yet — call a model by a name you control.
				</p>
			) : (
				<div className="overflow-x-auto">
					<Table className="w-full text-left text-sm">
						<THead className="text-xs text-ink-3">
							<TR>
								<TH className="py-1 pr-3 font-normal">Alias</TH>
								<TH className="py-1 pr-3 font-normal">Target model</TH>
								<TH className="py-1 pr-3 font-normal">Provider</TH>
								{list.can_edit && <TH className="py-1 font-normal" />}
							</TR>
						</THead>
						<TBody>
							{list.items.map((row) => (
								<TR key={row.alias} className="border-t border-line align-top">
									<TD className="py-1.5 pr-3 font-mono break-all">
										{row.alias}
									</TD>
									<TD className="py-1.5 pr-3 font-mono break-all">
										{editing === row.alias ? (
											<input
												aria-label={`New target for ${row.alias}`}
												className={inputClass}
												value={editTarget}
												onChange={(e) => setEditTarget(e.target.value)}
											/>
										) : (
											row.target_model
										)}
									</TD>
									<TD className="py-1.5 pr-3">
										{row.provider ?? (
											<span className="text-danger-ink">
												no longer routable
											</span>
										)}
									</TD>
									{list.can_edit && (
										<TD className="py-1.5 whitespace-nowrap text-right">
											{editing === row.alias ? (
												<span className="inline-flex gap-1.5">
													<Button
														variant="bare"
														type="button"
														className={quietButton}
														disabled={update.isPending || !editTarget.trim()}
														onClick={() =>
															update.mutate({
																alias: row.alias,
																target_model: editTarget.trim(),
																create: false,
															})
														}
													>
														Save
													</Button>
													<Button
														variant="bare"
														type="button"
														className={quietButton}
														onClick={() => setEditing(null)}
													>
														Cancel
													</Button>
												</span>
											) : (
												<span className="inline-flex gap-1.5">
													<Button
														variant="bare"
														type="button"
														className={quietButton}
														onClick={() => {
															update.reset();
															setEditing(row.alias);
															setEditTarget(row.target_model);
														}}
													>
														Edit
													</Button>
													<Button
														variant="bare"
														type="button"
														className={quietButton}
														disabled={remove.isPending}
														onClick={() => {
															if (
																window.confirm(
																	`Delete alias "${row.alias}"? Calls using it will be refused as an unknown model.`,
																)
															) {
																remove.mutate(row.alias);
															}
														}}
													>
														Delete
													</Button>
												</span>
											)}
										</TD>
									)}
								</TR>
							))}
						</TBody>
					</Table>
				</div>
			)}
			{update.isError && (
				<p className="text-sm text-danger-ink" role="alert">
					{refusalText(update.error)}
				</p>
			)}
			{remove.isError && (
				<p className="text-sm text-danger-ink" role="alert">
					{refusalText(remove.error)}
				</p>
			)}

			{list.can_edit ? (
				<form
					className="grid gap-2 sm:grid-cols-[1fr_1.5fr_auto] sm:items-end"
					onSubmit={(e) => {
						e.preventDefault();
						if (!canCreate) return;
						create.mutate({
							alias: alias.trim(),
							target_model: target.trim(),
							create: true,
						});
					}}
				>
					<label className="block text-xs text-ink-2">
						Alias
						<input
							className={inputClass}
							placeholder="fast"
							value={alias}
							maxLength={64}
							onChange={(e) => setAlias(e.target.value)}
						/>
					</label>
					<label className="block text-xs text-ink-2">
						Target model
						<input
							className={inputClass}
							placeholder="claude-haiku-4-5-20251001"
							value={target}
							maxLength={256}
							onChange={(e) => setTarget(e.target.value)}
						/>
					</label>
					<Button
						variant="bare"
						type="submit"
						className={primaryButton}
						disabled={
							!canCreate || create.isPending || !alias.trim() || !target.trim()
						}
					>
						{create.isPending ? "Saving…" : "Add alias"}
					</Button>
					{atCap && (
						<p className="text-sm text-ink-2 sm:col-span-3">
							{list.items.length} of {list.max} — delete one to add another.
						</p>
					)}
					{create.isError && (
						<p className="text-sm text-danger-ink sm:col-span-3" role="alert">
							{refusalText(create.error)}
						</p>
					)}
				</form>
			) : (
				<p className="text-sm text-ink-3">
					Only a workspace owner can change aliases.
				</p>
			)}
		</div>
	);
}
