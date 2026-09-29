"use client";
import { Button } from "@tracelanedev/ui";

/**
 * FailoverManager — GWY-52: the workspace's own cross-provider failover
 * (`specs/GWY-52-workspace-failover.md` §4, §8). The gateway owns validation, the
 * owner-only write and the cap; every number is its (`models.length` of `max`).
 */

import { ApiError, apiFetch } from "@/lib/api-fetch";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

interface FailoverState {
	enabled: boolean;
	models: { model: string; provider: string | null }[];
	max: number | null;
	can_edit: boolean;
}

const ENDPOINT = "/api/settings/gateway-failover";
const KEY = ["gateway-failover"];

const REFUSAL: Record<string, string> = {
	unroutable_model: "One of those models does not route to any provider.",
	duplicate_model: "A model is listed twice.",
	model_is_alias:
		"That is one of your aliases — list the real model it points at.",
	failover_cap_reached: "Too many fallback models for your workspace limit.",
	failover_limit_unavailable:
		"The limit could not be read right now. Try again shortly.",
	role_forbidden: "Only a workspace owner can change failover.",
};

const inputClass =
	"w-full rounded border border-line bg-surface px-2 py-1.5 font-mono text-sm text-ink placeholder:text-ink-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-action";
const quiet =
	"rounded border border-line px-2 py-1 text-xs text-ink-2 transition-colors hover:bg-surface-2 disabled:opacity-40";

export function FailoverManager({
	operatorChain,
}: {
	operatorChain: string[];
}) {
	const qc = useQueryClient();
	const { data, error, isLoading, refetch } = useQuery({
		queryKey: KEY,
		queryFn: () => apiFetch<FailoverState>(ENDPOINT),
		staleTime: 30_000,
	});
	const [enabled, setEnabled] = useState(false);
	const [models, setModels] = useState<string[]>([]);
	const [draft, setDraft] = useState("");
	useEffect(() => {
		if (data) {
			setEnabled(data.enabled);
			setModels(data.models.map((m) => m.model));
		}
	}, [data]);

	const save = useMutation({
		mutationFn: (body: { enabled: boolean; models: string[] }) =>
			apiFetch("/api/settings/gateway-failover", {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(body),
			}),
		onSuccess: () => void qc.invalidateQueries({ queryKey: KEY }),
	});

	if (isLoading) {
		return (
			<div
				className="h-16 w-full animate-pulse rounded bg-surface-2"
				aria-busy="true"
			/>
		);
	}
	if (error) {
		const forbidden = error instanceof ApiError && error.status === 403;
		return (
			<div
				className="rounded border border-line p-3 text-sm text-ink-2"
				role="alert"
			>
				{forbidden
					? "Only a workspace owner can view failover settings."
					: `Failover settings could not be loaded${error instanceof ApiError ? ` (HTTP ${error.status})` : ""}.`}{" "}
				{!forbidden && (
					<Button
						variant="bare"
						type="button"
						className={quiet}
						onClick={() => refetch()}
					>
						Retry
					</Button>
				)}
			</div>
		);
	}
	const st = data ?? { enabled: false, models: [], max: null, can_edit: false };
	const edit = st.can_edit;
	const atCap = st.max !== null && models.length >= st.max;
	const dirty =
		enabled !== st.enabled ||
		models.join("\n") !== st.models.map((m) => m.model).join("\n");

	return (
		<div className="space-y-3">
			<label className="flex items-start gap-2 text-sm">
				<input
					type="checkbox"
					checked={enabled}
					disabled={!edit}
					onChange={(e) => setEnabled(e.target.checked)}
					className="mt-0.5"
				/>
				<span>
					Fail over to another provider when the primary errors — for every
					request, no header needed. One call can still opt out with{" "}
					<code className="font-mono">X-Tracelane-Failover: off</code>.
				</span>
			</label>
			<div className="flex items-baseline justify-between">
				<h4 className="font-medium">Fallback models, in order</h4>
				<span className="text-xs text-ink-3" data-testid="failover-count">
					{st.max === null
						? `${models.length} · limit unavailable`
						: `${models.length} of ${st.max}`}
				</span>
			</div>
			{models.length === 0 ? (
				<p className="text-sm text-ink-2">
					Using the default chain
					{operatorChain.length > 0 ? `: ${operatorChain.join(" → ")}` : ""}.
					Add models to use your own instead.
				</p>
			) : (
				<ol className="list-decimal space-y-1 pl-5 text-sm">
					{models.map((m, i) => (
						<li key={m} className="font-mono">
							<span className="break-all">{m}</span>{" "}
							<span className="font-sans text-xs text-ink-3">
								{st.models.find((x) => x.model === m)?.provider ?? ""}
							</span>
							{edit && (
								<span className="ml-2 inline-flex gap-1">
									<Button
										variant="bare"
										type="button"
										className={quiet}
										disabled={i === 0}
										aria-label={`Move ${m} up`}
										onClick={() =>
											setModels((xs) => {
												const n = [...xs];
												[n[i - 1], n[i]] = [n[i] as string, n[i - 1] as string];
												return n;
											})
										}
									>
										↑
									</Button>
									<Button
										variant="bare"
										type="button"
										className={quiet}
										aria-label={`Remove ${m}`}
										onClick={() => setModels((xs) => xs.filter((x) => x !== m))}
									>
										Remove
									</Button>
								</span>
							)}
						</li>
					))}
				</ol>
			)}
			{edit ? (
				<div className="flex flex-wrap items-end gap-2">
					<input
						className={`${inputClass} max-w-xs`}
						placeholder="gpt-4o-mini"
						aria-label="Add a fallback model"
						value={draft}
						onChange={(e) => setDraft(e.target.value)}
					/>
					<Button
						variant="bare"
						type="button"
						className={quiet}
						disabled={!draft.trim() || atCap || st.max === null}
						onClick={() => {
							const m = draft.trim();
							if (m && !models.includes(m)) setModels((xs) => [...xs, m]);
							setDraft("");
						}}
					>
						Add
					</Button>
					<Button
						variant="bare"
						type="button"
						className="rounded bg-action px-3 py-1.5 text-sm text-action-on transition-colors hover:bg-action/90 disabled:opacity-40"
						disabled={!dirty || save.isPending}
						onClick={() => save.mutate({ enabled, models })}
					>
						{save.isPending ? "Saving…" : "Save failover"}
					</Button>
				</div>
			) : (
				<p className="text-sm text-ink-3">
					Only a workspace owner can change failover.
				</p>
			)}
			{save.isError && (
				<p className="text-sm text-danger-ink" role="alert">
					{save.error instanceof ApiError
						? (REFUSAL[save.error.message] ??
							`The gateway refused the change (HTTP ${save.error.status}).`)
						: "The change could not be saved."}
				</p>
			)}
		</div>
	);
}
