"use client";

/**
 * `EVL-02` — start an experiment.
 *
 * ## Why the arms are chosen by ENV, not by a version id
 *
 * The experiment this product exists to run is *"is the candidate better than
 * what is in production?"* — `staging` vs `production` — and the second one is
 * *"is the cheaper model good enough?"*, which is one version against two models.
 * Both are expressible here.
 *
 * A raw version-id picker is NOT, and deliberately: there is no endpoint that
 * lists a prompt's versions with their ids (`GET /v1/prompts` returns counts and
 * the active version NUMBER per env, not ids), so a picker would either need a
 * new gateway route or a fabricated list. Choosing by env resolves through
 * `GET /api/prompts/{name}?env=` — one call per arm, on selection — and the id
 * the gateway then authorizes is one it issued.
 *
 * ## Every refusal is rendered with its own reason
 *
 * The gateway's refusals are typed and each names what to do:
 * `402 workspace_budget_exceeded` (with both dollar figures),
 * `403 role_forbidden` (with the required role), `400 dataset_too_large` (with
 * both counts), `422 dataset_never_frozen`. Collapsing them into "something went
 * wrong" is the exact defect this repo tracks, so the submit handler surfaces the
 * gateway's own `message` and never replaces it with a generic one.
 */

import { Button } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { useState } from "react";

export type DatasetOption = {
	dataset_id: string;
	name: string;
	/** `null` = the count query failed; rendered `—`, never `0`. */
	items: number | null;
};

export type PromptOption = {
	name: string;
	active: { env: string; version_number: number }[];
};

type AssertionKind =
	| "contains"
	| "not_contains"
	| "regex"
	| "json_schema"
	| "exact_match"
	| "max_latency_ms"
	| "max_cost_usd";

/**
 * Which kinds carry a value, and how it is typed on the wire.
 *
 * **`json_valid` is GONE, and removing it here was not optional.** `EVL-23`
 * deleted the variant from the gateway (it decided pass/fail from
 * `serde_json::from_str(..).is_ok()` — parseability alone, the live violation
 * `CLAUDE.md` §21 names), so a body carrying `{"kind":"json_valid"}` now gets a
 * `400`. Leaving the option in this dropdown would have shipped a control that
 * fails only after the user fills the form in.
 *
 * `json_schema` is its replacement and takes the schema as JSON; `{}` accepts
 * anything that parses, which is `json_valid`'s old behaviour stated honestly.
 *
 * **`llm_judge` and `length_bounds` are deliberately NOT here.** A judge needs a
 * rubric selector, a judging-model field and a threshold, and it is entitlement
 * gated (Team+) so this dialog would also need the 403 branch — that is a real
 * control, not a dropdown entry, and it is filed as item 11 scope rather than
 * half-built here. Both are reachable today through
 * `POST /v1/prompts/{name}/evals`.
 */
const ASSERTION_VALUE: Record<AssertionKind, "string" | "number" | "json"> = {
	contains: "string",
	not_contains: "string",
	regex: "string",
	json_schema: "json",
	exact_match: "string",
	max_latency_ms: "number",
	max_cost_usd: "number",
};

type AssertionDraft = { kind: AssertionKind; value: string };
type ArmDraft = { label: string; env: string; model: string };

const MAX_ARMS = 4;

export function NewExperimentDialog({
	datasets,
	prompts,
	/** Why the control is disabled, or `null` when it is not. */
	disabledReason,
}: {
	datasets: DatasetOption[];
	prompts: PromptOption[];
	disabledReason: string | null;
}) {
	const router = useRouter();
	const [open, setOpen] = useState(false);
	const [name, setName] = useState("");
	const [datasetId, setDatasetId] = useState(datasets[0]?.dataset_id ?? "");
	const [promptName, setPromptName] = useState(prompts[0]?.name ?? "");
	const [assertions, setAssertions] = useState<AssertionDraft[]>([
		{ kind: "contains", value: "" },
	]);
	const [arms, setArms] = useState<ArmDraft[]>([
		{ label: "A", env: "production", model: "" },
		{ label: "B", env: "staging", model: "" },
	]);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	if (disabledReason !== null) {
		// DISABLED WITH THE REASON ON IT, never enabled-then-failing. A button that
		// opens a dialog you cannot complete is the dead-button shape.
		return (
			<span className="inline-flex flex-col items-end gap-1">
				<Button disabled>+ New experiment</Button>
				<span className="text-ink-3 text-xs">{disabledReason}</span>
			</span>
		);
	}

	if (!open) {
		return <Button onClick={() => setOpen(true)}>+ New experiment</Button>;
	}

	async function resolveVersion(prompt: string, env: string): Promise<string> {
		const res = await fetch(
			`/api/prompts/${encodeURIComponent(prompt)}?env=${encodeURIComponent(env)}`,
			{ cache: "no-store" },
		);
		if (!res.ok) {
			throw new Error(
				res.status === 404
					? `“${prompt}” has no version routed to ${env}. Promote one first, or pick a different environment for that arm.`
					: `Couldn't resolve the ${env} version of “${prompt}”.`,
			);
		}
		const v = (await res.json()) as { prompt_version_id?: string };
		if (!v.prompt_version_id)
			throw new Error("The gateway returned no version id.");
		return v.prompt_version_id;
	}

	async function submit() {
		setBusy(true);
		setError(null);
		try {
			const resolved = await Promise.all(
				arms.map(async (a) => ({
					label: a.label.trim() || undefined,
					prompt_version_id: await resolveVersion(promptName, a.env),
					model: a.model.trim() || undefined,
				})),
			);
			// TWO ARMS ON THE SAME VERSION AND THE SAME MODEL measure nothing — the
			// two sides would be byte-identical requests. Caught here so the user
			// learns it before a cent is spent, rather than from a diff of zeros.
			const keys = resolved.map(
				(a) => `${a.prompt_version_id}|${a.model ?? ""}`,
			);
			if (new Set(keys).size !== keys.length) {
				throw new Error(
					"Two arms resolve to the same version AND the same model, so they would run identical requests. Change one arm's environment or give it a different model.",
				);
			}
			const body = {
				name: name.trim(),
				prompt_name: promptName,
				dataset_id: datasetId,
				assertions: assertions
					.filter((a) => a.value.trim().length > 0)
					.map((a) => {
						const shape = ASSERTION_VALUE[a.kind];
						if (shape === "number")
							return { kind: a.kind, value: Number(a.value) };
						// `json_schema` carries a SCHEMA, not a value — and a schema
						// that will not parse is refused HERE rather than sent as a
						// string the gateway rejects with a shape error naming
						// nothing the user typed. The message names WHICH scorer,
						// because a bare "Unexpected token }" in a form with four
						// scorers does not tell you which box to look in.
						if (shape === "json") {
							try {
								return { kind: a.kind, schema: JSON.parse(a.value) };
							} catch {
								throw new Error(
									`Scorer ${assertions.indexOf(a) + 1} (json_schema): that is not valid JSON. A schema of {} accepts anything that parses.`,
								);
							}
						}
						return { kind: a.kind, value: a.value };
					}),
				arms: resolved,
			};
			const res = await fetch("/api/experiments", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(body),
			});
			if (!res.ok) {
				// The gateway's own message names the limit, the role or both dollar
				// figures. Surfacing it verbatim is the whole point.
				const j = (await res.json().catch(() => ({}))) as {
					message?: string;
					error?: string;
				};
				throw new Error(
					j.message ?? j.error ?? `The gateway refused with ${res.status}.`,
				);
			}
			const created = (await res.json()) as { experiment_id?: string };
			setOpen(false);
			if (created.experiment_id) {
				router.push(`/experiments/${created.experiment_id}`);
			} else {
				router.refresh();
			}
		} catch (e) {
			setError(
				e instanceof Error ? e.message : "Couldn't start the experiment.",
			);
		} finally {
			setBusy(false);
		}
	}

	const dataset = datasets.find((d) => d.dataset_id === datasetId);

	return (
		<div className="rounded-lg border border-line bg-surface-2 p-4">
			<h2 className="t-h2 mb-1">New experiment</h2>
			{/* Stated UP FRONT, because it is what makes the wait explicable and it
			    is the safety property the whole design rests on. */}
			<p className="mb-3 text-ink-3 text-xs">
				Arms run one after another, not in parallel — that is what makes the
				progress count true and the budget cap exact. Estimated: {arms.length}{" "}
				arm{arms.length === 1 ? "" : "s"} × {dataset?.items ?? "—"} item
				{dataset?.items === 1 ? "" : "s"} provider calls.
			</p>

			<label className="mb-2 block text-sm">
				<span className="mb-1 block text-ink-3">Name</span>
				<input
					className="w-full rounded-md border border-line bg-surface px-2 py-1"
					value={name}
					onChange={(e) => setName(e.target.value)}
					placeholder="tone-v4-vs-v3"
				/>
			</label>

			<label className="mb-2 block text-sm">
				<span className="mb-1 block text-ink-3">Dataset</span>
				<select
					className="w-full rounded-md border border-line bg-surface px-2 py-1"
					value={datasetId}
					onChange={(e) => setDatasetId(e.target.value)}
				>
					{datasets.map((d) => (
						<option key={d.dataset_id} value={d.dataset_id}>
							{d.name} ({d.items ?? "—"} items)
						</option>
					))}
				</select>
			</label>

			<label className="mb-3 block text-sm">
				<span className="mb-1 block text-ink-3">Prompt</span>
				<select
					className="w-full rounded-md border border-line bg-surface px-2 py-1"
					value={promptName}
					onChange={(e) => setPromptName(e.target.value)}
				>
					{prompts.map((p) => (
						<option key={p.name} value={p.name}>
							{p.name}
							{p.active.length > 0
								? ` (${p.active.map((a) => `${a.env} v${a.version_number}`).join(", ")})`
								: ""}
						</option>
					))}
				</select>
			</label>

			<div className="mb-3">
				<div className="mb-1 text-ink-3 text-sm">Arms</div>
				{arms.map((a, i) => (
					// biome-ignore lint/suspicious/noArrayIndexKey: arms are positional
					<div key={i} className="mb-2 flex flex-wrap items-center gap-2">
						<input
							className="w-16 rounded-md border border-line bg-surface px-2 py-1 text-sm"
							value={a.label}
							aria-label={`Arm ${i + 1} label`}
							onChange={(e) =>
								setArms(
									arms.map((x, j) =>
										j === i ? { ...x, label: e.target.value } : x,
									),
								)
							}
						/>
						<select
							className="rounded-md border border-line bg-surface px-2 py-1 text-sm"
							value={a.env}
							aria-label={`Arm ${i + 1} environment`}
							onChange={(e) =>
								setArms(
									arms.map((x, j) =>
										j === i ? { ...x, env: e.target.value } : x,
									),
								)
							}
						>
							<option value="production">production</option>
							<option value="staging">staging</option>
						</select>
						<input
							className="min-w-[12rem] flex-1 rounded-md border border-line bg-surface px-2 py-1 text-sm"
							value={a.model}
							aria-label={`Arm ${i + 1} model override`}
							placeholder="model (blank = the version's pin)"
							onChange={(e) =>
								setArms(
									arms.map((x, j) =>
										j === i ? { ...x, model: e.target.value } : x,
									),
								)
							}
						/>
						{arms.length > 2 && (
							<button
								type="button"
								className="text-sm underline"
								onClick={() => setArms(arms.filter((_, j) => j !== i))}
							>
								remove
							</button>
						)}
					</div>
				))}
				{/* The control DISABLES at the ceiling and says what the ceiling is. */}
				<button
					type="button"
					className="text-sm underline disabled:no-underline disabled:opacity-50"
					disabled={arms.length >= MAX_ARMS}
					onClick={() =>
						setArms([
							...arms,
							{
								label: String.fromCharCode(65 + arms.length),
								env: "staging",
								model: "",
							},
						])
					}
				>
					{arms.length >= MAX_ARMS
						? `Up to ${MAX_ARMS} arms per experiment.`
						: "+ Add arm"}
				</button>
			</div>

			<div className="mb-3">
				<div className="mb-1 text-ink-3 text-sm">
					Scorers — the SAME for every arm, or the two sides are not comparable
				</div>
				{assertions.map((a, i) => (
					// biome-ignore lint/suspicious/noArrayIndexKey: scorers are positional
					<div key={i} className="mb-2 flex flex-wrap items-center gap-2">
						<select
							className="rounded-md border border-line bg-surface px-2 py-1 text-sm"
							value={a.kind}
							aria-label={`Scorer ${i + 1} kind`}
							onChange={(e) =>
								setAssertions(
									assertions.map((x, j) =>
										j === i
											? { ...x, kind: e.target.value as AssertionKind }
											: x,
									),
								)
							}
						>
							{Object.keys(ASSERTION_VALUE).map((k) => (
								<option key={k} value={k}>
									{k}
								</option>
							))}
						</select>
						<input
							className="min-w-[12rem] flex-1 rounded-md border border-line bg-surface px-2 py-1 text-sm"
							value={a.value}
							aria-label={`Scorer ${i + 1} value`}
							inputMode={
								ASSERTION_VALUE[a.kind] === "number" ? "decimal" : "text"
							}
							placeholder={
								ASSERTION_VALUE[a.kind] === "json"
									? '{"type":"object","required":["order"]}'
									: undefined
							}
							onChange={(e) =>
								setAssertions(
									assertions.map((x, j) =>
										j === i ? { ...x, value: e.target.value } : x,
									),
								)
							}
						/>
						{assertions.length > 1 && (
							<button
								type="button"
								className="text-sm underline"
								onClick={() =>
									setAssertions(assertions.filter((_, j) => j !== i))
								}
							>
								remove
							</button>
						)}
					</div>
				))}
				<button
					type="button"
					className="text-sm underline"
					onClick={() =>
						setAssertions([...assertions, { kind: "contains", value: "" }])
					}
				>
					+ Add scorer
				</button>
			</div>

			{error && (
				<p className="mb-3 rounded-md border border-line bg-surface p-2 text-sm">
					{error}
				</p>
			)}

			<div className="flex gap-2">
				<Button onClick={submit} disabled={busy || !name.trim() || !datasetId}>
					{busy ? "Starting…" : "Run experiment"}
				</Button>
				<Button variant="ghost" onClick={() => setOpen(false)} disabled={busy}>
					Cancel
				</Button>
			</div>
		</div>
	);
}
