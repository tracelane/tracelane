"use client";

/**
 * `EVL-29` — the "New queue" dialog.
 *
 * **This closes a founder-reported gap, not a new design.** The button this file
 * builds was already specified — `specs/EVL-29-golden-case-authoring-queues.md:400`
 * (the limits table) names "**Create queue** disables at 50 with…" — and `/review`
 * shipped 2026-08-29 with the read side only: the empty-state copy even said
 * "+ New queue" in the wireframe (spec §8) and no such control existed anywhere in
 * `apps/web` (`grep -rn "create.*queue|new queue|CreateQueue" apps/web` = 0 hits
 * outside tests). The API was always end to end —
 * `POST /v1/annotation-queues` (`crates/gateway/src/annotation_routes.rs:1335`,
 * `CreateQueueBody` at `:1323`) and the Next.js proxy
 * (`apps/web/app/api/annotation-queues/route.ts`) forward the body VERBATIM — so a
 * customer's only path to a queue was `curl`.
 *
 * ## Why the disabled state is load-bearing, not a nicety
 *
 * `annotation_queues.default_dataset_id` is NOT NULL (R222). A queue that names no
 * target dataset cannot exist, so `/review/page.tsx` already refuses to offer a
 * create control it knows will fail when the tenant has zero datasets — this
 * dialog inherits that rule rather than re-deciding it: `disabledReason` is
 * computed once, server-side, in `page.tsx`, and this component ALSO refuses to
 * open with an empty dataset list even if a caller forgets to pass a reason
 * (`effectiveDisabledReason` below), because "this page must not offer a create
 * button it knows will fail" is the rule the founder finding was about.
 *
 * ## What is mirrored from the gateway, and why it is not the boundary
 *
 * The constants below (`MAX_QUEUE_NAME_LEN`, `MAX_QUEUE_WINDOW_HOURS`, …) are
 * copied from `crates/gateway/src/annotation_routes.rs` so the form can show a cap
 * BEFORE a round trip, not to replace server validation. Every one of them is
 * re-checked by the gateway (`validate_window`, `validate_rubric_definition`,
 * `create_queue_handler`), and every submit error path in this file renders the
 * gateway's own `{error, field, message}` — this file's own pre-checks exist only
 * to fail fast with the SAME wording the server would use, never a different one.
 */

import type {
	QueueSource as GatewayQueueSource,
	RubricFieldType as GatewayRubricFieldType,
} from "@/app/api/annotation-queues/shared";
import { Modal } from "@/components/Modal";
import { Button } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { useEffect, useId, useState } from "react";

// ─────────────────────────── constants mirrored from the gateway ───────────
// Every value here has a citation. If the cited line moves, re-read it — do not
// assume the number still holds (`CLAUDE.md` §16).

/** `crates/gateway/src/annotation_routes.rs:646` */
export const MAX_QUEUE_NAME_LEN = 200;
/** `crates/gateway/src/annotation_routes.rs:664` */
export const DEFAULT_QUEUE_WINDOW_HOURS = 168;
/** `crates/gateway/src/annotation_routes.rs:685` — the content snapshot's TTL. */
export const SNAPSHOT_TTL_DAYS = 30;
/**
 * `crates/gateway/src/annotation_routes.rs:679` — `24 * SNAPSHOT_TTL_DAYS`,
 * tied to the snapshot's own lifetime (R228), NOT to `spans`' 365-day backstop
 * TTL. A queue cannot reach further back than the content behind it survives.
 */
export const MAX_QUEUE_WINDOW_HOURS = 24 * SNAPSHOT_TTL_DAYS;
/** `crates/gateway/src/annotation_routes.rs:648` */
export const MAX_RUBRIC_FIELDS = 20;
/** `crates/gateway/src/annotation_routes.rs:650` */
export const MAX_RUBRIC_KEY_LEN = 64;
/** `crates/gateway/src/annotation_routes.rs:652` */
export const MAX_RUBRIC_OPTIONS = 32;

export type RubricFieldType = GatewayRubricFieldType;
export type QueueSourceKind = GatewayQueueSource["kind"];

/** `crates/gateway/src/annotation_routes.rs:713-719` — the closed vocabulary. */
export const RUBRIC_TYPE_LABEL: Record<RubricFieldType, string> = {
	verdict: "Verdict (short label)",
	score: "Score (bounded number)",
	choice: "Choice (pick one)",
	text: "Text (free-form)",
	boolean: "Yes / no",
};
const RUBRIC_TYPES = Object.keys(RUBRIC_TYPE_LABEL) as RubricFieldType[];

/** `crates/gateway/src/annotation_routes.rs:765-779` — the closed source union. */
export const SOURCE_LABEL: Record<QueueSourceKind, string> = {
	online_eval_score: "Low online-eval judge score",
	trace_error: "Errored traces",
	needs_review: "Flagged needs_review",
};
const SOURCE_KINDS = Object.keys(SOURCE_LABEL) as QueueSourceKind[];

export type DatasetOption = { dataset_id: string; name: string };

export type RubricFieldDraft = {
	key: string;
	label: string;
	type: RubricFieldType;
	required: boolean;
	/** comma-separated; only meaningful when `type === "choice"`. */
	options: string;
	/** only meaningful when `type === "score"`. */
	min: string;
	max: string;
};

export function emptyRubricField(): RubricFieldDraft {
	return {
		key: "",
		label: "",
		type: "text",
		required: true,
		options: "",
		min: "",
		max: "",
	};
}

export type NewQueueFormState = {
	name: string;
	sourceKind: QueueSourceKind;
	maxScore: string;
	sourceRubric: string;
	windowHours: string;
	datasetId: string;
	rubric: RubricFieldDraft[];
	referenceKey: string;
};

export function initialFormState(defaultDatasetId: string): NewQueueFormState {
	return {
		name: "",
		sourceKind: "online_eval_score",
		maxScore: "0.5",
		sourceRubric: "",
		windowHours: String(DEFAULT_QUEUE_WINDOW_HOURS),
		datasetId: defaultDatasetId,
		rubric: [emptyRubricField()],
		referenceKey: "",
	};
}

/** Swap two rubric rows. Out-of-range or a no-op move returns the input unchanged. */
export function moveRubricField(
	fields: RubricFieldDraft[],
	from: number,
	to: number,
): RubricFieldDraft[] {
	if (
		to < 0 ||
		to >= fields.length ||
		from === to ||
		from < 0 ||
		from >= fields.length
	) {
		return fields;
	}
	const copy = [...fields];
	const item = copy[from];
	if (item === undefined) return fields;
	copy.splice(from, 1);
	copy.splice(to, 0, item);
	return copy;
}

/**
 * The exact wire shape POSTed to `/api/annotation-queues` — snake_case, and ONLY
 * these keys. The gateway's `CreateQueueBody` is `#[serde(deny_unknown_fields)]`
 * (`crates/gateway/src/annotation_routes.rs:1321-1333`), so one extra key here is
 * a 400 the user did nothing to deserve.
 */
export type CreateQueueRequestBody = {
	name: string;
	filter: {
		source: GatewayQueueSource;
		window_hours: number;
	};
	rubric: Array<{
		key: string;
		label: string;
		type: RubricFieldType;
		required: boolean;
		options?: string[];
		min?: number;
		max?: number;
	}>;
	default_dataset_id: string;
	expected_output_field: string;
};

/** A refusal, client- or server-origin, in the SAME vocabulary either way — see
 * `locationForError` below, which is what lets one render path handle both. */
export type SubmitError = { code: string; field?: string; message: string };

export type BuildResult =
	| { ok: true; body: CreateQueueRequestBody }
	| { ok: false; error: SubmitError };

/**
 * Pure: form state → the exact wire body, or the first refusal — in the gateway's
 * own error vocabulary, so `locationForError` does not need a second dialect.
 * Mirrors, in order, `create_queue_handler` (`crates/gateway/src/annotation_routes.rs:1335`)
 * and `validate_rubric_definition` (`:871`).
 */
export function buildCreateQueuePayload(form: NewQueueFormState): BuildResult {
	const name = form.name.trim();
	if (!name || name.length > MAX_QUEUE_NAME_LEN) {
		return {
			ok: false,
			error: {
				code: "invalid_name",
				field: "name",
				message: `A queue name must be 1..=${MAX_QUEUE_NAME_LEN} characters.`,
			},
		};
	}
	if (!form.datasetId) {
		return {
			ok: false,
			error: {
				code: "dataset_required",
				field: "default_dataset_id",
				message: "Choose a target dataset.",
			},
		};
	}

	const parsedWindow = Number.parseInt(form.windowHours, 10);
	if (!Number.isFinite(parsedWindow) || parsedWindow < 1) {
		return {
			ok: false,
			error: {
				code: "window_out_of_range",
				message: `\`window_hours\` must be between 1 and ${MAX_QUEUE_WINDOW_HOURS} (${SNAPSHOT_TTL_DAYS} days — the content snapshot's lifetime).`,
			},
		};
	}
	// Clamped, not rejected: the input's own `max` attribute already keeps a user
	// from TYPING past this bound, so coercing here can never produce a queue
	// whose window differs from the number shown on screen when they hit Save.
	const windowHours = Math.min(parsedWindow, MAX_QUEUE_WINDOW_HOURS);

	if (form.rubric.length === 0) {
		return {
			ok: false,
			error: {
				code: "rubric_empty",
				message:
					"A queue needs at least one rubric field — a review with nothing to answer cannot produce a reference.",
			},
		};
	}
	if (form.rubric.length > MAX_RUBRIC_FIELDS) {
		return {
			ok: false,
			error: {
				code: "rubric_too_large",
				message: `A rubric may hold at most ${MAX_RUBRIC_FIELDS} fields.`,
			},
		};
	}

	const seenKeys = new Set<string>();
	const rubric: CreateQueueRequestBody["rubric"] = [];
	for (const f of form.rubric) {
		const key = f.key.trim();
		if (!key || key.length > MAX_RUBRIC_KEY_LEN) {
			return {
				ok: false,
				error: {
					code: "rubric_bad_key",
					field: key,
					message: `A rubric field key must be 1..=${MAX_RUBRIC_KEY_LEN} characters.`,
				},
			};
		}
		if (seenKeys.has(key)) {
			return {
				ok: false,
				error: {
					code: "rubric_duplicate_key",
					field: key,
					message:
						"Two rubric fields share a key; an answer would be ambiguous.",
				},
			};
		}
		seenKeys.add(key);

		const entry: CreateQueueRequestBody["rubric"][number] = {
			key,
			label: f.label.trim() || key,
			type: f.type,
			required: f.required,
		};
		if (f.type === "choice") {
			const options = f.options
				.split(",")
				.map((o) => o.trim())
				.filter((o) => o.length > 0);
			if (options.length === 0) {
				return {
					ok: false,
					error: {
						code: "rubric_choice_needs_options",
						field: key,
						message:
							"A `choice` field must list its options; without them nothing is answerable.",
					},
				};
			}
			if (options.length > MAX_RUBRIC_OPTIONS) {
				return {
					ok: false,
					error: {
						code: "rubric_too_many_options",
						field: key,
						message: `At most ${MAX_RUBRIC_OPTIONS} options.`,
					},
				};
			}
			entry.options = options;
		}
		if (f.type === "score") {
			const min = Number.parseFloat(f.min);
			const max = Number.parseFloat(f.max);
			if (!Number.isFinite(min) || !Number.isFinite(max) || min >= max) {
				return {
					ok: false,
					error: {
						code: "rubric_score_bad_bounds",
						field: key,
						message:
							"A `score` field must declare `min` and `max`, with `min` strictly less than `max`.",
					},
				};
			}
			entry.min = min;
			entry.max = max;
		}
		rubric.push(entry);
	}

	const referenceKey = form.referenceKey.trim();
	const referenceField = rubric.find((f) => f.key === referenceKey);
	if (!referenceField) {
		return {
			ok: false,
			error: {
				code: "expected_output_field_unknown",
				field: referenceKey,
				message:
					"Choose which question's answer becomes the graded case's expected output.",
			},
		};
	}
	if (referenceField.type === "boolean") {
		return {
			ok: false,
			error: {
				code: "expected_output_field_not_usable",
				field: referenceKey,
				message:
					'A yes/no field cannot be the reference: an expected_output of "true" is a scorer comparing prose against a word that means nothing.',
			},
		};
	}
	if (!referenceField.required) {
		return {
			ok: false,
			error: {
				code: "expected_output_field_optional",
				field: referenceKey,
				message: "The field naming the reference must be required.",
			},
		};
	}

	let source: GatewayQueueSource;
	if (form.sourceKind === "online_eval_score") {
		const maxScore = Number.parseFloat(form.maxScore);
		if (!Number.isFinite(maxScore)) {
			return {
				ok: false,
				error: {
					code: "max_score_invalid",
					field: "max_score",
					message: "Enter the score ceiling as a number.",
				},
			};
		}
		const sourceRubric = form.sourceRubric.trim();
		source = sourceRubric
			? { kind: "online_eval_score", max_score: maxScore, rubric: sourceRubric }
			: { kind: "online_eval_score", max_score: maxScore };
	} else if (form.sourceKind === "trace_error") {
		source = { kind: "trace_error" };
	} else {
		source = { kind: "needs_review" };
	}

	return {
		ok: true,
		body: {
			name,
			filter: { source, window_hours: windowHours },
			rubric,
			default_dataset_id: form.datasetId,
			expected_output_field: referenceKey,
		},
	};
}

/** Where a `SubmitError` renders — one control, or the banner when none fits. */
export type ErrorLocation =
	| "name"
	| "dataset"
	| "reference"
	| "window"
	| "max_score"
	| { rubricIndex: number }
	| "banner";

const CODE_LOCATION: Record<string, ErrorLocation> = {
	invalid_name: "name",
	queue_name_taken: "name",
	dataset_required: "dataset",
	dataset_not_found: "dataset",
	expected_output_field_unknown: "reference",
	expected_output_field_not_usable: "reference",
	expected_output_field_optional: "reference",
	window_out_of_range: "window",
	max_score_invalid: "max_score",
};
const RUBRIC_ROW_CODES = new Set([
	"rubric_bad_key",
	"rubric_duplicate_key",
	"rubric_choice_needs_options",
	"rubric_too_many_options",
	"rubric_score_needs_bounds",
	"rubric_score_bad_bounds",
]);

export function locationForError(
	err: SubmitError,
	rubric: RubricFieldDraft[],
): ErrorLocation {
	if (RUBRIC_ROW_CODES.has(err.code)) {
		if (err.field !== undefined) {
			const idx = rubric.findIndex((r) => r.key.trim() === err.field);
			if (idx >= 0) return { rubricIndex: idx };
		}
		return "banner";
	}
	return CODE_LOCATION[err.code] ?? "banner";
}

/** 5xx / network failures never carry a useful field — always the banner, and
 * always retryable, because nothing about the FORM was wrong. */
const RETRYABLE_CODES = new Set(["gateway_unreachable", "network_error"]);

async function submitCreateQueue(
	body: CreateQueueRequestBody,
): Promise<{ ok: true } | { ok: false; error: SubmitError }> {
	let res: Response;
	try {
		res = await fetch("/api/annotation-queues", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
	} catch {
		return {
			ok: false,
			error: {
				code: "network_error",
				message: "Could not reach the gateway — your queue was not created.",
			},
		};
	}
	if (res.status === 201) return { ok: true };

	let parsed: { error?: string; field?: string; message?: string } = {};
	try {
		parsed = (await res.json()) as typeof parsed;
	} catch {
		// no body at all — treat like any other unreadable 5xx below
	}
	// `apps/web/app/api/annotation-queues/shared.ts`'s `passthrough` collapses
	// EVERY >=500 (the gateway's own 502/503 refusals included — `datasets_
	// unavailable`, `dataset_lookup_failed`, `store_failed`) into
	// `{error:"unavailable", reason:"gateway_unreachable"}`. So any 5xx, or a
	// body with no `error` at all, is the generic "could not reach it" case —
	// never a field-scoped one, because at that point nothing is known about
	// which field was at fault.
	if (res.status >= 500 || !parsed.error) {
		return {
			ok: false,
			error: {
				code: "gateway_unreachable",
				message: "Could not reach the gateway — your queue was not created.",
			},
		};
	}
	return {
		ok: false,
		error: {
			code: parsed.error,
			field: parsed.field,
			message: parsed.message ?? `The gateway refused with ${res.status}.`,
		},
	};
}

function fieldClass(invalid: boolean): string {
	return [
		"w-full rounded-md border bg-surface px-2 py-1 text-sm",
		invalid ? "border-danger" : "border-line",
	].join(" ");
}

export function NewQueueDialog({
	datasets,
	disabledReason,
	label = "+ New queue",
	size = "md",
}: {
	datasets: DatasetOption[];
	/** Computed by the page (`/review`), which knows the tenant's real dataset and
	 * cap state. `ReactNode` so the caller can embed a link. */
	disabledReason: ReactNode | null;
	label?: string;
	size?: "sm" | "md" | "lg";
}) {
	const router = useRouter();
	const baseId = useId();
	const [open, setOpen] = useState(false);
	const [form, setForm] = useState<NewQueueFormState>(() =>
		initialFormState(datasets[0]?.dataset_id ?? ""),
	);
	const [busy, setBusy] = useState(false);
	const [submitError, setSubmitError] = useState<SubmitError | null>(null);

	// Defence in depth: this page's own rule is "never offer a create button that
	// KNOWS it will fail" (R222 — a queue with no target dataset cannot exist).
	// The caller computes the real reason from server data; if it forgets to and
	// datasets is empty anyway, this still refuses to render an enabled control.
	const effectiveDisabledReason =
		disabledReason ??
		(datasets.length === 0 ? "Create a dataset first." : null);

	// Keep the reference-field selection valid as the rubric changes underneath
	// it — never leave a `<select>` pointing at an option that no longer exists.
	const eligibleReference = form.rubric.filter(
		(f) => f.required && f.type !== "boolean" && f.key.trim().length > 0,
	);
	const eligibleReferenceKeys = eligibleReference
		.map((f) => f.key.trim())
		.join(" ");
	// Intentionally keyed on the eligible-key SET (eligibleReferenceKeys), not on
	// eligibleReference or form.referenceKey — re-deriving on every keystroke of a
	// field that is not currently the reference would fight the user's typing.
	// biome-ignore lint/correctness/useExhaustiveDependencies: see comment above
	useEffect(() => {
		if (eligibleReference.some((f) => f.key.trim() === form.referenceKey))
			return;
		setForm((prev) => ({
			...prev,
			referenceKey: eligibleReference[0]?.key.trim() ?? "",
		}));
	}, [eligibleReferenceKeys]);

	if (effectiveDisabledReason !== null) {
		return (
			<span className="inline-flex flex-col items-end gap-1">
				<Button
					type="button"
					variant="primary"
					size={size}
					disabled
					data-testid="nq-trigger"
				>
					{label}
				</Button>
				<span
					className="max-w-[240px] text-right text-ink-3 text-xs"
					data-testid="nq-disabled-reason"
				>
					{effectiveDisabledReason}
				</span>
			</span>
		);
	}

	if (!open) {
		return (
			<Button
				type="button"
				variant="primary"
				size={size}
				data-testid="nq-trigger"
				onClick={() => {
					setForm(initialFormState(datasets[0]?.dataset_id ?? ""));
					setSubmitError(null);
					setOpen(true);
				}}
			>
				{label}
			</Button>
		);
	}

	async function submit() {
		const result = buildCreateQueuePayload(form);
		if (!result.ok) {
			setSubmitError(result.error);
			return;
		}
		setBusy(true);
		setSubmitError(null);
		const outcome = await submitCreateQueue(result.body);
		setBusy(false);
		if (!outcome.ok) {
			setSubmitError(outcome.error);
			return;
		}
		setOpen(false);
		router.refresh();
	}

	const loc = submitError ? locationForError(submitError, form.rubric) : null;
	const errAt = (target: ErrorLocation): string | undefined =>
		loc !== null &&
		submitError !== null &&
		(typeof target === "object" && typeof loc === "object"
			? target.rubricIndex === loc.rubricIndex
			: target === loc)
			? submitError.message
			: undefined;

	const nameError = errAt("name");
	const datasetError = errAt("dataset");
	const referenceError = errAt("reference");
	const windowError = errAt("window");
	const maxScoreError = errAt("max_score");
	const bannerError =
		loc === "banner" && submitError ? submitError.message : undefined;
	const retryable =
		submitError !== null && RETRYABLE_CODES.has(submitError.code);

	const selectedDataset = datasets.find((d) => d.dataset_id === form.datasetId);
	const sourceSummary =
		form.sourceKind === "online_eval_score"
			? `Judge score ≤ ${form.maxScore || "?"}${form.sourceRubric.trim() ? ` (${form.sourceRubric.trim()})` : ""}`
			: SOURCE_LABEL[form.sourceKind];
	const eligibleReferenceCount = eligibleReference.length;

	return (
		<Modal
			title="New review queue"
			description="A saved filter that routes matching traces to a human reviewer."
			onClose={() => !busy && setOpen(false)}
			dismissable={!busy}
			width="lg"
		>
			<div className="space-y-4">
				{bannerError && (
					<div className="rounded-md border border-danger bg-danger-soft p-2">
						<p
							role="alert"
							data-testid="nq-banner-error"
							className="text-danger-ink text-sm"
						>
							{bannerError}
						</p>
						{retryable && (
							<Button
								type="button"
								variant="ghost"
								size="sm"
								className="mt-1"
								onClick={submit}
							>
								Retry
							</Button>
						)}
					</div>
				)}

				<label className="block text-sm" htmlFor={`${baseId}-name`}>
					<span className="mb-1 flex items-center justify-between text-ink-3">
						<span>Name</span>
						<span className="text-2xs text-ink-3">
							{form.name.length}/{MAX_QUEUE_NAME_LEN}
						</span>
					</span>
					<input
						id={`${baseId}-name`}
						data-testid="nq-name-input"
						className={fieldClass(!!nameError)}
						value={form.name}
						maxLength={MAX_QUEUE_NAME_LEN}
						aria-invalid={!!nameError}
						aria-describedby={nameError ? `${baseId}-name-err` : undefined}
						onChange={(e) => setForm({ ...form, name: e.target.value })}
						placeholder="Low-score support replies"
					/>
					{nameError && (
						<p
							id={`${baseId}-name-err`}
							role="alert"
							data-testid="nq-name-error"
							className="mt-1 text-danger-ink text-xs"
						>
							{nameError}
						</p>
					)}
				</label>

				<div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
					<label className="block text-sm" htmlFor={`${baseId}-source`}>
						<span className="mb-1 block text-ink-3">Source</span>
						<select
							id={`${baseId}-source`}
							className={fieldClass(false)}
							value={form.sourceKind}
							onChange={(e) =>
								setForm({
									...form,
									sourceKind: e.target.value as QueueSourceKind,
								})
							}
						>
							{SOURCE_KINDS.map((k) => (
								<option key={k} value={k}>
									{SOURCE_LABEL[k]}
								</option>
							))}
						</select>
					</label>

					<label className="block text-sm" htmlFor={`${baseId}-window`}>
						<span className="mb-1 block text-ink-3">Window (hours)</span>
						<input
							id={`${baseId}-window`}
							data-testid="nq-window-input"
							type="number"
							min={1}
							max={MAX_QUEUE_WINDOW_HOURS}
							className={fieldClass(!!windowError)}
							value={form.windowHours}
							aria-invalid={!!windowError}
							aria-describedby={`${baseId}-window-hint`}
							onChange={(e) =>
								setForm({ ...form, windowHours: e.target.value })
							}
						/>
						<p
							id={`${baseId}-window-hint`}
							className="mt-1 text-2xs text-ink-3"
						>
							Capped at {MAX_QUEUE_WINDOW_HOURS}h ({SNAPSHOT_TTL_DAYS} days) — a
							reviewed trace's content snapshot does not survive longer than
							that, so a wider window could point at content already gone.
						</p>
						{windowError && (
							<p role="alert" className="mt-1 text-danger-ink text-xs">
								{windowError}
							</p>
						)}
					</label>
				</div>

				{form.sourceKind === "online_eval_score" && (
					<div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
						<label className="block text-sm" htmlFor={`${baseId}-max-score`}>
							<span className="mb-1 block text-ink-3">Score ceiling</span>
							<input
								id={`${baseId}-max-score`}
								data-testid="nq-max-score-input"
								type="number"
								step="0.01"
								className={fieldClass(!!maxScoreError)}
								value={form.maxScore}
								aria-invalid={!!maxScoreError}
								onChange={(e) => setForm({ ...form, maxScore: e.target.value })}
								placeholder="0.5"
							/>
							<p className="mt-1 text-2xs text-ink-3">
								A trace whose most recent judge score is at or below this
								becomes a candidate.
							</p>
							{maxScoreError && (
								<p role="alert" className="mt-1 text-danger-ink text-xs">
									{maxScoreError}
								</p>
							)}
						</label>
						<label
							className="block text-sm"
							htmlFor={`${baseId}-source-rubric`}
						>
							<span className="mb-1 block text-ink-3">
								Only from eval rubric (optional)
							</span>
							<input
								id={`${baseId}-source-rubric`}
								className={fieldClass(false)}
								value={form.sourceRubric}
								onChange={(e) =>
									setForm({ ...form, sourceRubric: e.target.value })
								}
								placeholder="helpfulness"
							/>
							<p className="mt-1 text-2xs text-ink-3">
								Leave blank to match a low score from any online-eval rubric.
							</p>
						</label>
					</div>
				)}

				<label className="block text-sm" htmlFor={`${baseId}-dataset`}>
					<span className="mb-1 block text-ink-3">Target dataset</span>
					<select
						id={`${baseId}-dataset`}
						data-testid="nq-dataset-select"
						className={fieldClass(!!datasetError)}
						value={form.datasetId}
						aria-invalid={!!datasetError}
						aria-describedby={
							datasetError ? `${baseId}-dataset-err` : undefined
						}
						onChange={(e) => setForm({ ...form, datasetId: e.target.value })}
					>
						{datasets.map((d) => (
							<option key={d.dataset_id} value={d.dataset_id}>
								{d.name}
							</option>
						))}
					</select>
					<p className="mt-1 text-2xs text-ink-3">
						Every review through this queue adds a graded case here (R222).
					</p>
					{datasetError && (
						<p
							id={`${baseId}-dataset-err`}
							role="alert"
							className="mt-1 text-danger-ink text-xs"
						>
							{datasetError}
						</p>
					)}
				</label>

				<fieldset className="space-y-2 rounded-md border border-line p-3">
					<legend className="px-1 text-ink-3 text-sm">
						Rubric — what the reviewer answers
					</legend>
					{form.rubric.map((f, i) => {
						const rowError =
							loc !== null && typeof loc === "object" && loc.rubricIndex === i
								? submitError?.message
								: undefined;
						return (
							<div
								// biome-ignore lint/suspicious/noArrayIndexKey: rubric fields are positional, same pattern as NewExperimentDialog's arms/scorers
								key={i}
								className="space-y-1.5 rounded-md border border-line/60 p-2"
							>
								<div className="flex flex-wrap items-center gap-2">
									<input
										className={`${fieldClass(!!rowError)} w-32`}
										value={f.key}
										aria-label={`Rubric field ${i + 1} key`}
										aria-invalid={!!rowError}
										placeholder="key (e.g. severity)"
										onChange={(e) =>
											setForm({
												...form,
												rubric: form.rubric.map((x, j) =>
													j === i ? { ...x, key: e.target.value } : x,
												),
											})
										}
									/>
									<input
										className={`${fieldClass(false)} min-w-[10rem] flex-1`}
										value={f.label}
										aria-label={`Rubric field ${i + 1} label`}
										placeholder="label shown to the reviewer"
										onChange={(e) =>
											setForm({
												...form,
												rubric: form.rubric.map((x, j) =>
													j === i ? { ...x, label: e.target.value } : x,
												),
											})
										}
									/>
									<select
										className={fieldClass(false)}
										value={f.type}
										aria-label={`Rubric field ${i + 1} type`}
										onChange={(e) =>
											setForm({
												...form,
												rubric: form.rubric.map((x, j) =>
													j === i
														? { ...x, type: e.target.value as RubricFieldType }
														: x,
												),
											})
										}
									>
										{RUBRIC_TYPES.map((t) => (
											<option key={t} value={t}>
												{RUBRIC_TYPE_LABEL[t]}
											</option>
										))}
									</select>
									<label className="flex items-center gap-1 text-ink-3 text-xs">
										<input
											type="checkbox"
											checked={f.required}
											aria-label={`Rubric field ${i + 1} required`}
											onChange={(e) =>
												setForm({
													...form,
													rubric: form.rubric.map((x, j) =>
														j === i ? { ...x, required: e.target.checked } : x,
													),
												})
											}
										/>
										required
									</label>
									<div className="flex items-center gap-1">
										<button
											type="button"
											className="text-xs underline disabled:no-underline disabled:opacity-40"
											disabled={i === 0}
											aria-label={`Move rubric field ${i + 1} up`}
											onClick={() =>
												setForm({
													...form,
													rubric: moveRubricField(form.rubric, i, i - 1),
												})
											}
										>
											↑
										</button>
										<button
											type="button"
											className="text-xs underline disabled:no-underline disabled:opacity-40"
											disabled={i === form.rubric.length - 1}
											aria-label={`Move rubric field ${i + 1} down`}
											onClick={() =>
												setForm({
													...form,
													rubric: moveRubricField(form.rubric, i, i + 1),
												})
											}
										>
											↓
										</button>
										<button
											type="button"
											className="text-xs underline disabled:no-underline disabled:opacity-40"
											disabled={form.rubric.length <= 1}
											onClick={() =>
												setForm({
													...form,
													rubric: form.rubric.filter((_, j) => j !== i),
												})
											}
										>
											remove
										</button>
									</div>
								</div>
								{f.type === "choice" && (
									<input
										className={fieldClass(false)}
										value={f.options}
										aria-label={`Rubric field ${i + 1} options`}
										placeholder="options, comma separated (hallucination, wrong_units, other)"
										onChange={(e) =>
											setForm({
												...form,
												rubric: form.rubric.map((x, j) =>
													j === i ? { ...x, options: e.target.value } : x,
												),
											})
										}
									/>
								)}
								{f.type === "score" && (
									<div className="flex items-center gap-2">
										<input
											className={`${fieldClass(false)} w-24`}
											type="number"
											value={f.min}
											aria-label={`Rubric field ${i + 1} minimum`}
											placeholder="min"
											onChange={(e) =>
												setForm({
													...form,
													rubric: form.rubric.map((x, j) =>
														j === i ? { ...x, min: e.target.value } : x,
													),
												})
											}
										/>
										<span className="text-ink-3 text-xs">to</span>
										<input
											className={`${fieldClass(false)} w-24`}
											type="number"
											value={f.max}
											aria-label={`Rubric field ${i + 1} maximum`}
											placeholder="max"
											onChange={(e) =>
												setForm({
													...form,
													rubric: form.rubric.map((x, j) =>
														j === i ? { ...x, max: e.target.value } : x,
													),
												})
											}
										/>
									</div>
								)}
								{rowError && (
									<p role="alert" className="text-danger-ink text-xs">
										{rowError}
									</p>
								)}
							</div>
						);
					})}
					<button
						type="button"
						className="text-sm underline disabled:no-underline disabled:opacity-50"
						disabled={form.rubric.length >= MAX_RUBRIC_FIELDS}
						onClick={() =>
							setForm({ ...form, rubric: [...form.rubric, emptyRubricField()] })
						}
					>
						{form.rubric.length >= MAX_RUBRIC_FIELDS
							? `Up to ${MAX_RUBRIC_FIELDS} fields per queue.`
							: "+ Add field"}
					</button>
				</fieldset>

				<label className="block text-sm" htmlFor={`${baseId}-reference`}>
					<span className="mb-1 block text-ink-3">Reference field</span>
					<select
						id={`${baseId}-reference`}
						data-testid="nq-reference-select"
						className={fieldClass(!!referenceError)}
						value={form.referenceKey}
						disabled={eligibleReferenceCount === 0}
						aria-invalid={!!referenceError}
						aria-describedby={
							referenceError ? `${baseId}-reference-err` : undefined
						}
						onChange={(e) => setForm({ ...form, referenceKey: e.target.value })}
					>
						{eligibleReferenceCount === 0 ? (
							<option value="">
								Mark a required, non-boolean field above first
							</option>
						) : (
							eligibleReference.map((f) => (
								<option key={f.key.trim()} value={f.key.trim()}>
									{f.label.trim() || f.key.trim()}
								</option>
							))
						)}
					</select>
					<p className="mt-1 text-2xs text-ink-3">
						This question's answer becomes the graded case's expected output.
					</p>
					{referenceError && (
						<p
							id={`${baseId}-reference-err`}
							role="alert"
							className="mt-1 text-danger-ink text-xs"
						>
							{referenceError}
						</p>
					)}
				</label>

				<p className="rounded-md bg-surface-2 p-2 text-ink-2 text-xs">
					Every trace matching <strong>{sourceSummary}</strong> in the last{" "}
					<strong>{form.windowHours || "?"}h</strong>, reviewed against{" "}
					<strong>
						{form.rubric.length} question{form.rubric.length === 1 ? "" : "s"}
					</strong>
					, lands in{" "}
					<strong>{selectedDataset?.name ?? "(choose a dataset)"}</strong>.
				</p>

				<div className="flex gap-2 pt-1">
					<Button
						type="button"
						variant="primary"
						data-testid="nq-submit"
						onClick={submit}
						disabled={
							busy ||
							!form.name.trim() ||
							!form.datasetId ||
							form.rubric.length === 0 ||
							!form.referenceKey
						}
					>
						{busy ? "Creating…" : "Create queue"}
					</Button>
					<Button
						type="button"
						variant="ghost"
						data-testid="nq-cancel"
						onClick={() => setOpen(false)}
						disabled={busy}
					>
						Cancel
					</Button>
				</div>
			</div>
		</Modal>
	);
}
