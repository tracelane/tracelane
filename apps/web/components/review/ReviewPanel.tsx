"use client";

/**
 * `EVL-29` — THE ONE ACTION, at the surface.
 *
 * A reviewer reads one candidate, answers the queue's rubric, and presses
 * **Submit review**. That single press creates the dataset item carrying their
 * answer as its `expected_output` AND records the review. There is no second
 * button and there must never be one: the founder's done-when for this item is
 * literally *"if it takes two clicks in two places, item 12 is not done"*.
 *
 * ## Why the form is generated from the rubric rather than hard-coded
 *
 * The queue owns its rubric definition, so this component renders fields it has
 * never seen before by reading the definition and the answer together. That is
 * the 0026 rule satisfied rather than sidestepped: a CLOSED set where the UI
 * must know the values (`label` stays good/bad/needs_review), an OPEN set only
 * where the UI is handed the schema alongside the data.
 *
 * ## Client-side validation is a COURTESY, never the control
 *
 * Every rule here — required, range, options — is enforced again by the gateway,
 * fail-closed, and the gateway is the authority. This copy exists only so a
 * reviewer sees the problem before a round trip. When the two disagree, the
 * gateway wins and its `field`-scoped message is rendered against the field it
 * names.
 */

import type { QueueItem } from "@/app/api/annotation-queues/[queueId]/items/route";
import type {
	AnnotationQueue,
	RubricField,
} from "@/app/api/annotation-queues/shared";
import { Button } from "@tracelanedev/ui";
import { useCallback, useMemo, useState } from "react";

type Props = {
	queue: AnnotationQueue;
	items: QueueItem[];
	scanTruncated: boolean;
	scanExhausted: boolean;
};

type Answers = Record<string, string | number | boolean>;

type Outcome =
	| { kind: "idle" }
	| { kind: "saving" }
	| { kind: "done"; itemId: string; deduped: boolean; expected: string }
	| { kind: "error"; message: string; field?: string };

function initialAnswers(rubric: RubricField[]): Answers {
	const a: Answers = {};
	for (const f of rubric) {
		if (f.type === "boolean") a[f.key] = false;
		else if (f.type === "score") a[f.key] = f.min ?? 0;
		else if (f.type === "choice") a[f.key] = f.options?.[0] ?? "";
		else a[f.key] = "";
	}
	return a;
}

export function ReviewPanel({
	queue,
	items,
	scanTruncated,
	scanExhausted,
}: Props) {
	const [cursor, setCursor] = useState(0);
	const [label, setLabel] = useState<"good" | "bad" | "needs_review">("bad");
	const [note, setNote] = useState("");
	const [answers, setAnswers] = useState<Answers>(() =>
		initialAnswers(queue.rubric),
	);
	const [outcome, setOutcome] = useState<Outcome>({ kind: "idle" });

	const current = items[cursor];
	const referenceField = useMemo(
		() => queue.rubric.find((f) => f.key === queue.expected_output_field),
		[queue],
	);

	const reset = useCallback(() => {
		setAnswers(initialAnswers(queue.rubric));
		setNote("");
		setLabel("bad");
		setOutcome({ kind: "idle" });
	}, [queue.rubric]);

	async function submit() {
		if (!current) return;
		setOutcome({ kind: "saving" });
		const res = await fetch(`/api/annotation-queues/${queue.id}/reviews`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				trace_id: current.trace_id,
				span_id: current.span_id,
				label,
				note,
				rubric: answers,
			}),
		});
		const body = (await res.json().catch(() => ({}))) as {
			error?: string;
			field?: string;
			message?: string;
			item_id?: string;
			deduped?: boolean;
			expected_output?: string;
		};
		if (!res.ok) {
			setOutcome({
				kind: "error",
				// The gateway's message is preferred over anything invented here:
				// it is the one that knows WHICH rule refused.
				message: body.message ?? body.error ?? `Request failed (${res.status})`,
				field: body.field,
			});
			return;
		}
		setOutcome({
			kind: "done",
			itemId: body.item_id ?? "",
			deduped: Boolean(body.deduped),
			expected: body.expected_output ?? "",
		});
	}

	if (items.length === 0) {
		return (
			<div className="rounded border p-6">
				<h2 className="font-medium">Nothing to review</h2>
				<p className="mt-2 text-sm opacity-80">
					{scanExhausted
						? "No trace in this queue's window matches its filter and is still unreviewed."
						: scanTruncated
							? "We scanned as far as we go in one pass and everything matched was already reviewed. Narrow the queue's filter or widen its window."
							: "No unreviewed candidates right now."}
				</p>
			</div>
		);
	}

	if (!current) {
		return (
			<div className="rounded border p-6">
				<h2 className="font-medium">Queue complete</h2>
				<p className="mt-2 text-sm opacity-80">
					You have worked every candidate on this page. Reload for the next set
					— membership is a live query, so new traces appear as they arrive.
				</p>
			</div>
		);
	}

	return (
		<div className="space-y-6">
			<div className="text-sm opacity-70">
				Candidate {cursor + 1} of {items.length}
				{scanTruncated ? " (page truncated by the scan bound)" : ""}
			</div>

			<div className="rounded border p-4 space-y-2">
				<div className="font-mono text-xs break-all">{current.trace_id}</div>
				{/* An absent score is rendered as absent. A 0 here would read as
				    "the judge scored this worst", which is a different claim. */}
				{current.score !== undefined && (
					<div className="text-sm">
						Judge score <strong>{current.score}</strong>
						{current.verdict ? ` · ${current.verdict}` : ""}
					</div>
				)}
				{current.reason && (
					<p className="text-sm opacity-80">{current.reason}</p>
				)}
				<a className="text-sm underline" href={`/traces/${current.trace_id}`}>
					Open the full trace
				</a>
			</div>

			<div className="space-y-4">
				<div>
					<label className="block text-sm font-medium" htmlFor="rv-label">
						Verdict
					</label>
					<select
						id="rv-label"
						className="mt-1 rounded border px-2 py-1"
						value={label}
						onChange={(e) =>
							setLabel(e.target.value as "good" | "bad" | "needs_review")
						}
					>
						<option value="good">good</option>
						<option value="bad">bad</option>
						<option value="needs_review">needs_review</option>
					</select>
				</div>

				{queue.rubric.map((f) => {
					const isRef = f.key === queue.expected_output_field;
					const errored = outcome.kind === "error" && outcome.field === f.key;
					return (
						<div key={f.key}>
							<label
								className="block text-sm font-medium"
								htmlFor={`rf-${f.key}`}
							>
								{f.label}
								{f.required ? " *" : ""}
								{isRef && (
									<span className="ml-2 text-xs font-normal opacity-70">
										— becomes this case&rsquo;s expected output
									</span>
								)}
							</label>
							{f.type === "boolean" ? (
								<input
									id={`rf-${f.key}`}
									type="checkbox"
									className="mt-1"
									checked={Boolean(answers[f.key])}
									onChange={(e) =>
										setAnswers({ ...answers, [f.key]: e.target.checked })
									}
								/>
							) : f.type === "choice" ? (
								<select
									id={`rf-${f.key}`}
									className="mt-1 block rounded border px-2 py-1"
									value={String(answers[f.key] ?? "")}
									onChange={(e) =>
										setAnswers({ ...answers, [f.key]: e.target.value })
									}
								>
									{(f.options ?? []).map((o) => (
										<option key={o} value={o}>
											{o}
										</option>
									))}
								</select>
							) : f.type === "score" ? (
								<input
									id={`rf-${f.key}`}
									type="number"
									min={f.min}
									max={f.max}
									className="mt-1 block rounded border px-2 py-1"
									value={Number(answers[f.key] ?? 0)}
									onChange={(e) =>
										setAnswers({ ...answers, [f.key]: Number(e.target.value) })
									}
								/>
							) : (
								<textarea
									id={`rf-${f.key}`}
									rows={isRef ? 5 : 2}
									className="mt-1 block w-full rounded border px-2 py-1"
									value={String(answers[f.key] ?? "")}
									onChange={(e) =>
										setAnswers({ ...answers, [f.key]: e.target.value })
									}
								/>
							)}
							{errored && (
								<p className="mt-1 text-sm text-danger-ink">
									{outcome.message}
								</p>
							)}
						</div>
					);
				})}

				<div>
					<label className="block text-sm font-medium" htmlFor="rv-note">
						Note
					</label>
					<textarea
						id="rv-note"
						rows={2}
						className="mt-1 block w-full rounded border px-2 py-1"
						value={note}
						onChange={(e) => setNote(e.target.value)}
					/>
				</div>
			</div>

			{outcome.kind === "error" && !outcome.field && (
				<p className="text-sm text-danger-ink">{outcome.message}</p>
			)}

			{outcome.kind === "done" ? (
				<div className="rounded border border-ok bg-ok-soft p-4 space-y-2">
					<p className="text-sm">
						Review recorded and{" "}
						{outcome.deduped
							? "the reference was written onto the existing case"
							: "a new graded case was created"}{" "}
						in this queue&rsquo;s dataset.
					</p>
					<p className="font-mono text-xs break-all">item {outcome.itemId}</p>
					<Button
						type="button"
						variant="secondary"
						size="sm"
						onClick={() => {
							setCursor(cursor + 1);
							reset();
						}}
					>
						Next candidate
					</Button>
				</div>
			) : (
				<Button
					type="button"
					variant="primary"
					disabled={outcome.kind === "saving" || !referenceField}
					onClick={submit}
				>
					{outcome.kind === "saving"
						? "Saving…"
						: "Submit review and create the graded case"}
				</Button>
			)}
		</div>
	);
}
