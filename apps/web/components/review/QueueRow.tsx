"use client";

/**
 * `EVL-29` — one row of the `/review` queue list, with its archive/un-archive
 * action.
 *
 * **Second half of the same founder finding as `NewQueueDialog`.** The read
 * side (`archived_at` renders as "(archived)" with the link suppressed) shipped
 * 2026-08-29; `PATCH /v1/annotation-queues/{queue_id}` — rename, re-filter,
 * re-rubric, archive/un-archive — existed end to end at both the gateway
 * (`crates/gateway/src/annotation_routes.rs:1516`, `PatchQueueBody` at `:1499`)
 * and the Next.js proxy (`apps/web/app/api/annotation-queues/[queueId]/route.ts`),
 * and nothing in `apps/web` ever called it.
 *
 * `archived: bool` is the ONLY field this component sends — `true` archives,
 * `false` un-archives (`PatchQueueBody.archived`,
 * `crates/gateway/src/annotation_routes.rs:1510-1513`, doc comment: *"There is
 * deliberately NO DELETE: a review's `queue_id` must never dangle"*). Renaming,
 * re-filtering and re-rubricing are the SAME route and are explicitly out of
 * scope here — the founder's ask was archive, and widening this action to a
 * full edit form is a separate, larger surface this file does not attempt.
 *
 * The whole ROW (not just the button) is a client component so archiving is
 * visibly optimistic: the name cell, the archived label and the button all
 * flip together, then roll back together if the PATCH fails.
 */

import type { AnnotationQueue } from "@/app/api/annotation-queues/shared";
import { formatDateTimeUtc } from "@/lib/format-date";
import { Button } from "@tracelanedev/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

export type PatchOutcome = { ok: true } | { ok: false; error: string };

/** Isolated for testing without a DOM: the exact request this row issues, and
 * how a non-2xx response becomes the message the row renders. */
export async function patchQueueArchived(
	queueId: string,
	archived: boolean,
): Promise<PatchOutcome> {
	let res: Response;
	try {
		res = await fetch(`/api/annotation-queues/${encodeURIComponent(queueId)}`, {
			method: "PATCH",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ archived }),
		});
	} catch {
		return {
			ok: false,
			error: "Could not reach the gateway. The queue was not changed.",
		};
	}
	if (res.ok) return { ok: true };
	let body: { error?: string; message?: string } = {};
	try {
		body = (await res.json()) as typeof body;
	} catch {
		// no body — fall through to the generic message below
	}
	return {
		ok: false,
		error:
			body.message ?? body.error ?? `The gateway refused with ${res.status}.`,
	};
}

export function confirmArchiveMessage(
	name: string,
	archiving: boolean,
): string {
	return archiving
		? `Archive "${name}"? It stops matching new traces and leaves the active list. Existing reviews are kept, and this can be undone by un-archiving.`
		: `Un-archive "${name}"? It returns to the active list and starts matching new traces again.`;
}

export function QueueRow({
	queue,
	sourceLabel,
}: {
	queue: AnnotationQueue;
	sourceLabel: string;
}) {
	const router = useRouter();
	const [pending, setPending] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// `undefined` = no optimistic override; render `queue.archived_at` as-is.
	const [archivedOverride, setArchivedOverride] = useState<
		string | null | undefined
	>(undefined);

	const archivedAt =
		archivedOverride !== undefined
			? archivedOverride
			: (queue.archived_at ?? null);
	const isArchived = archivedAt !== null;

	async function toggle() {
		const next = !isArchived;
		if (!window.confirm(confirmArchiveMessage(queue.name, next))) return;
		const prevOverride = archivedOverride;
		setPending(true);
		setError(null);
		// Optimistic: the row updates immediately, before the network resolves.
		setArchivedOverride(next ? new Date().toISOString() : null);
		const outcome = await patchQueueArchived(queue.id, next);
		setPending(false);
		if (!outcome.ok) {
			setArchivedOverride(prevOverride);
			setError(outcome.error);
			return;
		}
		router.refresh();
	}

	return (
		<tr className="border-b last:border-0">
			<td className="py-2 pr-4">
				{isArchived ? (
					<span className="opacity-60">{queue.name} (archived)</span>
				) : (
					<Link className="underline" href={`/review/${queue.id}`}>
						{queue.name}
					</Link>
				)}
			</td>
			<td className="py-2 pr-4">{sourceLabel}</td>
			<td className="py-2 pr-4">{queue.filter.window_hours}h</td>
			<td className="py-2 pr-4">
				<code>{queue.expected_output_field}</code>
			</td>
			<td className="py-2 pr-4">{formatDateTimeUtc(queue.created_at)}</td>
			<td className="py-2 pr-4">
				<div className="flex flex-col items-start gap-1">
					<Button
						type="button"
						variant="ghost"
						size="sm"
						disabled={pending}
						onClick={toggle}
					>
						{pending
							? isArchived
								? "Un-archiving…"
								: "Archiving…"
							: isArchived
								? "Un-archive"
								: "Archive"}
					</Button>
					{error && (
						<p role="alert" className="text-2xs text-danger-ink">
							{error}
						</p>
					)}
				</div>
			</td>
		</tr>
	);
}
