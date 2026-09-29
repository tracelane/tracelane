"use client";
import { apiFetchRaw } from "@/lib/api-fetch";
import { Button, ConfirmDialog } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { datasetResponse, ownerReason } from "../management";
export function DeleteDatasetButton({
	datasetId,
	datasetName,
	canWrite = false,
}: { datasetId: string; datasetName: string; canWrite?: boolean }) {
	const router = useRouter();
	const [open, setOpen] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [queues, setQueues] = useState<{ id: string; name: string }[] | null>(
		null,
	);
	const [queueError, setQueueError] = useState("");
	async function loadQueues() {
		setQueueError("");
		setQueues(null);
		try {
			const data = await datasetResponse<{
				queues: { id: string; name: string; default_dataset_id: string }[];
			}>(await apiFetchRaw("/api/annotation-queues"));
			setQueues(data.queues.filter((q) => q.default_dataset_id === datasetId));
		} catch {
			setQueueError(
				"Could not check affected review queues. Deleting may prevent reviews from being submitted. Retry to check.",
			);
		}
	}
	async function remove() {
		if (!canWrite || busy) return;
		setBusy(true);
		setError("");
		try {
			await datasetResponse(
				await apiFetchRaw(`/api/datasets/${encodeURIComponent(datasetId)}`, {
					method: "DELETE",
				}),
			);
			setOpen(false);
			router.push("/datasets");
			router.refresh();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not delete. Retry.");
		} finally {
			setBusy(false);
		}
	}
	return (
		<>
			<Button
				variant="danger"
				disabled={!canWrite}
				title={!canWrite ? ownerReason : undefined}
				onClick={() => {
					setOpen(true);
					void loadQueues();
				}}
			>
				Delete dataset
			</Button>
			<ConfirmDialog
				open={open}
				onClose={() => setOpen(false)}
				onConfirm={() => void remove()}
				title={`Delete ${datasetName}`}
				confirmText={datasetName}
				busy={busy}
				error={error}
			>
				<p>
					Items are removed from view. Frozen snapshots and past experiment
					results are kept. A dataset slot is freed. This cannot be undone.
				</p>
				{queues === null ? (
					<p aria-live="polite">{queueError || "Checking review queues…"}</p>
				) : queues.length ? (
					<div>
						<p>
							These review queues will refuse new submissions until their
							dataset is changed:
						</p>
						<ul>
							{queues.map((q) => (
								<li key={q.id}>
									<a className="underline" href={`/review/${q.id}`}>
										{q.name}
									</a>
								</li>
							))}
						</ul>
					</div>
				) : (
					<p>No review queues write into this dataset.</p>
				)}
				{queueError && (
					<Button onClick={() => void loadQueues()}>Retry queue check</Button>
				)}
			</ConfirmDialog>
		</>
	);
}
