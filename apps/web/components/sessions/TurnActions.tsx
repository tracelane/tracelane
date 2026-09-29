"use client";
import { DatasetAction } from "@/app/datasets/DatasetAction";
import { useObjectCommands } from "@/components/command-palette/object-commands";
import { ShareDialog } from "@/components/trace-viewer/ShareDialog";
import {
	type Annotation,
	TraceFlag,
} from "@/components/trace-viewer/TraceFlag";
import { apiFetch } from "@/lib/api-fetch";
import { Button, Dialog, ObjectActions, Toast } from "@tracelanedev/ui";
import { useRef, useState } from "react";
export function CopySessionLink({ sessionId }: { sessionId: string }) {
	const trigger = useRef<HTMLButtonElement>(null);
	useObjectCommands([
		{
			id: "session-copy-link",
			label: "Copy session link",
			href: "",
			group: "action",
			onSelect: () => trigger.current?.click(),
		},
	]);
	const [notice, setNotice] = useState<string | null>(null);
	return (
		<>
			<Button
				ref={trigger}
				onClick={async () => {
					try {
						await navigator.clipboard.writeText(
							`${window.location.origin}/sessions/${encodeURIComponent(sessionId)}`,
						);
						setNotice("Session link copied");
					} catch {
						setNotice("Could not copy. Check clipboard permissions.");
					}
				}}
			>
				Copy session link
			</Button>
			<Toast message={notice} onDismiss={() => setNotice(null)} />
		</>
	);
}
export function TurnActions({
	traceId,
	spanId,
	viewerRole,
	userId,
	canCopyContent,
}: {
	traceId: string;
	spanId?: string;
	viewerRole: string | null;
	userId: string;
	canCopyContent: boolean;
}) {
	const [open, setOpen] = useState(false);
	const [annotation, setAnnotation] = useState<Annotation | null>(null);
	const [loaded, setLoaded] = useState(false);
	const [error, setError] = useState("");
	const [notice, setNotice] = useState<string | null>(null);
	async function load() {
		setLoaded(false);
		setError("");
		try {
			const rows = await apiFetch<Annotation[]>(
				`/api/traces/${encodeURIComponent(traceId)}/annotations`,
			);
			setAnnotation(
				rows.find((a) => a.span_id === "" && a.author_sub === userId) ?? null,
			);
			setLoaded(true);
		} catch {
			setError("Could not load flags. Retry.");
		}
	}
	return (
		<>
			<ObjectActions
				label="Turn actions"
				actions={[
					{
						label: "Open trace",
						onSelect: () => {
							window.location.href = `/traces/${encodeURIComponent(traceId)}`;
						},
					},
					{
						label: "Flag, share or add to dataset",
						onSelect: () => {
							setOpen(true);
							void load();
						},
					},
					{
						label: "Copy turn link",
						onSelect: async () => {
							try {
								await navigator.clipboard.writeText(
									`${window.location.origin}/traces/${encodeURIComponent(traceId)}`,
								);
								setNotice("Turn link copied");
							} catch {
								setNotice("Could not copy. Check clipboard permissions.");
							}
						},
					},
				]}
			/>
			<Dialog open={open} title="Turn actions" onClose={() => setOpen(false)}>
				<div className="space-y-5">
					{error ? (
						<div>
							<p role="alert">{error}</p>
							<Button onClick={() => void load()}>Retry flags</Button>
						</div>
					) : loaded ? (
						<TraceFlag
							traceId={traceId}
							initial={annotation}
							canWrite={viewerRole !== "viewer"}
						/>
					) : (
						<p aria-live="polite">Loading flags…</p>
					)}
					<ShareDialog traceId={traceId} />
					{viewerRole !== "owner" && viewerRole !== "admin" ? (
						<Button disabled title="Only a workspace owner can change datasets">
							Add to dataset
						</Button>
					) : (
						<DatasetAction
							traceId={traceId}
							spanId={spanId}
							contentUnavailable={!canCopyContent || !spanId}
						/>
					)}
					<a
						className="block underline"
						href={`/traces/${encodeURIComponent(traceId)}`}
					>
						Open full trace
					</a>
				</div>
			</Dialog>
			<Toast message={notice} onDismiss={() => setNotice(null)} />
		</>
	);
}
