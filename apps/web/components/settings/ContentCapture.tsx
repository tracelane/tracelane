"use client";
import { apiFetchRaw } from "@/lib/api-fetch";
import { Button, ConfirmDialog, Skeleton } from "@tracelanedev/ui";
import { useCallback, useEffect, useState } from "react";
type Capture = {
	input: boolean;
	output: boolean;
	operator_allowlisted: boolean;
	effective: { input: boolean; output: boolean };
	queryable_days: number | null;
	max_field_bytes: number;
	can_edit: boolean;
};
export function ContentCapture() {
	const [data, setData] = useState<Capture | null>(null);
	const [loading, setLoading] = useState(true);
	const [readError, setReadError] = useState(false);
	const [busy, setBusy] = useState(false);
	const [confirm, setConfirm] = useState(false);
	const [error, setError] = useState("");
	const load = useCallback(async () => {
		setLoading(true);
		setReadError(false);
		try {
			const res = await apiFetchRaw("/api/settings/content-capture");
			if (!res.ok) throw new Error();
			setData(await res.json());
		} catch {
			setReadError(true);
		} finally {
			setLoading(false);
		}
	}, []);
	useEffect(() => {
		void load();
	}, [load]);
	async function save(enabled: boolean) {
		if (busy || !data?.can_edit || data.operator_allowlisted) return;
		setBusy(true);
		setError("");
		try {
			const res = await apiFetchRaw("/api/settings/content-capture", {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ input: enabled, output: enabled }),
			});
			const result = await res.json();
			if (!res.ok) {
				setError(
					result.error === "audit_unavailable"
						? "Not saved — the change could not be recorded in the audit ledger. Try again."
						: res.status === 403
							? "Only the workspace owner can change this."
							: result.error === "no_control_plane"
								? "Not saved — no control plane is available."
								: "Not saved — the service did not answer. Try again.",
				);
				return;
			}
			setData(result);
			setConfirm(false);
		} catch {
			setError("Not saved — the service did not answer. Try again.");
		} finally {
			setBusy(false);
		}
	}
	const on = !!data && (data.effective.input || data.effective.output);
	return (
		<section
			className="mb-6 space-y-3 rounded-card border border-line bg-surface p-5"
			aria-labelledby="capture-title"
		>
			<h3 id="capture-title" className="text-sm font-semibold">
				Record prompt and response text
			</h3>
			{loading ? (
				<Skeleton className="h-16 w-full" />
			) : readError || !data ? (
				<>
					<p role="alert">Couldn't load this setting.</p>
					<Button onClick={() => void load()}>Retry</Button>
				</>
			) : (
				<>
					<label className="flex items-center gap-3 text-sm">
						<input
							type="checkbox"
							checked={on}
							disabled={busy || !data.can_edit || data.operator_allowlisted}
							onChange={(e) => {
								setError("");
								if (e.target.checked) void save(true);
								else setConfirm(true);
							}}
						/>
						Record prompt and response text
					</label>
					{!on ? (
						<p className="text-sm text-ink-2">
							Off. Traces keep model, tokens, cost and latency — not the
							messages.
						</p>
					) : (
						<p className="text-sm text-ink-2">
							New requests through the gateway keep{" "}
							{data.effective.input && data.effective.output
								? "the messages you send and the model's reply"
								: data.effective.input
									? "the messages you send"
									: "the model's reply"}{" "}
							on the trace,{" "}
							{data.queryable_days === null
								? "for as long as the trace is kept"
								: `for ${data.queryable_days} days — the same as the trace`}
							. Known secrets and personal data are replaced with [REDACTED]
							markers before storage. Each field is kept up to{" "}
							{data.max_field_bytes / 1024} KiB.
						</p>
					)}
					{data.operator_allowlisted && (
						<p className="text-sm text-ink-2">
							Recording is on for this workspace by the operator.
						</p>
					)}
					{!data.can_edit && (
						<p className="text-sm text-ink-2">
							Only the workspace owner can change this.
						</p>
					)}
					<p className="text-xs text-ink-2">
						Responses from the native Anthropic endpoint are not recorded yet —
						requests are.
					</p>
					{busy && <p aria-live="polite">Saving…</p>}
				</>
			)}
			{error && !confirm && (
				<p role="alert" className="text-danger-ink">
					{error}
				</p>
			)}
			<ConfirmDialog
				open={confirm}
				title="Stop recording new text?"
				confirmLabel="Stop recording"
				onClose={() => setConfirm(false)}
				onConfirm={() => void save(false)}
				busy={busy}
				error={error}
			>
				<p>Text already recorded stays until its trace expires.</p>
			</ConfirmDialog>
		</section>
	);
}
