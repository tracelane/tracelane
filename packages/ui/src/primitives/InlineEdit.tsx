"use client";
import { useId, useState } from "react";
import { Button } from "./Button";
export function InlineEdit({
	label,
	value,
	onSave,
	multiline = false,
	disabled = false,
}: {
	label: string;
	value: string;
	onSave: (value: string) => Promise<void>;
	multiline?: boolean;
	disabled?: boolean;
}) {
	const [editing, setEditing] = useState(false);
	const [draft, setDraft] = useState(value);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const id = useId();
	if (!editing)
		return (
			<div className="space-y-2">
				<pre className="whitespace-pre-wrap break-words text-sm">
					{value || "Not set"}
				</pre>
				<Button
					disabled={disabled}
					size="sm"
					onClick={() => {
						setDraft(value);
						setError(null);
						setEditing(true);
					}}
				>
					Edit {label}
				</Button>
			</div>
		);
	const props = {
		id,
		value: draft,
		onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
			setDraft(e.target.value),
		disabled: busy,
		className:
			"w-full rounded-control border border-line bg-surface p-2 text-sm",
	};
	return (
		<form
			onSubmit={async (e) => {
				e.preventDefault();
				if (busy) return;
				setBusy(true);
				setError(null);
				try {
					await onSave(draft);
					setEditing(false);
				} catch (err) {
					setError(
						err instanceof Error ? err.message : "Could not save. Try again.",
					);
				} finally {
					setBusy(false);
				}
			}}
			className="space-y-2"
		>
			<label htmlFor={id}>{label}</label>
			{multiline ? <textarea {...props} rows={5} /> : <input {...props} />}{" "}
			{error && (
				<p role="alert" className="text-danger-ink">
					{error}
				</p>
			)}
			<div className="flex gap-2">
				<Button type="submit" disabled={busy} variant="primary">
					{busy ? "Saving…" : "Save"}
				</Button>
				<Button disabled={busy} onClick={() => setEditing(false)}>
					Cancel
				</Button>
			</div>
		</form>
	);
}
