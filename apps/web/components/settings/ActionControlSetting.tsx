"use client";
import {
	ACTION_CONTROL_ON_CONFIRMATION,
	ACTION_CONTROL_SUMMARY,
} from "@/lib/action-control-setting";
import { apiFetchRaw } from "@/lib/api-fetch";
import { Button, ConfirmDialog, Skeleton } from "@tracelanedev/ui";
import { useCallback, useEffect, useState } from "react";

type State = {
	enabled: boolean;
	can_edit: boolean;
	note: string;
	off_warning: string;
};

const ERRORS: Record<string, string> = {
	role_forbidden: "Only workspace owners and admins can change this.",
	changed_elsewhere: "Not saved — the setting just changed. Reload and retry.",
	rate_limited: "Too many changes. Try again in a few minutes.",
	write_unavailable:
		"Not saved — could not confirm the change. Reload and retry.",
	control_audit_unavailable:
		"Not saved — the change could not be recorded in the change log. Try again.",
};

/** Owner switch for action control (preview). Answer first: the state, then the switch. */
export function ActionControlSetting() {
	const [data, setData] = useState<State | null>(null);
	const [loading, setLoading] = useState(true);
	const [readError, setReadError] = useState(false);
	const [confirm, setConfirm] = useState<boolean | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [saved, setSaved] = useState("");

	const load = useCallback(async () => {
		setLoading(true);
		setReadError(false);
		try {
			const res = await apiFetchRaw("/api/settings/action-control");
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
		if (busy || !data?.can_edit) return;
		setBusy(true);
		setError("");
		try {
			const res = await apiFetchRaw("/api/settings/action-control", {
				method: "PUT",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ enabled, confirmed: true }),
			});
			const result = await res.json().catch(() => ({}));
			if (!res.ok) {
				setError(
					ERRORS[result.error as string] ??
						"Not saved — the service did not answer. Try again.",
				);
				return;
			}
			setData({ ...data, enabled: result.enabled });
			setSaved(
				result.changed
					? `Saved. ${result.note ?? data.note}`
					: "Already set. Nothing changed.",
			);
			setConfirm(null);
		} catch {
			setError("Not saved — the service did not answer. Try again.");
		} finally {
			setBusy(false);
		}
	}

	return (
		<section
			className="mb-6 space-y-3 rounded-card border border-line bg-surface p-4 sm:p-5"
			aria-labelledby="action-control-title"
		>
			<h3 id="action-control-title" className="text-sm font-semibold">
				Action control (preview)
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
					<p className="text-sm">
						{data.enabled
							? "Action control is on for this workspace."
							: "Action control is off for this workspace."}
					</p>
					<p className="text-sm text-ink-2">{ACTION_CONTROL_SUMMARY}</p>
					<label className="flex min-h-11 items-center gap-3 text-sm">
						<input
							type="checkbox"
							className="size-5"
							checked={data.enabled}
							disabled={busy || !data.can_edit}
							onChange={(e) => {
								setError("");
								setSaved("");
								setConfirm(e.target.checked);
							}}
						/>
						Turn on action control
					</label>
					{!data.can_edit && (
						<p className="text-sm text-ink-2">
							Only workspace owners and admins can change this.
						</p>
					)}
					{saved && (
						<p className="text-sm text-ink-2" aria-live="polite">
							{saved}
						</p>
					)}
				</>
			)}
			{error && confirm === null && (
				<p role="alert" className="text-danger-ink">
					{error}
				</p>
			)}
			<ConfirmDialog
				open={confirm !== null}
				title={confirm ? "Turn on action control?" : "Turn off action control?"}
				confirmLabel={confirm ? "Turn on" : "Turn off"}
				onClose={() => setConfirm(null)}
				onConfirm={() => confirm !== null && void save(confirm)}
				busy={busy}
				error={error}
			>
				<p>{confirm ? ACTION_CONTROL_ON_CONFIRMATION : data?.off_warning}</p>
			</ConfirmDialog>
		</section>
	);
}
