"use client";
import { ObjectPageCommands } from "@/components/command-palette/object-commands";
import { fmtUsd } from "@/lib/metrics/format";

import { apiFetchRaw } from "@/lib/api-fetch";
import { formatDateTimeUtc } from "@/lib/format-date";
import { Button, Dialog } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import type { ApiKeyRow } from "./ApiKeyManager";
type Spend = {
	window: "day" | "week" | "month";
	window_starts_at: string;
	recorded_usd: number | null;
};
export function KeyEditDrawer({
	row,
	onClose,
	onSaved,
}: {
	row: ApiKeyRow;
	onClose: () => void;
	onSaved: (row: ApiKeyRow, changed: string[]) => void;
}) {
	const [name, setName] = useState(row.name);
	const [scope, setScope] = useState(row.scope ?? []);
	const [scopeEdited, setScopeEdited] = useState(false);
	const [budget, setBudget] = useState(
		row.budgetUsdMonthly == null ? "" : String(row.budgetUsdMonthly),
	);
	const [rpm, setRpm] = useState(
		row.rateLimitRpm == null ? "" : String(row.rateLimitRpm),
	);
	const [cadence, setCadence] = useState(row.budgetReset ?? "monthly");
	const [expiry, setExpiry] = useState(
		row.expiresAt ? new Date(row.expiresAt).toISOString().slice(0, 16) : "",
	);
	const [velocity, setVelocity] = useState(row.velocityBreaker ?? false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<{
		message: string;
		field?: string;
	} | null>(null);
	const [spend, setSpend] = useState<Spend | null>(null);
	const [loading, setLoading] = useState(true);
	const [unavailable, setUnavailable] = useState(false);
	const [retiring, setRetiring] = useState(row.revokedAt ?? null);
	useEffect(() => {
		let live = true;
		void (async () => {
			try {
				const response = await apiFetchRaw(
					`/api/settings/api-keys/${encodeURIComponent(row.id)}`,
				);
				if (!live) return;
				if (!response.ok) {
					if (response.status === 404) {
						setUnavailable(true);
						setError({
							message: "This key no longer exists, has expired or was revoked.",
						});
					}
					return;
				}
				const data = await response.json();
				if (live) {
					setSpend(data.spend);
					setRetiring(data.revokedAt ?? null);
				}
			} catch {
			} finally {
				if (live) setLoading(false);
			}
		})();
		return () => {
			live = false;
		};
	}, [row.id]);
	const readOnly = !!retiring || unavailable;
	function fieldError(field: string) {
		return error?.field === field ? (
			<p role="alert" className="text-xs text-danger-ink">
				{error.message}
			</p>
		) : null;
	}
	async function save() {
		if (busy || readOnly) return;
		setError(null);
		const patch: Record<string, unknown> = {};
		if (name !== row.name) patch.name = name;
		if (scopeEdited) patch.scope = scope;
		if (budget !== String(row.budgetUsdMonthly ?? "")) {
			const n = budget.trim() === "" ? null : Number(budget);
			if (n !== null && (!Number.isFinite(n) || n < 0)) {
				setError({
					field: "budget_usd_monthly",
					message: "Budget must be a finite, non-negative number.",
				});
				return;
			}
			patch.budgetUsdMonthly = n;
		}
		if (rpm !== String(row.rateLimitRpm ?? "")) {
			const n = rpm.trim() === "" ? null : Number(rpm);
			if (n !== null && (!Number.isSafeInteger(n) || n <= 0)) {
				setError({
					field: "rate_limit_rpm",
					message: "Rate limit must be a positive whole number.",
				});
				return;
			}
			patch.rateLimitRpm = n;
		}
		if (cadence !== (row.budgetReset ?? "monthly")) patch.budgetReset = cadence;
		if (velocity !== (row.velocityBreaker ?? false))
			patch.velocityBreaker = velocity;
		if (
			expiry !==
			(row.expiresAt ? new Date(row.expiresAt).toISOString().slice(0, 16) : "")
		) {
			const date = expiry ? new Date(`${expiry}Z`) : null;
			if (
				date &&
				(!Number.isFinite(date.getTime()) || date.getTime() <= Date.now())
			) {
				setError({
					field: "expires_at",
					message:
						"Expiry must be in the future. To stop a key now, revoke it.",
				});
				return;
			}
			patch.expiresAt = date?.toISOString() ?? null;
		}
		if (!Object.keys(patch).length) {
			setError({ message: "No changes to save." });
			return;
		}
		setBusy(true);
		try {
			const response = await apiFetchRaw(
				`/api/settings/api-keys/${encodeURIComponent(row.id)}`,
				{
					method: "PATCH",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(patch),
				},
			);
			const data = await response.json();
			if (!response.ok) {
				if (response.status === 409 && data.error === "key_retiring")
					setRetiring(row.revokedAt ?? "unknown");
				setError({
					field: data.field,
					message:
						response.status === 403
							? "Your role can't change this key's limits"
							: response.status >= 500
								? "Couldn't save — nothing was changed. Retry."
								: (data.message ?? data.error ?? "Couldn't save. Retry."),
				});
				return;
			}
			onSaved(data, data.changed ?? []);
		} catch {
			setError({
				message: "Couldn't save — the service did not answer. Retry.",
			});
		} finally {
			setBusy(false);
		}
	}
	const field =
		"mt-1 block w-full rounded-control border border-line bg-surface p-2 text-sm";
	const comparable =
		spend &&
		cadence ===
			({ day: "daily", week: "weekly", month: "monthly" } as const)[
				spend.window
			];
	return (
		<Dialog
			drawer
			open
			title={`Edit limits — ${row.name}`}
			onClose={onClose}
			busy={busy}
		>
			<ObjectPageCommands
				copyHref={`/settings/api-keys?key=${encodeURIComponent(row.id)}`}
				commands={[
					{
						id: "key-edit-limits",
						label: "Edit limits",
						href: `/settings/api-keys?key=${encodeURIComponent(row.id)}`,
						group: "action",
					},
				]}
			/>
			<form
				className="space-y-4"
				onSubmit={(e) => {
					e.preventDefault();
					void save();
				}}
			>
				{loading ? (
					<p aria-live="polite">Loading recorded spend…</p>
				) : spend?.recorded_usd != null ? (
					<p>
						Recorded spend this {spend.window}: {fmtUsd(spend.recorded_usd)}
					</p>
				) : (
					<p>Spend unavailable right now — can't check current spend.</p>
				)}
				<p className="text-xs text-ink-2">
					Unpriced models add nothing to recorded spend. Recent requests may not
					have been ingested yet.
				</p>
				{row.scope == null && (
					<p className="rounded-control bg-warn-soft p-3 text-sm text-warn-ink">
						Full access (legacy) — narrow this key in place. It keeps its
						secret; clients keep working unless they need a scope you remove.
					</p>
				)}
				{retiring && (
					<p role="alert">
						This key is being rotated
						{retiring !== "unknown" &&
							` and retires ${formatDateTimeUtc(retiring)}`}
						. Edit its successor instead.{" "}
						<a className="underline" href="/settings/api-keys">
							Choose another key
						</a>
					</p>
				)}
				<fieldset disabled={busy || readOnly} className="space-y-4">
					<label className="block">
						Name
						<input
							className={field}
							value={name}
							onChange={(e) => setName(e.target.value)}
						/>
						<span className="text-xs text-ink-2">{name.length} characters</span>
						{fieldError("name")}
					</label>
					<fieldset>
						<legend>
							Scope
							{row.scope == null && !scopeEdited
								? " (unchanged legacy access)"
								: ""}
						</legend>
						<div className="mt-2 flex flex-wrap gap-4">
							{["chat", "read", "ingest", "admin"].map((s) => (
								<label key={s} className="flex gap-2">
									<input
										type="checkbox"
										checked={scope.includes(s)}
										onChange={(e) => {
											setScopeEdited(true);
											setScope((old) =>
												e.target.checked
													? [...old, s]
													: old.filter((v) => v !== s),
											);
										}}
									/>
									{s}
								</label>
							))}
						</div>
						{fieldError("scope")}
					</fieldset>
					<label className="block">
						Budget USD
						<input
							aria-label="Budget USD"
							type="number"
							min="0"
							step="any"
							className={field}
							value={budget}
							onChange={(e) => setBudget(e.target.value)}
						/>
						{fieldError("budget_usd_monthly")}
					</label>
					<p className="text-xs text-ink-2">
						Blank clears this key's budget cap.
					</p>
					<label className="block">
						Budget window
						<select
							className={field}
							value={cadence}
							onChange={(e) => setCadence(e.target.value as typeof cadence)}
						>
							<option value="daily">Day</option>
							<option value="weekly">Week</option>
							<option value="monthly">Month</option>
						</select>
						{fieldError("budget_reset")}
					</label>
					{budget !== "" &&
						comparable &&
						spend.recorded_usd != null &&
						Number(budget) > 0 &&
						Number(budget) <= spend.recorded_usd && (
							<p className="text-warn-ink">
								This key has already spent {fmtUsd(spend.recorded_usd)} — a
								{fmtUsd(Number(budget))} cap stops it on its next request.
							</p>
						)}
					{!comparable && !loading && (
						<p className="text-xs text-ink-2">
							Current spend cannot be checked for the selected window.
						</p>
					)}
					<label className="block">
						Requests per minute
						<input
							className={field}
							type="number"
							min="1"
							step="1"
							value={rpm}
							onChange={(e) => setRpm(e.target.value)}
						/>
						{fieldError("rate_limit_rpm")}
					</label>
					<p className="text-xs text-ink-2">
						Blank uses the workspace plan limit. The workspace limit still
						applies.
					</p>
					<label className="block">
						Expires at (UTC)
						<input
							className={field}
							type="datetime-local"
							value={expiry}
							onChange={(e) => setExpiry(e.target.value)}
						/>
						{fieldError("expires_at")}
					</label>
					<Button type="button" onClick={() => setExpiry("")}>
						Never expires
					</Button>
					<label className="flex gap-2">
						<input
							type="checkbox"
							checked={velocity}
							onChange={(e) => setVelocity(e.target.checked)}
						/>
						Velocity breaker
					</label>
					{fieldError("velocity_breaker")}
				</fieldset>
				{error && !error.field && (
					<p role="alert" className="text-danger-ink">
						{error.message}
					</p>
				)}
				<p className="text-xs text-ink-2">
					Applies to this key's next request. Requests already admitted finish
					under the old limits.
				</p>
				<div className="flex gap-2">
					<Button type="submit" variant="primary" disabled={busy || readOnly}>
						{busy ? "Saving…" : "Save limits"}
					</Button>
					<Button disabled={busy} onClick={onClose}>
						Cancel
					</Button>
				</div>
			</form>
		</Dialog>
	);
}
