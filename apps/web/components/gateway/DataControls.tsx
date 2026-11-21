"use client";

import { ContentCapture } from "@/components/settings/ContentCapture";
import { Button } from "@tracelanedev/ui";
import { useState } from "react";
import {
	Boundary,
	RefusalNote,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { Field, Panel, WhyDisabled, inputClass } from "./fields";

type Capture = { input?: boolean; output?: boolean };
type Key = {
	id: string;
	name: string;
	prefix: string;
	capture: Capture | null;
};
type View = {
	retention: {
		days: number | null;
		effective_days: number;
		plan_days: number;
		min_days: number;
		max_days: number;
	};
	sweep: { mode: string; enforced: boolean; next_sweep_at: string | null };
	keys?: Key[];
	key_overrides_count: number;
	routes: { route: string; binding: string }[];
};
function KeyCapture({ row, allowed }: { row: Key; allowed: boolean }) {
	const [input, setInput] = useState(row.capture?.input === false);
	const [output, setOutput] = useState(row.capture?.output === false);
	const save = useControlWrite<
		{ changed: string[] },
		{ capture: Capture | null }
	>("PATCH", `keys/${encodeURIComponent(row.id)}`, ["data-controls"]);
	return (
		<fieldset
			className="space-y-2 rounded border border-border p-3"
			disabled={!allowed || save.isPending}
		>
			<legend className="px-1 font-medium">
				{row.name} <span className="text-muted">{row.prefix}…</span>
			</legend>
			<label className="flex gap-2">
				<input
					type="checkbox"
					checked={input}
					onChange={(e) => setInput(e.target.checked)}
				/>
				Disable prompt capture for this key
			</label>
			<label className="flex gap-2">
				<input
					type="checkbox"
					checked={output}
					onChange={(e) => setOutput(e.target.checked)}
				/>
				Disable response capture for this key
			</label>
			<Button
				onClick={() =>
					save.mutate({
						capture:
							input || output
								? {
										...(input ? { input: false } : {}),
										...(output ? { output: false } : {}),
									}
								: null,
					})
				}
			>
				Save key capture
			</Button>
			{save.error && <RefusalNote error={save.error} />}
			{save.isSuccess && <output>Saved</output>}
		</fieldset>
	);
}
function Retention({ view, allowed }: { view: View; allowed: boolean }) {
	const r = view.retention;
	const [days, setDays] = useState(r.days === null ? "" : String(r.days));
	const [confirm, setConfirm] = useState("");
	const save = useControlWrite<
		{ changed: boolean; rows_past_window?: Record<string, number | null> },
		{ days: number | null; confirm?: string }
	>("PUT", "data-controls/retention", ["data-controls"]);
	const selected = days.trim() === "" ? r.plan_days : Number(days);
	const reducing = selected < r.effective_days;
	const valid =
		Number.isInteger(selected) &&
		selected >= r.min_days &&
		selected <= r.max_days;
	return (
		<div className="space-y-4">
			<p>
				Current window: {r.effective_days} days. Your plan allows {r.plan_days}{" "}
				days. Minimum: {r.min_days} days.
			</p>
			<Field label="Retention (days)">
				<input
					aria-label="Retention (days)"
					className={inputClass}
					type="number"
					min={r.min_days}
					max={r.max_days}
					value={days}
					placeholder={String(r.plan_days)}
					disabled={!allowed || save.isPending}
					onChange={(e) => setDays(e.target.value)}
				/>
			</Field>
			<Button
				variant="ghost"
				disabled={!allowed || save.isPending}
				onClick={() => {
					setDays("");
					setConfirm("");
				}}
			>
				Use plan retention
			</Button>
			{reducing && (
				<dialog
					open
					aria-label="Confirm retention reduction"
					className="relative m-0 w-full rounded border border-border bg-background p-4"
				>
					<Field label="Confirm deletion">
						<p className="text-sm">
							Reducing retention can permanently delete older telemetry. Type
							“delete data older than {selected} days” to confirm.
						</p>
						<input
							aria-label="Confirm deletion"
							className={inputClass}
							value={confirm}
							disabled={!allowed || save.isPending}
							onChange={(e) => setConfirm(e.target.value)}
						/>
					</Field>
					<Button
						variant="ghost"
						onClick={() => {
							setDays(r.days === null ? "" : String(r.days));
							setConfirm("");
						}}
					>
						Cancel reduction
					</Button>
				</dialog>
			)}
			<Button
				disabled={
					!allowed ||
					save.isPending ||
					!valid ||
					(reducing && confirm !== `delete data older than ${selected} days`)
				}
				onClick={() =>
					save.mutate({
						days: days.trim() === "" ? null : selected,
						...(reducing ? { confirm } : {}),
					})
				}
			>
				Save retention
			</Button>
			{save.error && <RefusalNote error={save.error} />}
			{save.isSuccess && (
				<output>
					Retention saved. Historical deletion follows the sweep status below.
				</output>
			)}
			{save.data?.rows_past_window && (
				<div>
					<p>Rows past the saved window (bounded estimates):</p>
					<ul>
						{Object.entries(save.data.rows_past_window).map(
							([table, count]) => (
								<li key={table}>
									{table.replaceAll("_", " ")}:{" "}
									{count === null
										? "Count unavailable"
										: count.toLocaleString()}
								</li>
							),
						)}
					</ul>
				</div>
			)}
			<p>
				Sweep mode:{" "}
				{view.sweep.mode === "dryrun"
					? "Preview only"
					: view.sweep.mode === "enforce"
						? "Deletion enabled"
						: "Off"}
				.
			</p>
			<p>
				{view.sweep.enforced
					? "Scheduled sweeps delete telemetry outside the retention window."
					: "Historical deletion is not active. The read window still applies."}
			</p>
			{view.sweep.next_sweep_at && (
				<p>
					Next scheduled sweep:{" "}
					{new Date(view.sweep.next_sweep_at).toISOString()}
				</p>
			)}
		</div>
	);
}
export function DataControls() {
	const q = useControlQuery<View>("data-controls");
	const can = useCan("edit_policies");
	return (
		<Boundary query={q} resource="data controls" rows={4}>
			{() =>
				q.data && (
					<div className="space-y-6">
						<Panel
							title="Data controls"
							description="Choose what this workspace records and how long telemetry remains available."
						>
							<WhyDisabled reason={can.reason} />
							<Retention view={q.data} allowed={can.allowed} />
						</Panel>
						<ContentCapture key={q.data.retention.effective_days} />
						<Panel
							title="Capture per key"
							description="Keys inherit workspace capture unless disabled here. A key cannot enable capture that the workspace disables."
						>
							{(q.data.keys ?? []).length === 0 ? (
								<p>
									No active keys. Create a key in Settings → API keys to set a
									capture override.
								</p>
							) : (
								(q.data.keys ?? []).map((row) => (
									<KeyCapture
										key={`${row.id}:${JSON.stringify(row.capture)}`}
										row={row}
										allowed={can.allowed}
									/>
								))
							)}
						</Panel>
						<Panel
							title="Zero retention routing"
							note="Send the required zero-retention header to constrain provider dispatch. Constrained requests also suppress captured text and response-cache access."
						>
							<p>
								<code>x-tracelane-zdr: required</code>
							</p>
							<ul>
								{q.data.routes.map((row) => (
									<li key={row.route}>
										{row.route.replaceAll("_", " ")}:{" "}
										{row.binding === "gated"
											? "requires an eligible provider"
											: "refuses constrained content"}
									</li>
								))}
							</ul>
						</Panel>
					</div>
				)
			}
		</Boundary>
	);
}
