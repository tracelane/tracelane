"use client";

/**
 * AlertsManager — self-service alert destinations + rules UI.
 *
 * Two sections: Destinations (webhook targets) and Alert Rules (metric
 * thresholds bound to a destination). Every button wires to a real gateway
 * proxy. All three states (loading / empty / error) are present per section.
 *
 * ADR-059 (alerting): gated on f_alerts; the parent RSC already checked the
 * entitlement before rendering this component, so this component assumes it
 * is entitled.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, EmptyState, Skeleton } from "@tracelanedev/ui";
import { useState } from "react";

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────

export interface AlertDestination {
	id: string;
	name: string;
	kind: string;
	url: string;
}

export interface AlertRule {
	id: string;
	metric: string;
	comparator: string;
	threshold: number;
	window_minutes: number;
	destination_id: string;
	enabled: boolean;
	last_state: string | null;
}

// ─────────────────────────────────────────────
// Label maps
// ─────────────────────────────────────────────

const METRIC_META: Record<string, { label: string; unit: string }> = {
	error_rate: { label: "Error rate", unit: "%" },
	burn_rate: { label: "SLO burn rate", unit: "×" },
	latency_p95: { label: "p95 latency", unit: "ms" },
	cost_usd: { label: "Cost", unit: "USD" },
	quota_pct: { label: "Quota used", unit: "%" },
};

const KIND_LABELS: Record<string, string> = {
	slack: "Slack",
	discord: "Discord",
	webhook: "Webhook",
};

function formatWindow(minutes: number): string {
	if (minutes < 60) return `${String(minutes)}m`;
	if (minutes < 1440) return `${String(Math.round(minutes / 60))}h`;
	return `${String(Math.round(minutes / 1440))}d`;
}

// ─────────────────────────────────────────────
// API helpers (call our /api/alerts/* proxies)
// ─────────────────────────────────────────────

async function fetchDestinations(): Promise<{
	destinations: AlertDestination[];
}> {
	const res = await fetch("/api/alerts/destinations");
	if (!res.ok) throw new Error(`HTTP ${String(res.status)}`);
	return res.json() as Promise<{ destinations: AlertDestination[] }>;
}

async function createDestination(body: {
	name: string;
	kind: string;
	url: string;
}): Promise<{ id: string }> {
	const res = await fetch("/api/alerts/destinations", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	if (!res.ok) {
		const data = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(data.error ?? `HTTP ${String(res.status)}`);
	}
	return res.json() as Promise<{ id: string }>;
}

async function deleteDestination(id: string): Promise<void> {
	const res = await fetch(
		`/api/alerts/destinations/${encodeURIComponent(id)}`,
		{ method: "DELETE" },
	);
	if (!res.ok) throw new Error(`HTTP ${String(res.status)}`);
}

async function testDestination(destination_id: string): Promise<void> {
	const res = await fetch("/api/alerts/test", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ destination_id }),
	});
	if (!res.ok) {
		const data = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(data.error ?? `HTTP ${String(res.status)}`);
	}
}

async function fetchRules(): Promise<{ rules: AlertRule[] }> {
	const res = await fetch("/api/alerts/rules");
	if (!res.ok) throw new Error(`HTTP ${String(res.status)}`);
	return res.json() as Promise<{ rules: AlertRule[] }>;
}

async function createRule(body: {
	metric: string;
	comparator: string;
	threshold: number;
	window_minutes: number;
	destination_id: string;
}): Promise<{ id: string }> {
	const res = await fetch("/api/alerts/rules", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
	if (!res.ok) {
		const data = (await res.json().catch(() => ({}))) as { error?: string };
		throw new Error(data.error ?? `HTTP ${String(res.status)}`);
	}
	return res.json() as Promise<{ id: string }>;
}

async function deleteRule(id: string): Promise<void> {
	const res = await fetch(`/api/alerts/rules/${encodeURIComponent(id)}`, {
		method: "DELETE",
	});
	if (!res.ok) throw new Error(`HTTP ${String(res.status)}`);
}

// ─────────────────────────────────────────────
// Shared sub-components
// ─────────────────────────────────────────────

function SectionHeader({
	title,
	description,
	onAdd,
	addLabel,
}: {
	title: string;
	description: string;
	onAdd: () => void;
	addLabel: string;
}) {
	return (
		<div className="flex items-start justify-between">
			<div>
				<h2 className="text-sm font-semibold text-ink">{title}</h2>
				<p className="text-xs text-ink-2 mt-0.5">{description}</p>
			</div>
			<button
				type="button"
				onClick={onAdd}
				className="shrink-0 px-3 py-1.5 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 transition-colors"
			>
				{addLabel}
			</button>
		</div>
	);
}

function LoadingState() {
	return (
		<div className="space-y-1">
			<Skeleton className="h-10 w-full" />
			<Skeleton className="h-10 w-full" />
			<Skeleton className="h-10 w-3/4" />
		</div>
	);
}

function SectionError({ message }: { message: string }) {
	return <p className="text-sm text-danger">{message}</p>;
}

/** Displays the alert rule's last-evaluated state. */
function LastStateBadge({ state }: { state: string | null }) {
	if (!state || state === "no_data") {
		return <span className="text-xs text-ink-3">—</span>;
	}
	if (state === "ok") {
		return <Badge tone="ok">OK</Badge>;
	}
	if (state === "firing") {
		return <Badge tone="danger">Firing</Badge>;
	}
	return <Badge tone="neutral">{state}</Badge>;
}

// ─────────────────────────────────────────────
// Destinations section
// ─────────────────────────────────────────────

function AddDestinationDialog({
	onClose,
	onCreate,
	pending,
	error,
}: {
	onClose: () => void;
	onCreate: (body: { name: string; kind: string; url: string }) => void;
	pending: boolean;
	error: Error | null;
}) {
	const [name, setName] = useState("");
	const [kind, setKind] = useState("slack");
	const [url, setUrl] = useState("");

	const urlPlaceholder =
		kind === "slack"
			? "https://hooks.slack.com/services/…"
			: kind === "discord"
				? "https://discord.com/api/webhooks/…/slack"
				: "https://example.com/webhook";

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
			<div className="bg-surface border border-line rounded-lg p-6 w-full max-w-md shadow-2xl space-y-4">
				<h3 className="text-base font-semibold text-ink">Add destination</h3>
				<form
					onSubmit={(e) => {
						e.preventDefault();
						if (!pending)
							onCreate({ name: name.trim(), kind, url: url.trim() });
					}}
					className="space-y-3"
				>
					<div>
						<label
							htmlFor="dest-name"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							Name
						</label>
						<input
							id="dest-name"
							type="text"
							value={name}
							onChange={(e) => setName(e.target.value)}
							placeholder="e.g. #alerts-prod"
							disabled={pending}
							required
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
						/>
					</div>
					<div>
						<label
							htmlFor="dest-kind"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							Type
						</label>
						<select
							id="dest-kind"
							value={kind}
							onChange={(e) => setKind(e.target.value)}
							disabled={pending}
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
						>
							<option value="slack">Slack</option>
							<option value="discord">Discord</option>
							<option value="webhook">Generic webhook</option>
						</select>
					</div>
					{kind === "discord" && (
						<p className="text-[11px] text-ink-2 bg-surface-2 border border-line rounded px-2.5 py-2">
							Discord: use the webhook URL from your channel settings and append{" "}
							<code className="font-mono">/slack</code> to the end — Tracelane
							sends a Slack-compatible payload, which Discord&apos;s Slack
							bridge accepts.
						</p>
					)}
					<div>
						<label
							htmlFor="dest-url"
							className="text-xs font-medium text-ink-2 block mb-1"
						>
							URL
						</label>
						<input
							id="dest-url"
							type="url"
							value={url}
							onChange={(e) => setUrl(e.target.value)}
							placeholder={urlPlaceholder}
							disabled={pending}
							required
							pattern="https://.*"
							title="URL must begin with https://"
							className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
						/>
						<p className="text-[11px] text-ink-3 mt-1">
							Must begin with https://
						</p>
					</div>
					{error && (
						<p
							role="alert"
							className="text-xs text-danger bg-danger-soft border border-danger/30 rounded px-2 py-1.5"
						>
							{error.message}
						</p>
					)}
					<div className="flex justify-end gap-2 pt-1">
						<button
							type="button"
							onClick={onClose}
							disabled={pending}
							className="px-4 py-2 rounded text-sm border border-line text-ink-2 hover:bg-surface-2 transition-colors disabled:opacity-50"
						>
							Cancel
						</button>
						<button
							type="submit"
							disabled={!name.trim() || !url.trim() || pending}
							className="px-4 py-2 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 disabled:opacity-40 transition-colors"
						>
							{pending ? "Adding…" : "Add"}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}

function DestinationsSection() {
	const qc = useQueryClient();
	const [showAdd, setShowAdd] = useState(false);
	// id of the destination currently pending test confirmation
	const [testingId, setTestingId] = useState<string | null>(null);
	const [testSuccess, setTestSuccess] = useState<string | null>(null);
	// id of destination pending delete confirmation
	const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);

	const { data, isLoading, isError } = useQuery({
		queryKey: ["alert-destinations"],
		queryFn: fetchDestinations,
		staleTime: 30_000,
	});

	const destinations = data?.destinations ?? [];

	const createMutation = useMutation({
		mutationFn: createDestination,
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: ["alert-destinations"] });
			setShowAdd(false);
		},
	});

	const deleteMutation = useMutation({
		mutationFn: deleteDestination,
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: ["alert-destinations"] });
			// Rules referencing this destination should also refresh.
			void qc.invalidateQueries({ queryKey: ["alert-rules"] });
			setPendingDeleteId(null);
		},
	});

	const testMutation = useMutation({
		mutationFn: testDestination,
		onSuccess: (_data, variables) => {
			setTestingId(null);
			setTestSuccess(variables);
			setTimeout(() => setTestSuccess(null), 4000);
		},
	});

	return (
		<div className="space-y-4">
			<SectionHeader
				title="Destinations"
				description="Webhook targets that receive alert notifications."
				onAdd={() => {
					createMutation.reset();
					setShowAdd(true);
				}}
				addLabel="+ Add destination"
			/>

			{isLoading && <LoadingState />}
			{isError && <SectionError message="Failed to load destinations." />}
			{deleteMutation.isError && (
				<p role="alert" className="text-sm text-danger">
					Could not delete destination: {deleteMutation.error.message}
				</p>
			)}
			{testMutation.isError && (
				<p role="alert" className="text-sm text-danger">
					Test alert failed: {testMutation.error.message}
				</p>
			)}
			{testSuccess && (
				<output className="text-sm text-ok block">
					Test alert sent successfully.
				</output>
			)}

			{!isLoading && !isError && destinations.length === 0 && (
				<EmptyState
					title="No destinations yet"
					description="Add one to start receiving alert notifications."
				/>
			)}

			{destinations.length > 0 && (
				<div className="rounded-lg border border-line overflow-hidden">
					<table className="w-full text-left">
						<thead className="bg-surface">
							<tr>
								<th className="py-2.5 px-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Name
								</th>
								<th className="py-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Type
								</th>
								<th className="py-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3 hidden sm:table-cell">
									URL
								</th>
								<th className="py-2.5 pr-4" />
							</tr>
						</thead>
						<tbody>
							{destinations.map((dest) => (
								<tr
									key={dest.id}
									className="border-t border-line last:border-0"
								>
									<td className="py-3 px-4 text-sm text-ink">{dest.name}</td>
									<td className="py-3 pr-4 text-xs text-ink-2">
										{KIND_LABELS[dest.kind] ?? dest.kind}
									</td>
									<td className="py-3 pr-4 text-xs text-ink-2 hidden sm:table-cell max-w-[14rem] truncate">
										{dest.url}
									</td>
									<td className="py-3 pr-4">
										{pendingDeleteId === dest.id ? (
											<div className="flex items-center gap-2">
												<span className="text-xs text-ink-2">Delete?</span>
												<button
													type="button"
													onClick={() => deleteMutation.mutate(dest.id)}
													disabled={deleteMutation.isPending}
													className="text-xs px-2 py-1 rounded bg-danger text-danger-on hover:bg-danger/90 disabled:opacity-50 transition-colors"
												>
													{deleteMutation.isPending ? "Deleting…" : "Confirm"}
												</button>
												<button
													type="button"
													onClick={() => setPendingDeleteId(null)}
													disabled={deleteMutation.isPending}
													className="text-xs px-2 py-1 rounded border border-line text-ink-2 hover:bg-surface-2 disabled:opacity-50 transition-colors"
												>
													Cancel
												</button>
											</div>
										) : (
											<div className="flex items-center gap-2">
												<button
													type="button"
													onClick={() => {
														setTestingId(dest.id);
														testMutation.reset();
														testMutation.mutate(dest.id);
													}}
													disabled={
														testMutation.isPending && testingId === dest.id
													}
													className="text-xs px-2 py-1 rounded border border-line text-ink-2 hover:text-ink hover:border-ink-3 disabled:opacity-50 transition-colors"
												>
													{testMutation.isPending && testingId === dest.id
														? "Sending…"
														: "Test"}
												</button>
												<button
													type="button"
													onClick={() => {
														setPendingDeleteId(dest.id);
														deleteMutation.reset();
													}}
													className="text-xs px-2 py-1 rounded border border-danger text-danger hover:bg-danger-soft transition-colors"
												>
													Delete
												</button>
											</div>
										)}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}

			{showAdd && (
				<AddDestinationDialog
					onClose={() => {
						setShowAdd(false);
						createMutation.reset();
					}}
					onCreate={(body) => createMutation.mutate(body)}
					pending={createMutation.isPending}
					error={createMutation.error}
				/>
			)}
		</div>
	);
}

// ─────────────────────────────────────────────
// Rules section
// ─────────────────────────────────────────────

function AddRuleDialog({
	destinations,
	onClose,
	onCreate,
	pending,
	error,
}: {
	destinations: AlertDestination[];
	onClose: () => void;
	onCreate: (body: {
		metric: string;
		comparator: string;
		threshold: number;
		window_minutes: number;
		destination_id: string;
	}) => void;
	pending: boolean;
	error: Error | null;
}) {
	const [metric, setMetric] = useState("error_rate");
	const [comparator, setComparator] = useState("gt");
	const [threshold, setThreshold] = useState("");
	const [windowMinutes, setWindowMinutes] = useState("60");
	const [destinationId, setDestinationId] = useState(destinations[0]?.id ?? "");

	const metricMeta = METRIC_META[metric] ?? { label: metric, unit: "" };

	const canSubmit =
		!pending &&
		threshold.trim() !== "" &&
		!Number.isNaN(Number(threshold)) &&
		destinationId !== "" &&
		windowMinutes.trim() !== "" &&
		Number(windowMinutes) >= 1 &&
		Number(windowMinutes) <= 44640;

	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
			<div className="bg-surface border border-line rounded-lg p-6 w-full max-w-md shadow-2xl space-y-4">
				<h3 className="text-base font-semibold text-ink">Add alert rule</h3>
				{destinations.length === 0 ? (
					<p className="text-sm text-ink-2">
						No destinations configured. Add a destination first, then come back
						to create a rule.
					</p>
				) : (
					<form
						onSubmit={(e) => {
							e.preventDefault();
							if (canSubmit) {
								onCreate({
									metric,
									comparator,
									threshold: Number(threshold),
									window_minutes: Number(windowMinutes),
									destination_id: destinationId,
								});
							}
						}}
						className="space-y-3"
					>
						<div>
							<label
								htmlFor="rule-metric"
								className="text-xs font-medium text-ink-2 block mb-1"
							>
								Metric
							</label>
							<select
								id="rule-metric"
								value={metric}
								onChange={(e) => setMetric(e.target.value)}
								disabled={pending}
								className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
							>
								<option value="error_rate">Error rate (%)</option>
								<option value="burn_rate">SLO burn rate (×)</option>
								<option value="latency_p95">p95 latency (ms)</option>
								<option value="cost_usd">Cost (USD)</option>
								<option value="quota_pct">Quota used (%)</option>
							</select>
						</div>
						<div className="flex gap-3">
							<div className="w-28 shrink-0">
								<label
									htmlFor="rule-comparator"
									className="text-xs font-medium text-ink-2 block mb-1"
								>
									Condition
								</label>
								<select
									id="rule-comparator"
									value={comparator}
									onChange={(e) => setComparator(e.target.value)}
									disabled={pending}
									className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
								>
									<option value="gt">is above</option>
									<option value="lt">is below</option>
								</select>
							</div>
							<div className="flex-1">
								<label
									htmlFor="rule-threshold"
									className="text-xs font-medium text-ink-2 block mb-1"
								>
									Threshold ({metricMeta.unit})
								</label>
								<input
									id="rule-threshold"
									type="number"
									value={threshold}
									onChange={(e) => setThreshold(e.target.value)}
									placeholder="e.g. 5"
									disabled={pending}
									required
									step="any"
									className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink font-mono tabular-nums placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
								/>
							</div>
						</div>
						<div>
							<label
								htmlFor="rule-window"
								className="text-xs font-medium text-ink-2 block mb-1"
							>
								Evaluation window (minutes)
							</label>
							<input
								id="rule-window"
								type="number"
								value={windowMinutes}
								onChange={(e) => setWindowMinutes(e.target.value)}
								min="1"
								max="44640"
								disabled={pending}
								required
								className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink font-mono tabular-nums placeholder:text-ink-3 focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
							/>
							<p className="text-[11px] text-ink-3 mt-1">
								1 – 44,640 minutes (up to 31 days)
							</p>
						</div>
						<div>
							<label
								htmlFor="rule-destination"
								className="text-xs font-medium text-ink-2 block mb-1"
							>
								Destination
							</label>
							<select
								id="rule-destination"
								value={destinationId}
								onChange={(e) => setDestinationId(e.target.value)}
								disabled={pending}
								className="w-full rounded border border-line bg-bg px-3 py-2 text-sm text-ink focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal disabled:opacity-50"
							>
								{destinations.map((d) => (
									<option key={d.id} value={d.id}>
										{d.name} ({KIND_LABELS[d.kind] ?? d.kind})
									</option>
								))}
							</select>
						</div>
						{error && (
							<p
								role="alert"
								className="text-xs text-danger bg-danger-soft border border-danger/30 rounded px-2 py-1.5"
							>
								{error.message}
							</p>
						)}
						<div className="flex justify-end gap-2 pt-1">
							<button
								type="button"
								onClick={onClose}
								disabled={pending}
								className="px-4 py-2 rounded text-sm border border-line text-ink-2 hover:bg-surface-2 transition-colors disabled:opacity-50"
							>
								Cancel
							</button>
							<button
								type="submit"
								disabled={!canSubmit}
								className="px-4 py-2 rounded text-sm bg-accent text-accent-on hover:bg-accent/90 disabled:opacity-40 transition-colors"
							>
								{pending ? "Adding…" : "Add rule"}
							</button>
						</div>
					</form>
				)}
				{destinations.length === 0 && (
					<div className="flex justify-end">
						<button
							type="button"
							onClick={onClose}
							className="px-4 py-2 rounded text-sm border border-line text-ink-2 hover:bg-surface-2 transition-colors"
						>
							Close
						</button>
					</div>
				)}
			</div>
		</div>
	);
}

function RulesSection({
	destinations,
}: {
	destinations: AlertDestination[];
}) {
	const qc = useQueryClient();
	const [showAdd, setShowAdd] = useState(false);
	const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);

	const { data, isLoading, isError } = useQuery({
		queryKey: ["alert-rules"],
		queryFn: fetchRules,
		staleTime: 30_000,
	});

	const rules = data?.rules ?? [];

	const createMutation = useMutation({
		mutationFn: createRule,
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: ["alert-rules"] });
			setShowAdd(false);
		},
	});

	const deleteMutation = useMutation({
		mutationFn: deleteRule,
		onSuccess: () => {
			void qc.invalidateQueries({ queryKey: ["alert-rules"] });
			setPendingDeleteId(null);
		},
	});

	const destById = new Map(destinations.map((d) => [d.id, d]));

	return (
		<div className="space-y-4">
			<SectionHeader
				title="Alert rules"
				description="Trigger a notification when a metric crosses a threshold."
				onAdd={() => {
					createMutation.reset();
					setShowAdd(true);
				}}
				addLabel="+ Add rule"
			/>

			{isLoading && <LoadingState />}
			{isError && <SectionError message="Failed to load alert rules." />}
			{deleteMutation.isError && (
				<p role="alert" className="text-sm text-danger">
					Could not delete rule: {deleteMutation.error.message}
				</p>
			)}

			{!isLoading && !isError && rules.length === 0 && (
				<EmptyState
					title="No alert rules yet"
					description="Add one to start monitoring your agents."
				/>
			)}

			{rules.length > 0 && (
				<div className="rounded-lg border border-line overflow-hidden">
					<table className="w-full text-left">
						<thead className="bg-surface">
							<tr>
								<th className="py-2.5 px-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Metric
								</th>
								<th className="py-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									Condition
								</th>
								<th className="py-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3 hidden sm:table-cell">
									Window
								</th>
								<th className="py-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3 hidden md:table-cell">
									Destination
								</th>
								<th className="py-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wide text-ink-3">
									State
								</th>
								<th className="py-2.5 pr-4" />
							</tr>
						</thead>
						<tbody>
							{rules.map((rule) => {
								const meta = METRIC_META[rule.metric] ?? {
									label: rule.metric,
									unit: "",
								};
								const dest = destById.get(rule.destination_id);
								return (
									<tr
										key={rule.id}
										className="border-t border-line last:border-0"
									>
										<td className="py-3 px-4 text-sm text-ink">{meta.label}</td>
										<td className="py-3 pr-4 text-xs text-ink-2 font-mono tabular-nums whitespace-nowrap">
											{rule.comparator === "gt" ? ">" : "<"}{" "}
											{String(rule.threshold)} {meta.unit}
										</td>
										<td className="py-3 pr-4 text-xs text-ink-2 hidden sm:table-cell font-mono tabular-nums">
											{formatWindow(rule.window_minutes)}
										</td>
										<td className="py-3 pr-4 text-xs text-ink-2 hidden md:table-cell truncate max-w-[10rem]">
											{dest ? dest.name : <span className="text-ink-3">—</span>}
										</td>
										<td className="py-3 pr-4">
											<LastStateBadge state={rule.last_state} />
										</td>
										<td className="py-3 pr-4">
											{pendingDeleteId === rule.id ? (
												<div className="flex items-center gap-2">
													<span className="text-xs text-ink-2">Delete?</span>
													<button
														type="button"
														onClick={() => deleteMutation.mutate(rule.id)}
														disabled={deleteMutation.isPending}
														className="text-xs px-2 py-1 rounded bg-danger text-danger-on hover:bg-danger/90 disabled:opacity-50 transition-colors"
													>
														{deleteMutation.isPending ? "Deleting…" : "Confirm"}
													</button>
													<button
														type="button"
														onClick={() => setPendingDeleteId(null)}
														disabled={deleteMutation.isPending}
														className="text-xs px-2 py-1 rounded border border-line text-ink-2 hover:bg-surface-2 disabled:opacity-50 transition-colors"
													>
														Cancel
													</button>
												</div>
											) : (
												<button
													type="button"
													onClick={() => {
														setPendingDeleteId(rule.id);
														deleteMutation.reset();
													}}
													className="text-xs px-2 py-1 rounded border border-danger text-danger hover:bg-danger-soft transition-colors"
												>
													Delete
												</button>
											)}
										</td>
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}

			{showAdd && (
				<AddRuleDialog
					destinations={destinations}
					onClose={() => {
						setShowAdd(false);
						createMutation.reset();
					}}
					onCreate={(body) => createMutation.mutate(body)}
					pending={createMutation.isPending}
					error={createMutation.error}
				/>
			)}
		</div>
	);
}

// ─────────────────────────────────────────────
// Root export
// ─────────────────────────────────────────────

/**
 * AlertsManager — two-section view: Destinations + Rules.
 *
 * Destinations must exist before rules can reference them, so the Rules
 * section receives the already-fetched destination list as a prop to
 * populate the destination select without a second network round-trip.
 */
export function AlertsManager() {
	const { data } = useQuery({
		queryKey: ["alert-destinations"],
		queryFn: fetchDestinations,
		staleTime: 30_000,
	});

	const destinations = data?.destinations ?? [];

	return (
		<div className="space-y-8">
			<DestinationsSection />
			<div className="border-t border-line" />
			<RulesSection destinations={destinations} />
		</div>
	);
}
