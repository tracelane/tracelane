"use client";
/**
 * Gateway › Cache — `OG-51`: the workspace's response-cache controls.
 * `GET /v1/cache` (effective settings with the SOURCE of each value, epochs, 24 h stats),
 * `PUT /v1/cache/settings` (a full document) and `POST /v1/cache/invalidate`. Invalidation
 * is a generation counter: the gateway stops SERVING the scope's answers; it never claims
 * the stored rows are erased (the response says `effect: stop_serving`).
 */

import { Button } from "@tracelanedev/ui";
import { useEffect, useState } from "react";
import {
	Boundary,
	RefusalNote,
	useCan,
	useControlQuery,
	useControlWrite,
} from "./control";
import { EmptyNote, Field, Panel, WhyDisabled, inputClass } from "./fields";

type Mode = "inherit" | "on" | "off";
type NamespaceBy = "workspace" | "project" | "end_user" | "key";

interface Sourced<T> {
	value: T;
	source: string;
}

export interface CacheView {
	plan: { cache_control: boolean; ttl_hours: number | null };
	settings: {
		mode: Sourced<Mode>;
		ttl_hours: Sourced<number | null>;
		namespace_by: Sourced<NamespaceBy>;
		semantic: Sourced<boolean>;
		updated_at: string | null;
	};
	effective: {
		enabled: boolean;
		why_off: string | null;
		ttl_hours: number | null;
		ttl_source: string;
		ttl_ceiling_hours: number;
	};
	epochs: { scope: string; epoch: number }[];
	stats: {
		window_hours: number;
		hits: number | null;
		cost_saved_usd: number | null;
		stats_unavailable: boolean;
	};
}

const WHY_OFF: Record<string, string> = {
	operator_cache_not_configured:
		"The gateway operator has not configured a response cache.",
	key_cache_off: "This key has the cache turned off.",
	workspace_cache_off: "This workspace has the cache turned off.",
	content_capture_off:
		"Content capture is off, and the cache is not cached unless it is turned on explicitly.",
};

function SettingsForm({
	view,
	allowed,
}: { view: CacheView; allowed: boolean }) {
	const s = view.settings;
	const [mode, setMode] = useState<Mode>(s.mode.value);
	const [ttl, setTtl] = useState(
		s.ttl_hours.value === null ? "" : String(s.ttl_hours.value),
	);
	const [ns, setNs] = useState<NamespaceBy>(s.namespace_by.value);
	const [semantic, setSemantic] = useState(s.semantic.value);
	// Re-seed when the server's document changes (after a save or a refetch).
	useEffect(() => {
		setMode(s.mode.value);
		setTtl(s.ttl_hours.value === null ? "" : String(s.ttl_hours.value));
		setNs(s.namespace_by.value);
		setSemantic(s.semantic.value);
	}, [s.mode.value, s.ttl_hours.value, s.namespace_by.value, s.semantic.value]);
	const save = useControlWrite<
		{ changed: boolean },
		{
			mode: Mode;
			ttl_hours: number | null;
			namespace_by: NamespaceBy;
			semantic: boolean;
		}
	>("PUT", "cache/settings", ["cache"]);
	const fieldError = (f: string) =>
		save.error?.refusal.field === f ? save.error.refusal.message : null;
	const ttlNumber = ttl.trim() === "" ? null : Number(ttl);
	const ttlInvalid =
		ttlNumber !== null && (!Number.isInteger(ttlNumber) || ttlNumber < 1);
	return (
		<div className="space-y-3">
			<div className="grid gap-3 sm:grid-cols-2">
				<Field
					label="Response cache"
					hint={`Source: ${s.mode.source}. “Inherit” follows the operator and plan defaults.`}
					error={fieldError("mode")}
				>
					<select
						className={inputClass}
						disabled={!allowed || save.isPending}
						value={mode}
						onChange={(e) => setMode(e.target.value as Mode)}
					>
						<option value="inherit">Inherit</option>
						<option value="on">On</option>
						<option value="off">Off</option>
					</select>
				</Field>
				<Field
					label="TTL (hours)"
					hint={`Blank = the plan default. Source: ${s.ttl_hours.source}. At most ${view.effective.ttl_ceiling_hours}.`}
					error={
						fieldError("ttl_hours") ??
						(ttlInvalid ? "Whole hours, at least 1, or blank." : null)
					}
				>
					<input
						className={inputClass}
						inputMode="numeric"
						disabled={!allowed || save.isPending}
						value={ttl}
						onChange={(e) => setTtl(e.target.value)}
					/>
				</Field>
				<Field
					label="Cache namespace"
					hint={`One cache per… Source: ${s.namespace_by.source}.`}
					error={fieldError("namespace_by")}
				>
					<select
						className={inputClass}
						disabled={!allowed || save.isPending}
						value={ns}
						onChange={(e) => setNs(e.target.value as NamespaceBy)}
					>
						<option value="workspace">Workspace</option>
						<option value="project">Project</option>
						<option value="end_user">End user</option>
						<option value="key">API key</option>
					</select>
				</Field>
				<Field label="Semantic matching" error={fieldError("semantic")}>
					<span className="flex items-center gap-2 py-1.5 text-sm">
						<input
							type="checkbox"
							disabled={!allowed || save.isPending}
							checked={semantic}
							onChange={(e) => setSemantic(e.target.checked)}
						/>
						Serve a near-identical prompt’s answer
					</span>
				</Field>
			</div>
			<RefusalNote error={save.error} fieldOnly />
			<div className="flex items-center gap-3">
				<Button
					variant="primary"
					size="sm"
					disabled={!allowed || save.isPending || ttlInvalid}
					onClick={() =>
						save.mutate({
							mode,
							ttl_hours: ttlNumber,
							namespace_by: ns,
							semantic,
						})
					}
				>
					{save.isPending ? "Saving…" : "Save cache settings"}
				</Button>
				{save.isSuccess ? (
					<output className="text-xs text-ok-ink">
						{save.data?.changed ? "Saved" : "Nothing changed"}
					</output>
				) : null}
			</div>
		</div>
	);
}

function Invalidate({ allowed }: { allowed: boolean }) {
	const [scope, setScope] = useState("workspace");
	const inv = useControlWrite<
		{ scope: string; epoch: number; note: string },
		{ scope: string }
	>("POST", "cache/invalidate", ["cache"]);
	return (
		<div className="space-y-3">
			<Field
				label="Scope"
				hint="workspace, project:<uuid>, key:<uuid> or model:<name>"
				error={
					inv.error?.refusal.field === "scope"
						? inv.error.refusal.message
						: null
				}
			>
				<input
					className={inputClass}
					disabled={!allowed || inv.isPending}
					value={scope}
					onChange={(e) => setScope(e.target.value)}
				/>
			</Field>
			<RefusalNote error={inv.error} fieldOnly />
			<div className="flex items-center gap-3">
				<Button
					size="sm"
					disabled={!allowed || inv.isPending || !scope.trim()}
					onClick={() => inv.mutate({ scope: scope.trim() })}
				>
					{inv.isPending ? "Invalidating…" : "Stop serving this scope"}
				</Button>
				{inv.data ? (
					<output className="text-xs text-ok-ink">
						{inv.data.scope}: generation {inv.data.epoch}. {inv.data.note}
					</output>
				) : null}
			</div>
		</div>
	);
}

export function CacheSettings() {
	const q = useControlQuery<CacheView>("cache");
	const { allowed, reason } = useCan("edit_policies");
	return (
		<Boundary query={q} resource="cache settings" rows={3}>
			{(view) => (
				<div className="space-y-6">
					<Panel
						id="cache-effective"
						title="Cache"
						description="Whether the gateway is serving cached answers for this workspace right now, and why."
					>
						<p className="text-sm" data-testid="cache-effective">
							{view.effective.enabled
								? `On — TTL ${view.effective.ttl_hours ?? "default"} h (${view.effective.ttl_source}).`
								: `Off — ${WHY_OFF[view.effective.why_off ?? ""] ?? "no reason reported"}`}
						</p>
						{view.stats.stats_unavailable ? (
							<EmptyNote>
								Hit statistics are unavailable right now; this is not a zero.
							</EmptyNote>
						) : (
							<p className="text-sm text-ink-2">
								Last {view.stats.window_hours} h: {view.stats.hits} hits, $
								{view.stats.cost_saved_usd?.toFixed(4)} saved.
							</p>
						)}
						{!view.plan.cache_control ? (
							<EmptyNote>
								Turning the cache on, or setting a TTL, is not part of this
								workspace’s plan. “Inherit”, “Off” and the namespace are still
								yours to set.
							</EmptyNote>
						) : null}
					</Panel>
					<Panel
						id="cache-settings"
						title="Settings"
						description="One document for the whole workspace; a key can only narrow it."
					>
						<SettingsForm view={view} allowed={allowed} />
						<WhyDisabled reason={reason} />
					</Panel>
					<Panel
						id="cache-invalidate"
						title="Invalidate"
						description="Bumps a generation counter: cached answers for the scope stop being served. Stored rows are not erased; they age out by TTL."
					>
						<Invalidate allowed={allowed} />
						{view.epochs.length > 0 ? (
							<p className="text-xs text-ink-3">
								Generations:{" "}
								{view.epochs.map((e) => `${e.scope} ${e.epoch}`).join(" · ")}
							</p>
						) : null}
					</Panel>
				</div>
			)}
		</Boundary>
	);
}
