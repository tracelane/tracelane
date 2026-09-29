import { TBody, TD, TH, THead, TR, Table } from "@tracelanedev/ui";
import type { ReactNode } from "react";
// Extracted from page.tsx 2026-09-23. Next 15 refuses any named export from a
// page file that is not one of its own contract fields, and `next build` is the
// ONLY thing that enforces it — `tsc` and the full gate both pass with the export
// in place, so this reached the deploy. The view lives here so the test can import
// it without putting a non-contract export on the route.

type Routing = { provider: string; prefixes: string[] };
export type GatewaySettings = {
	cache: {
		enabled: boolean;
		suspended: boolean;
		operator_ttl_hours: number | null;
		plan_ttl_hours: number | null;
		configurable: boolean;
		threshold: number | null;
		max_scan_entries: number | null;
	};
	limits: {
		available: boolean;
		rate_limit_rpm: number | null;
		workspace_budget_micro_usd: number | null;
		spend_ceiling_micro_usd: number | null;
	};
	routing: {
		native: Routing[];
		catalog: Routing[];
		aliases: { name: string; provider: string; upstream_model: string }[];
	};
	failover: {
		opt_in: boolean;
		retries: number;
		backoff_ms: number;
		chain: { provider: string; model: string }[];
	};
};
const money = (value: number | null) =>
	value == null
		? "Unavailable"
		: new Intl.NumberFormat("en-US", {
				style: "currency",
				currency: "USD",
			}).format(value / 1_000_000);
export function GatewaySettingsView({
	data,
	aliasManager,
	failoverManager,
}: {
	data: GatewaySettings;
	/** GWY-27: the workspace's own, editable aliases (a client island, so the page
	 * mounts it — this view stays a pure render of the gateway's report). */
	aliasManager?: ReactNode;
	/** GWY-52: the workspace's own, editable failover (a client island). */
	failoverManager?: ReactNode;
}) {
	return (
		<div className="space-y-6">
			<div>
				<h2 className="t-h2">Gateway settings</h2>
				<p className="text-sm text-ink-2">
					Configuration reported by the gateway serving this request — settings,
					not measured outcomes. Plan caps use the same cached entitlements as
					request admission. Model aliases below are yours to edit; the rest is
					set by your plan or the operator.
				</p>
			</div>
			<section className="space-y-2">
				<h3 className="t-h3">Response cache</h3>
				<p>
					{data.cache.suspended
						? "Suspended: a prompt canary is active or its state is unavailable"
						: data.cache.enabled
							? "Enabled"
							: "Disabled by the operator"}
					. Buffered chat completions only; streaming chat, native messages and
					embeddings do not reuse responses.
				</p>
				<p>
					Any plan can send <code>x-tracelane-cache: bypass</code> to skip both
					lookup and storage.
				</p>
				<p>
					{data.cache.configurable
						? "Your plan allows explicit cache control."
						: "Explicit cache control requires an eligible plan and available entitlements."}{" "}
					Send <code>x-tracelane-cache: use</code> or{" "}
					<code>x-tracelane-cache: ttl=&lt;hours&gt;</code> (hours). The
					effective TTL is the smallest of your request, plan ceiling and
					operator TTL.
				</p>
				{data.cache.plan_ttl_hours === 0 ? (
					<p className="rounded-[var(--radius-control)] bg-surface-2 px-3 py-2 text-sm text-ink">
						Your plan&apos;s cache ceiling is 0 hours, so responses are not
						cached for this workspace — the effective TTL is the smallest of the
						three limits below.{" "}
						<a className="text-action-ink underline" href="/plans">
							Compare plans
						</a>
					</p>
				) : null}
				<dl className="grid grid-cols-2 gap-2 text-sm">
					<dt>Operator TTL</dt>
					<dd>
						{data.cache.operator_ttl_hours == null
							? "Unavailable"
							: `${data.cache.operator_ttl_hours} hours`}
					</dd>
					<dt>Plan ceiling</dt>
					<dd>
						{data.cache.plan_ttl_hours == null
							? "Unavailable"
							: `${data.cache.plan_ttl_hours} hours`}
					</dd>
					<dt>Similarity threshold</dt>
					<dd>
						{typeof data.cache.threshold === "number"
							? data.cache.threshold.toFixed(2)
							: "Unavailable"}
					</dd>
					<dt>Maximum rows scanned per lookup</dt>
					<dd>{data.cache.max_scan_entries ?? "Unavailable"}</dd>
				</dl>
				<p className="text-sm text-ink-2">
					Configured requests return <code>x-tracelane-cache-ttl-hours</code>{" "}
					and <code>x-tracelane-cache-bound</code>, identifying the requested,
					plan or operator bound. Unsupported opt-in is refused. Provider-side
					prompt caching is separate.
				</p>
			</section>
			<section className="space-y-2">
				<h3 className="t-h3">Workspace caps</h3>
				{!data.limits.available ? (
					<p>Entitlements unavailable. No plan limits can be confirmed.</p>
				) : (
					<dl className="grid grid-cols-2 gap-2 text-sm">
						<dt>Requests per minute</dt>
						<dd>{data.limits.rate_limit_rpm ?? "No workspace cap"}</dd>
						<dt>Monthly budget</dt>
						<dd>
							{data.limits.workspace_budget_micro_usd === 0
								? "Not configured"
								: money(data.limits.workspace_budget_micro_usd)}
						</dd>
						<dt>Spend ceiling</dt>
						<dd>
							{data.limits.spend_ceiling_micro_usd == null
								? "Not configured"
								: money(data.limits.spend_ceiling_micro_usd)}
						</dd>
					</dl>
				)}
				<p className="text-sm text-ink-2">
					API keys may impose tighter limits. These caps do not show remaining
					balance.
				</p>
			</section>
			<section className="space-y-2">
				<h3 className="t-h3">Failover</h3>
				{failoverManager}
				<h4 className="font-medium">Operator default</h4>
				<p>
					Without a workspace setting, cross-provider failover is opt-in per
					chat request (<code>X-Tracelane-Failover: cross-provider</code>).
					Native messages and embeddings do not fail over.
				</p>
				<p>
					Same-provider retries: {data.failover.retries}; backoff:{" "}
					{data.failover.backoff_ms} ms.
				</p>
				<ol className="list-decimal pl-5">
					{data.failover.chain.map((hop) => (
						<li key={`${hop.provider}/${hop.model}`} className="break-all">
							{hop.provider} → {hop.model}
						</li>
					))}
				</ol>
				<p className="text-sm text-ink-2">
					Candidates require a usable credential and must pass the request’s
					failover checks.
				</p>
			</section>
			<section className="space-y-2">
				<h3 className="t-h3">Model routing</h3>
				<p>
					Your workspace aliases resolve first, then operator aliases, then
					native prefixes, then catalog prefixes. Catalog namespaced prefixes
					precede bare prefixes; longest bare prefix wins. Unmatched models are
					refused. A route does not confirm that your workspace has a provider
					key.
				</p>
				{aliasManager}
				<h4 className="font-medium">Operator aliases</h4>
				{data.routing.aliases.length === 0 ? (
					<p>No operator aliases configured.</p>
				) : (
					<ul>
						{data.routing.aliases.map((alias) => (
							<li className="break-all" key={alias.name}>
								{alias.name} → {alias.provider} / {alias.upstream_model}
							</li>
						))}
					</ul>
				)}
				<details className="rounded-[var(--radius-control)] border border-line">
					<summary className="cursor-pointer px-3 py-2 text-sm text-ink-2">
						All native and catalog prefix mappings (
						{data.routing.native.length + data.routing.catalog.length}{" "}
						providers) — how a model name picks its provider
					</summary>
					<div className="overflow-x-auto px-3 pb-3">
						<Table className="w-full text-left text-sm">
							<THead>
								<TR>
									<TH>Source</TH>
									<TH>Provider</TH>
									<TH>Model starts with</TH>
								</TR>
							</THead>
							<TBody>
								{(["native", "catalog"] as const).flatMap((kind) =>
									data.routing[kind].map((row) => (
										<TR key={`${kind}/${row.provider}`}>
											<TD>{kind}</TD>
											<TD>{row.provider}</TD>
											<TD className="break-all">
												{row.prefixes.join(", ") || "No prefix mapping"}
											</TD>
										</TR>
									)),
								)}
							</TBody>
						</Table>
					</div>
				</details>
			</section>
		</div>
	);
}
