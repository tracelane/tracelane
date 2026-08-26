/**
 * Spend attribution (GWY-43, Sprint 1 item 5) — where the money went, by API
 * key, model or provider.
 *
 * **Why this could not exist before.** Spans carried tenant, model and provider,
 * so "spend by model" was answerable and "spend by KEY" was not — not hard,
 * *impossible*, because the fact was never recorded. ClickHouse migration 16
 * added the `api_key_id` dimension and the gateway began writing it, so a "by
 * key" answer starts at that deploy and cannot see further back. The panel says
 * so; a short history must not read as low spend.
 *
 * **The honesty this panel owes.** `pricing.rs` returns no cost for a model
 * whose price we do not know, and the gateway omits the attribute rather than
 * writing 0 — but every read path used to wrap the extract in
 * `if(isFinite AND > 0, x, 0)`, so an honestly-unknown cost arrived here as a
 * confident **$0.00**. `unpriced_requests` is rendered beside the total for
 * exactly that reason: it is what separates a cheap window from an unpriced one.
 *
 * **P1 design pass (2026-08-22) — presentation only.** The six columns, their
 * values, `usd()`, `label()` and the `?by=` navigation are untouched. The table
 * is the shared `Table` primitive (it was a private `<thead>` at `text-xs` with
 * its own border treatment — one of the app's seven), the heading is the same
 * `SectionLabel` the rest of `/gateway` uses, and the numeric columns are now
 * right-aligned AND tabular AND monospace together, which is the only way a
 * column of costs can be compared down the page.
 */

import type { CostBreakdown } from "@/lib/gateway-ops";
import {
	Badge,
	Card,
	EmptyState,
	SegmentedControl,
	TBody,
	TD,
	TH,
	THead,
	TR,
	Table,
} from "@tracelanedev/ui";
import Link from "next/link";
import { SectionLabel } from "./SectionLabel";

const DIMENSIONS = [
	{ by: "key", label: "API key" },
	{ by: "model", label: "Model" },
	{ by: "provider", label: "Provider" },
] as const;

/** USD with enough precision to be useful at agent scale, where a request can
 *  cost a fraction of a cent. Never rounded to `$0.00` — see `usd` below. */
function usd(v: number): string {
	if (v <= 0) return "—";
	if (v < 0.01) return `$${v.toFixed(4)}`;
	return `$${v.toLocaleString(undefined, {
		minimumFractionDigits: 2,
		maximumFractionDigits: 2,
	})}`;
}

/** A key id is a UUID; showing all 36 characters buys nothing in a table. */
function label(by: CostBreakdown["by"], dimension: string): string {
	if (dimension === "") {
		// NOT "unattributed": a session-authenticated request genuinely has no
		// API key, and calling that a gap would send someone hunting a bug.
		return by === "key" ? "Dashboard session (no key)" : "(not recorded)";
	}
	return by === "key" ? `${dimension.slice(0, 8)}…` : dimension;
}

export function SpendAttribution({
	data,
	range,
	by,
}: {
	data: CostBreakdown | null;
	range?: string;
	by: CostBreakdown["by"];
}) {
	/**
	 * Link mode: this is a Server Component and the dimension is a `?by=` URL
	 * param, so every option must be a real href.
	 *
	 * It was `role="tablist"` / `role="tab"` / `aria-selected` over three links.
	 * That claimed the ARIA tab contract while implementing neither half of it —
	 * no roving tabindex, no `aria-controls` onto a `role="tabpanel"` — and the
	 * options navigate the whole page rather than swapping a panel, so they were
	 * never tabs. The primitive announces `role="group"` with the SAME accessible
	 * name and marks the chosen option `aria-current`, which is what these links
	 * actually are.
	 *
	 * `linkAs={Link}` is load-bearing and NOT cosmetic: without it the primitive
	 * renders a bare `<a>`, which is a full document reload rather than a soft
	 * navigation. The URLs are byte-identical either way, which is why a diff
	 * review cannot see the difference.
	 */
	const tabs = (
		<SegmentedControl
			linkAs={Link}
			label="Attribute spend by"
			value={by}
			options={DIMENSIONS.map((d) => ({ value: d.by, label: d.label }))}
			hrefFor={(v) => {
				const params = new URLSearchParams();
				if (range) params.set("range", range);
				params.set("by", v);
				return `/gateway?${params.toString()}`;
			}}
		/>
	);

	/* The section head: the same eyebrow + hairline + right-hand control the rest
	   of /gateway uses, with the honesty line beneath it. It was a `text-sm
	   font-semibold` `<h2>` — a CARD title role on a page SECTION, so this block
	   and the "Router events" block below announced themselves one level lower
	   than the metric groups above them. */
	const header = (
		<>
			<SectionLabel action={tabs}>Spend attribution</SectionLabel>
			<p className="max-w-3xl text-xs text-ink-3">
				Real per-request cost, summed from what each span recorded. Never an
				estimate.
			</p>
		</>
	);

	// Gateway unreachable is NOT zero spend.
	if (data === null) {
		return (
			<section aria-label="Spend attribution" className="space-y-3">
				{header}
				<EmptyState
					title="Waiting on the gateway"
					description="Spend appears here once the gateway is reachable."
				/>
			</section>
		);
	}

	if (data.rows.length === 0) {
		return (
			<section aria-label="Spend attribution" className="space-y-3">
				{header}
				<EmptyState
					title="No requests in this window"
					description="Route a request through the gateway and its cost is attributed here."
				/>
			</section>
		);
	}

	return (
		<section aria-label="Spend attribution" className="space-y-3">
			{header}

			<div className="flex flex-wrap items-center gap-2 text-xs">
				<span className="text-ink-2">
					Total{" "}
					<span className="font-mono font-medium tabular-nums text-ink">
						{usd(data.total_cost_usd)}
					</span>{" "}
					across{" "}
					<span className="font-mono tabular-nums">
						{data.total_requests.toLocaleString()}
					</span>{" "}
					requests
				</span>
				{/* The number that keeps the total honest. Rendered as a warning, not
				    hidden, because a big unpriced count means the total is a FLOOR. */}
				{data.unpriced_requests > 0 && (
					<Badge tone="warn">
						{data.unpriced_requests.toLocaleString()} unpriced — total is a
						lower bound
					</Badge>
				)}
				{/* R94. An experiment is DELIBERATELY expensive, so leaving its spend
				    inside the production figure is the worst possible conflation. The
				    total is not redefined — it is decomposed and the part is named,
				    the same shape `unpriced` already uses beside it. Rendered only
				    when there IS eval spend: a `0` badge on every workspace that has
				    never run an eval is noise, and its absence is not ambiguous
				    because the number is measured either way. */}
				{data.eval_requests > 0 && (
					<Badge tone="info">
						{usd(data.eval_cost_usd)} eval / experiment (
						{data.eval_requests.toLocaleString()} req)
					</Badge>
				)}
			</div>

			{data.attribution_begins_note && (
				<p className="text-2xs text-ink-3">{data.attribution_begins_note}</p>
			)}

			<Card quiet className="overflow-hidden">
				{/* `-mt-px` pulls the header band's top hairline under the card border,
				    where `overflow-hidden` clips it — otherwise the card edge and
				    `THead`'s `border-y` stack into a 2px rule along the top alone. */}
				<div className="-mt-px">
					<Table>
						<THead>
							<TR>
								<TH>{DIMENSIONS.find((d) => d.by === by)?.label}</TH>
								<TH numeric>Requests</TH>
								<TH numeric>Unpriced</TH>
								<TH numeric>Input tokens</TH>
								<TH numeric>Output tokens</TH>
								<TH numeric>Cost</TH>
							</TR>
						</THead>
						<TBody>
							{data.rows.map((r) => (
								<TR key={`${by}:${r.dimension}`}>
									{/* A key id / model string / provider id is a technical
									    identifier in a left column: mono, not right-aligned.
									    The `title` carries the untruncated value. */}
									<TD mono>
										<span title={r.dimension || undefined}>
											{label(by, r.dimension)}
										</span>
									</TD>
									<TD numeric muted>
										{r.requests.toLocaleString()}
									</TD>
									<TD numeric>
										{r.unpriced_requests > 0 ? (
											<span className="text-warn-ink">
												{r.unpriced_requests.toLocaleString()}
											</span>
										) : (
											<span className="text-ink-3">—</span>
										)}
									</TD>
									<TD numeric muted>
										{r.input_tokens.toLocaleString()}
									</TD>
									<TD numeric muted>
										{r.output_tokens.toLocaleString()}
									</TD>
									{/* Cost is the column this table exists for, so it keeps
									    primary ink and medium weight while its neighbours are
									    muted — the row's subject against the row's context. */}
									<TD numeric className="font-medium">
										{usd(r.cost_usd)}
									</TD>
								</TR>
							))}
						</TBody>
					</Table>
				</div>
			</Card>
		</section>
	);
}
