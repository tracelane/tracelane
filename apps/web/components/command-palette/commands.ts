/**
 * OBS-02 — what ⌘K can do (`specs/OBS-02-command-palette.md`). Pure: no fetch, no
 * router, so every rule here is a unit test rather than a render.
 *
 * Three kinds of command, in this order:
 *   1. derived from the QUERY — a trace id opens that trace; ≥ 4 chars searches
 *      traces (OBS-01's minimum); any text filters traces by model;
 *   2. VERBS — each lands where the action is done. The palette never performs a
 *      write itself;
 *   3. every SCREEN — derived from the sidebar's own `sections`, so a new page can
 *      never be missing from ⌘K again (the palette used to keep its own list of 5).
 */

import { sections } from "@/components/layout/nav-config";

export interface Command {
	id: string;
	label: string;
	description?: string;
	href: string;
	/** Calls an existing page-owned dialog or clipboard handler; never a mutation. */
	target?: boolean;
	group: "query" | "action" | "navigation";
}

const VERBS: Command[] = [
	{
		id: "verb-alias",
		label: "Add a model alias",
		description: "Settings → Gateway — swap the model behind a name, no deploy",
		href: "/settings/gateway",
		group: "action",
	},
	{
		id: "verb-api-key",
		label: "Create an API key",
		description: "Settings → API keys",
		href: "/settings/api-keys",
		group: "action",
	},
	{
		id: "verb-provider",
		label: "Connect an LLM provider",
		description: "Settings → LLM providers — add your own key",
		href: "/settings/providers",
		group: "action",
	},
	{
		id: "verb-playground",
		label: "Run a prompt",
		description: "Playground — the run lands on its own trace",
		href: "/playground",
		group: "action",
	},
	{
		id: "verb-compare",
		label: "Compare two traces",
		description: "Traces → Compare",
		href: "/traces/compare",
		group: "action",
	},
	{
		id: "verb-invite",
		label: "Invite a teammate",
		description: "Settings → Team",
		href: "/settings/team",
		group: "action",
	},
	{
		id: "verb-dashboard",
		label: "Build a dashboard",
		description: "Dashboards → New",
		href: "/dashboards/new",
		group: "action",
	},
	{
		id: "verb-verify",
		label: "Verify the audit ledger",
		description: "Audit — tamper-evident chain and anchors",
		href: "/audit",
		group: "action",
	},
];

/** Every sidebar destination, in sidebar order, each labelled with its group. */
export function destinations(): Command[] {
	return sections.flatMap((section) =>
		section.items.map((item) => ({
			id: `nav-${item.href}`,
			label: item.label,
			description: section.label ? `Go to · ${section.label}` : "Go to",
			href: item.href,
			group: "navigation" as const,
		})),
	);
}

const DASHED_UUID =
	/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX32 = /^[0-9a-f]{32}$/i;

/**
 * A trace id in the form trace pages use (dashed UUID), or `null`. A 32-hex W3C id
 * (the `traceparent` form) is normalised losslessly; anything else is not an id.
 */
export function asTraceId(raw: string): string | null {
	const q = raw.trim();
	if (DASHED_UUID.test(q)) return q.toLowerCase();
	if (HEX32.test(q)) {
		const h = q.toLowerCase();
		return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
	}
	return null;
}

/** OBS-01's free-text search minimum — the gateway refuses shorter queries. */
export const MIN_SEARCH_CHARS = 4;

function matches(c: Command, q: string): boolean {
	const needle = q.toLowerCase();
	return (
		c.label.toLowerCase().includes(needle) ||
		(c.description?.toLowerCase().includes(needle) ?? false)
	);
}

/** The commands for a query, most specific first. */
export function buildCommands(
	rawQuery: string,
	context: readonly Command[] = [],
): Command[] {
	const q = rawQuery.trim();
	if (!q) return [...context, ...VERBS, ...destinations()];

	const derived: Command[] = [];
	const traceId = asTraceId(q);
	if (traceId) {
		derived.push({
			id: "query-trace",
			label: `Open trace ${traceId}`,
			href: `/traces/${traceId}`,
			group: "query",
		});
	}
	if (q.length >= MIN_SEARCH_CHARS) {
		derived.push({
			id: "query-search",
			label: `Search traces for “${q}”`,
			description: "Full-text search across span attributes",
			href: `/traces?q=${encodeURIComponent(q)}`,
			group: "query",
		});
	}
	if (!traceId) {
		derived.push({
			id: "query-model",
			label: `Traces using model “${q}”`,
			href: `/traces?model=${encodeURIComponent(q)}`,
			group: "query",
		});
	}
	const listed = [...context, ...VERBS, ...destinations()].filter((c) =>
		matches(c, q),
	);
	// Named commands first when the query names one; the query-derived fallbacks after.
	return listed.length > 0 && !traceId
		? [...listed, ...derived]
		: [...derived, ...listed];
}
