/**
 * Support widget taxonomy — the single source of truth for the "kind" and
 * "area" options the in-product support form offers, shared by the client
 * form (`components/support/SupportForm.tsx`) and the server route
 * (`app/api/support/route.ts`).
 *
 * BEFORE THIS FILE, THE TWO LISTS WERE HAND-DUPLICATED: `TABS`/`AREAS` in the
 * form and `KINDS`/`CATEGORIES` in the route were four independent arrays
 * that happened to agree. That is exactly the shape `nav-config.tsx` already
 * warns about for the sidebar — two definitions of one vocabulary, either of
 * which can drift alone. Widening the area list from 7 to 14 entries
 * (founder, 2026-09-07) is the kind of change that drift would have shown up
 * on first, so it collapses to one array per list, imported both places.
 *
 * Keys are stable identifiers stored in `support_requests.message` as a
 * labelled first line (`[area: <label>]`) — see the route for why there is
 * no `category` column. Existing keys for the original seven areas and three
 * kinds are UNCHANGED so historical rows and any saved links stay valid;
 * only new keys were added.
 */

export const SUPPORT_KINDS = [
	{ key: "query", label: "Question" },
	{ key: "feedback", label: "Feedback" },
	{ key: "bug", label: "Bug" },
	{ key: "feature", label: "Feature request" },
] as const;

export type SupportKind = (typeof SUPPORT_KINDS)[number]["key"];

/** Broad product area so a request arrives with routing context. */
export const SUPPORT_AREAS = [
	{ key: "gateway", label: "Gateway & providers" },
	{ key: "traces", label: "Traces & sessions" },
	{ key: "evals", label: "Evals, datasets & experiments" },
	{ key: "prompts", label: "Prompts & playground" },
	{ key: "dashboards", label: "Dashboards" },
	{ key: "guardrails", label: "Guardrails" },
	{ key: "audit", label: "Audit ledger" },
	{ key: "ask-tara", label: "Ask Tara & MCP server" },
	{
		key: "integrations",
		label: "Integrations & SDKs (OTel, Claude Code, LangChain)",
	},
	{ key: "billing", label: "Billing & plan" },
	{ key: "account", label: "Account & team" },
	{ key: "security", label: "Security or privacy concern" },
	{ key: "data-export", label: "Data export or deletion" },
	{ key: "other", label: "Something else" },
] as const;

export type SupportArea = (typeof SUPPORT_AREAS)[number]["key"];
