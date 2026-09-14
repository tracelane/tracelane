/**
 * nav-config — the single source of truth for the dashboard sidebar's primary
 * navigation (`Sidebar.tsx` consumes `sections`).
 *
 * Kept separate from the `"use client"` `Sidebar` runtime so the nav set can be
 * unit-tested in the node env (`nav-config.test.ts`) without pulling in
 * `usePathname` / client components — that test guards against orphaned routes
 * (a page that exists but has no nav link) and dead links (a nav href with no
 * page). Icons are inline SVG (no icon-library dependency), matching the 24×24
 * viewBox / `h-4 w-4` convention used across the app.
 */

import { SETTINGS_ITEMS } from "@/components/settings/settings-nav-config";

function ActivityIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
		</svg>
	);
}

function BarChartIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<line x1="18" y1="20" x2="18" y2="10" />
			<line x1="12" y1="20" x2="12" y2="4" />
			<line x1="6" y1="20" x2="6" y2="14" />
		</svg>
	);
}

function BellIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
			<path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
		</svg>
	);
}

function GitBranchIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<line x1="6" y1="3" x2="6" y2="15" />
			<circle cx="18" cy="6" r="3" />
			<circle cx="6" cy="18" r="3" />
			<path d="M18 9a9 9 0 0 1-9 9" />
		</svg>
	);
}

function KeyIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<circle cx="7.5" cy="15.5" r="5.5" />
			<path d="M21 2 l-9.6 9.6" />
			<path d="M15.5 7.5 l3 3" />
		</svg>
	);
}

function ShieldIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
		</svg>
	);
}

function ShieldCheckIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
			<path d="m9 12 2 2 4-4" />
		</svg>
	);
}

function CreditCardIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<rect x="1" y="4" width="22" height="16" rx="2" ry="2" />
			<line x1="1" y1="10" x2="23" y2="10" />
		</svg>
	);
}

function SessionsIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<circle cx="12" cy="12" r="10" />
			<polygon points="10 8 16 12 10 16 10 8" />
		</svg>
	);
}

function ServerIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<rect x="2" y="3" width="20" height="8" rx="2" ry="2" />
			<rect x="2" y="13" width="20" height="8" rx="2" ry="2" />
			<line x1="6" y1="7" x2="6.01" y2="7" />
			<line x1="6" y1="17" x2="6.01" y2="17" />
		</svg>
	);
}

function UsersIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
			<circle cx="9" cy="7" r="4" />
			<path d="M23 21v-2a4 4 0 0 0-3-3.87" />
			<path d="M16 3.13a4 4 0 0 1 0 7.75" />
		</svg>
	);
}

function BuildingIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M3 21h18" />
			<path d="M5 21V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16" />
			<line x1="9" y1="7" x2="9.01" y2="7" />
			<line x1="9" y1="11" x2="9.01" y2="11" />
			<line x1="15" y1="7" x2="15.01" y2="7" />
			<line x1="15" y1="11" x2="15.01" y2="11" />
		</svg>
	);
}

function SignatureIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M12 2 22 12 12 22 2 12Z" />
		</svg>
	);
}

function GatewayIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<circle cx="6" cy="19" r="3" />
			<circle cx="18" cy="5" r="3" />
			<path d="M9 19h6a3 3 0 0 0 3-3V8" />
		</svg>
	);
}

function LayoutsIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<rect x="3" y="3" width="18" height="4" rx="1" />
			<rect x="3" y="11" width="8" height="10" rx="1" />
			<rect x="13" y="11" width="8" height="5" rx="1" />
			<rect x="13" y="18" width="8" height="3" rx="1" />
		</svg>
	);
}

function DashboardIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<rect x="3" y="3" width="7" height="9" rx="1" />
			<rect x="14" y="3" width="7" height="5" rx="1" />
			<rect x="14" y="12" width="7" height="9" rx="1" />
			<rect x="3" y="16" width="7" height="5" rx="1" />
		</svg>
	);
}

/** The conventional "leaves the app" glyph — a box with an arrow escaping its
 * top-right corner. Used only by `EXTERNAL_LINKS`, so a customer sees before
 * they click that the destination is a different origin. */
function ExternalLinkIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={1.6}
			strokeLinecap="round"
			strokeLinejoin="round"
			className="h-4 w-4 shrink-0"
			aria-hidden="true"
		>
			<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
			<polyline points="15 3 21 3 21 9" />
			<line x1="10" y1="14" x2="21" y2="3" />
		</svg>
	);
}

export type NavItem = {
	href: string;
	label: string;
	Icon: () => React.JSX.Element;
	/** Optional tag rendered after the label (e.g. "V1.1" for empty-state surfaces). */
	badge?: string;
};

export type NavSection = {
	label?: string;
	items: NavItem[];
};

/**
 * Primary sidebar nav, grouped Observe / Improve / Operate / Settings
 * (§"Left sidebar"). Every href MUST map to a real route
 * (`app/<href>/page.tsx`) — `nav-config.test.ts` enforces it (plus the named
 * previously-orphaned pages, and no duplicate hrefs) so a link can never go
 * dead. Items tagged `badge: "V1.1"` route to an honest ComingSoon empty state.
 */
/** Icons for the Settings group, by href; a page with no entry falls back to KeyIcon. */
const SETTINGS_ICONS: Partial<Record<string, () => React.JSX.Element>> = {
	"/settings/api-keys": KeyIcon,
	"/settings/providers": ServerIcon,
	"/settings/byok": KeyIcon,
	"/settings/audit": ShieldIcon,
	"/settings/alerts": BellIcon,
	"/settings/evals": ShieldCheckIcon,
	"/settings/billing": CreditCardIcon,
	"/settings/team": UsersIcon,
	"/settings/workspace": BuildingIcon,
	"/settings/account": UsersIcon,
};

export const sections: NavSection[] = [
	// ADR-074 §6 grouping. The SAME NINE hrefs as the previous Observe/Improve/
	// Operate split — regrouped, never reduced, which is why the R12 after-proof
	// on navigation is a re-grouping check and not a loss audit.
	{
		label: "Observe",
		items: [
			{ href: "/dashboard", label: "Overview", Icon: DashboardIcon },
			// DSH-13 custom dashboards — nav entry added after the feature shipped
			// (same rule as /experiments and /review: add once the page is real).
			{ href: "/dashboards", label: "Dashboards", Icon: LayoutsIcon },
			{ href: "/traces", label: "Traces", Icon: ActivityIcon },
			{ href: "/sessions", label: "Sessions", Icon: SessionsIcon },
			// EVL-29 review queues. Added only AFTER a real review produced rows
			// on prod (BUILD_RUNBOOK S3, the same rule `/experiments` records):
			// a queue is a live query, so an entry added before the loop closed
			// would have led to a surface that could not populate.
			{ href: "/review", label: "Review", Icon: SignatureIcon },
		],
	},
	{
		// PROVE is its own group DELIBERATELY (ADR-074 §6): the tamper-evident
		// ledger is the moat, and burying it under Settings or "Operate" made the
		// one thing competitors cannot copy the hardest thing to find.
		label: "Prove",
		items: [
			{ href: "/audit", label: "Audit", Icon: ShieldIcon },
			{ href: "/signatures", label: "Failure Signatures", Icon: SignatureIcon },
		],
	},
	{
		label: "Operate",
		items: [
			{ href: "/gateway", label: "Gateway", Icon: GatewayIcon },
			{ href: "/guardrails", label: "Guardrails", Icon: ShieldCheckIcon },
			{ href: "/slo", label: "SLO", Icon: BarChartIcon },
			{ href: "/prompts", label: "Prompts", Icon: GitBranchIcon },
			// EVL-02 Experiments. The S3 precondition is SATISFIED, which is why
			// this line exists now and not earlier: `docs/runbook/BUILD_RUNBOOK.md`
			// says the nav entry goes in only after a real run has produced rows on
			// prod, and one has — experiment `1cedfbdd` on 2026-08-24 wrote 1
			// `experiments` row, 2 `experiment_arms` rows and 20 `eval_run_items`
			// rows, all read back from ClickHouse. Adding it before that would have
			// been the dead-entry shape: a nav item leading to a surface that
			// cannot populate.
			{ href: "/experiments", label: "Experiments", Icon: BarChartIcon },
			// OBS-16 (2026-09-06). The form + `POST /api/playground` proxy are
			// real, so the entry moves in with them — same rule as Experiments
			// and /review: a nav link only after the page behind it is real.
			{ href: "/playground", label: "Playground", Icon: GitBranchIcon },
			// ── OUT OF THE NAV, AND THE REASON IS NOT THE SAME AS ABOVE ───────
			//
			// Experiments (EVL-02) was OUT of this list until 2026-08-24 (`968eb470`),
			// when Sprint 3 item 9 produced real rows on prod; the entry above is
			// the result. (This comment said "stays out of the nav" for two weeks
			// after the entry landed — corrected 2026-09-06.)
			//
			// Playground (OBS-16) was OUT of this list until 2026-09-06, when the
			// form replaced the ComingSoon stub; the entry above is the result.
			// (This comment called it "genuinely unbuilt" until the same day.)
			//
			// Datasets (EVL-04) has a shipped, prod-proven API and NO UI yet —
			// `app/datasets/page.tsx` is still a ComingSoon stub. It is out of the
			// nav because there is nothing to navigate TO, not because the feature
			// is absent.
			//
			// This comment was previously one line calling all three "V1.1
			// ComingSoon stubs". A comment that misdescribes the code is the §17
			// defect — here it would have told the next reader that a finished
			// feature does not exist.
		],
	},
	{
		// SET-36: DERIVED from the one settings list. This used to be a hand-kept
		// copy of `SettingsNav`'s tabs that never learned about `/settings/evals`
		// or `/settings/account` — and since `Sidebar` filters this group out and
		// renders Settings as one footer link, its only consumer is the chrome
		// sweep (`nav-model.ts` ALL_CHROME_ROUTES), so the two missing pages were
		// simply never walked. Icons are kept for the `NavItem` shape; nothing
		// renders them for this group today.
		label: "Settings",
		items: SETTINGS_ITEMS.map(({ href, label }) => ({
			href,
			label,
			Icon: SETTINGS_ICONS[href] ?? KeyIcon,
		})),
	},
];

export type ExternalNavLink = {
	href: string;
	label: string;
	Icon: () => React.JSX.Element;
};

/**
 * DSH-15 — chrome links that leave the app entirely (a different origin), so
 * they cannot be checked against `app/<href>/page.tsx` the way `sections` is.
 * Deliberately OUTSIDE `sections`: `nav-config.test.ts`'s dead-link sweep
 * flattens `sections` and would fail an absolute URL with no local route, and
 * `no-stranded-routes.test.ts` walks `app/`/`components/` for path LITERALS
 * starting with `/`, so an `https://` href is invisible to it too — neither
 * guard needed touching. Rendered by `AccountMenu`, next to Support — the
 * other help/account affordance — per the founder request 2026-09-06
 * (`specs/DSH-15-docs-link-in-app-shell.md`).
 */
export const EXTERNAL_LINKS: ExternalNavLink[] = [
	{ href: "https://docs.tracelane.dev", label: "Docs", Icon: ExternalLinkIcon },
];

/**
 * ── RAIL ITEM SURFACE (P0.13) ────────────────────────────────────────────────
 *
 * The class vocabulary for ONE row on the navigation rail, exported from here so
 * `Sidebar` (the nine primary items + Collapse) and `AccountMenu` (Settings,
 * Account, Support, Sign out) cannot drift into two different active states. They
 * could before: both hand-wrote the same active/idle pair inline, so either file
 * could have been restyled alone and the rail would have carried two vocabularies.
 *
 * Plain strings rather than a `cn()` helper, so this module stays import-free and
 * `nav-config.test.ts` keeps running in the node env (see the file header).
 *
 * WHY THE ACTIVE STEP IS `--surface-3` AND HOVER IS `--surface-2` — measured, not
 * assumed. The P0 brief asks for a SUBTLE active background in place of the solid
 * ink pill this rail used to paint, and for hover to stay distinguishable from it.
 * Only one pair of tokens keeps "active reads STRONGER than hover" in BOTH themes:
 *
 *              rail plane   hover           active
 *   light      #fcfcfb      #f5f5f4  (Δ7)   #ebebe9  (Δ17)
 *   dark       #101113      #1c1d20  (Δ12)  #26272b  (Δ22)
 *
 * The obvious pair — hover `--surface-hover`, active `--surface-2` — INVERTS in
 * dark: `--surface-hover` is #202125 there while `--surface-2` is #1c1d20, so
 * hovering an inactive item would light it up MORE than the item you are on.
 * tokens.css documents `--surface-hover` as the hover step ON A WHITE CARD, and
 * the rail is not a card — its steps are the well (`--surface-2`) and the press
 * step (`--surface-3`). This app wires no `dark:` variant (the theme is a
 * `data-theme` attribute, not `prefers-color-scheme`), so a per-theme override was
 * never an option: the pair has to work unbranched.
 *
 * `--surface-3` lands one step past the #F1F1F0 the brief sampled for light. That
 * is the cost of the monotonic ordering above, and it is still ~7% away from the
 * rail plane — nothing like the ink pill it replaces.
 *
 * The active row carries THREE non-colour signals besides the tone —
 * `aria-current="page"`, a heavier weight, and the 2px leading marker `Sidebar`
 * draws — so the state never rests on a 7%-luminance step alone.
 */
export const RAIL_ITEM =
	"relative flex items-center gap-2.5 rounded-[var(--radius-control)] px-2 py-2 text-sm transition-colors";
/** Idle rows are secondary ink; primary ink is reserved for the row you are on. */
export const RAIL_ITEM_IDLE = "text-ink-2 hover:bg-surface-2 hover:text-ink";
/* DSH-16: the active-row chip moves from a neutral grey (`bg-surface-3`) to the
   accent's own soft tint — reusing the ONE hue that already means "this is
   what you're interacting with" rather than adding a second, unrelated grey
   step. No new hue, no per-group colour. */
export const RAIL_ITEM_ACTIVE = "bg-action-soft font-medium text-ink";
/**
 * The fixed icon column. Every label starts at the same x whether its glyph is a
 * 16px `viewBox="0 0 16 16"` outline (AccountMenu) or a 24px one (nav-config), and
 * whether the row has a glyph at all (Support / Sign out render an empty slot).
 */
export const RAIL_ICON = "flex w-4 shrink-0 items-center justify-center";
/**
 * The group heading above each section. 11px/600/0.08em on tertiary ink — NOT
 * `.t-eyebrow`, which is 12px on secondary ink and is the scale's PAGE-section
 * label: a rail group heading has to sit BELOW its own nav items in the hierarchy,
 * and reusing the page-level eyebrow put it above them. Not `.t-metric-label`
 * either, despite the identical metrics — that class hardcodes secondary ink and
 * names a metric, so borrowing it would make a nav label read as a data label.
 */
export const RAIL_GROUP_LABEL =
	"px-2 pb-1.5 text-2xs font-semibold uppercase tracking-[0.08em] text-ink-3";
