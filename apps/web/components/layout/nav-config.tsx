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

function ActivityIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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
			strokeWidth={2}
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

function DashboardIcon() {
	return (
		<svg
			xmlns="http://www.w3.org/2000/svg"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			strokeWidth={2}
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
 * (`app/<href>/page.tsx`) — `nav-config.test.ts` enforces it (plus the named
 * previously-orphaned pages, and no duplicate hrefs) so a link can never go
 * dead. Items tagged `badge: "V1.1"` route to an honest ComingSoon empty state.
 */
export const sections: NavSection[] = [
	{
		label: "Observe",
		items: [
			{ href: "/dashboard", label: "Dashboard", Icon: DashboardIcon },
			{ href: "/traces", label: "Traces", Icon: ActivityIcon },
			{ href: "/sessions", label: "Sessions", Icon: SessionsIcon },
			{ href: "/slo", label: "SLO", Icon: BarChartIcon },
		],
	},
	{
		label: "Improve",
		items: [
			{ href: "/signatures", label: "Failure Signatures", Icon: SignatureIcon },
			{ href: "/prompts", label: "Prompts", Icon: GitBranchIcon },
			// Datasets / Experiments / Playground are V1.1 — not shown in the nav
			// until built (their `app/*/page.tsx` ComingSoon stubs remain for
			// direct-URL access + trivial re-enable). Re-add here when shipped.
		],
	},
	{
		label: "Operate",
		items: [
			{ href: "/guardrails", label: "Guardrails", Icon: ShieldCheckIcon },
			{ href: "/audit", label: "Audit", Icon: ShieldIcon },
			{ href: "/gateway", label: "Gateway", Icon: GatewayIcon },
		],
	},
	{
		label: "Settings",
		items: [
			{ href: "/settings/api-keys", label: "API Keys", Icon: KeyIcon },
			{ href: "/settings/providers", label: "LLM Providers", Icon: ServerIcon },
			{ href: "/settings/billing", label: "Billing", Icon: CreditCardIcon },
			{ href: "/settings/byok", label: "Encryption Keys", Icon: KeyIcon },
			{
				href: "/settings/audit",
				label: "Audit signing key",
				Icon: ShieldIcon,
			},
			{ href: "/settings/alerts", label: "Alerts", Icon: BellIcon },
			{ href: "/settings/team", label: "Team", Icon: UsersIcon },
			{ href: "/settings/workspace", label: "Workspace", Icon: BuildingIcon },
		],
	},
];
