"use client";

/**
 * SettingsNav — left-rail tab navigation for the /settings section.
 *
 * Uses pathname matching to highlight the active settings tab.
 */

import Link from "next/link";
import { usePathname } from "next/navigation";

const TABS = [
	{ href: "/settings/api-keys", label: "API Keys" },
	{ href: "/settings/providers", label: "LLM Providers" },
	{ href: "/settings/billing", label: "Billing" },
	// CMK / data-at-rest encryption keys — distinct from the LLM provider keys
	// above. Relabeled from "BYOK Keys" to disambiguate the overloaded term.
	{ href: "/settings/byok", label: "Encryption Keys" },
	// Audit signing key + verify/export how-to (page already existed; the nav
	// entry was missing, leaving it unreachable). Trust cluster, next to keys.
	{ href: "/settings/audit", label: "Audit" },
	{ href: "/settings/team", label: "Team" },
	{ href: "/settings/workspace", label: "Workspace" },
	// ADR-059: alerting settings (f_alerts gated; page shows honest not-entitled state)
	{ href: "/settings/alerts", label: "Alerts" },
	// EVL-28: online evals (f_online_evals gated; same honest not-entitled state).
	// Next to Alerts because both are "what Tracelane does with your traffic
	// while you are not watching", and both spend or notify on their own.
	{ href: "/settings/evals", label: "Online Evals" },
	{ href: "/settings/account", label: "Account" },
] as const;

export function SettingsNav() {
	const pathname = usePathname();

	return (
		/*
		 * P0.17: below `sm` this is a HORIZONTAL strip of seven tabs, which is wider
		 * than a phone. It scrolls in its own track rather than widening the page —
		 * `whitespace-nowrap` keeps each label on one line so the strip scrolls
		 * instead of the labels wrapping to two rows of ragged height.
		 */
		<nav className="flex gap-1 shrink-0 overflow-x-auto sm:overflow-x-visible sm:flex-col sm:w-40">
			{TABS.map(({ href, label }) => (
				<Link
					key={href}
					href={href}
					className={
						/*
						 * ACTIVE is `--surface-3`, HOVER is `--surface-hover`, and the pair
						 * has to be read in both themes. Active was `--surface-2` and hover
						 * a 50% wash of the same token: in LIGHT that ordered correctly by
						 * accident, but in DARK `--surface-hover` (#202125) is LIGHTER than
						 * `--surface-2` (#1c1d20), so hovering an inactive tab made it read
						 * louder than the tab you are actually on. `--surface-3` is the
						 * declared press/active step and sits above the hover step in BOTH
						 * themes, which is the only way this ordering survives a palette swap.
						 */
						pathname.startsWith(href)
							? "rounded-md px-3 py-2 text-sm font-medium text-ink bg-surface-3 whitespace-nowrap"
							: "rounded-md px-3 py-2 text-sm text-ink-2 whitespace-nowrap hover:text-ink hover:bg-surface-hover transition-colors"
					}
				>
					{label}
				</Link>
			))}
		</nav>
	);
}
