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
	{ href: "/settings/team", label: "Team" },
	{ href: "/settings/workspace", label: "Workspace" },
	// ADR-059: alerting settings (f_alerts gated; page shows honest not-entitled state)
	{ href: "/settings/alerts", label: "Alerts" },
	{ href: "/settings/account", label: "Account" },
] as const;

export function SettingsNav() {
	const pathname = usePathname();

	return (
		<nav className="flex sm:flex-col gap-1 shrink-0 sm:w-40">
			{TABS.map(({ href, label }) => (
				<Link
					key={href}
					href={href}
					className={
						pathname.startsWith(href)
							? "rounded-md px-3 py-2 text-sm font-medium text-ink bg-surface-2"
							: "rounded-md px-3 py-2 text-sm text-ink-2 hover:text-ink hover:bg-surface-2/50 transition-colors"
					}
				>
					{label}
				</Link>
			))}
		</nav>
	);
}
