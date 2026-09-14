/**
 * THE ONE LIST of settings pages — `SET-36`.
 *
 * Until 2026-09-14 there were two: `SettingsNav.tsx` carried ten flat tabs and
 * `layout/nav-config.tsx` carried a second, eight-entry copy that had never
 * learned about `/settings/evals` or `/settings/account`. The sidebar filters
 * that copy out and renders Settings as one footer link, so its only job was
 * to feed the dead-button sweep — which therefore never walked `/settings/evals`
 * at all. Both now read from here; `settings-nav-config.test.ts` walks
 * `app/settings/*\/page.tsx` and fails the day a page exists that is not
 * placed in a group, or is placed twice.
 *
 * Plain TypeScript on purpose: no `"use client"`, no React, so a server
 * component, a client component and a node test can all import it.
 *
 * Founder, 2026-09-14: "this settings page has too many subpages, find
 * elegant design to ensure they dont look cluttered." The design is four named
 * groups (spec `SET-36` §2) — the same small-caps grouping the sidebar already
 * uses for Observe · Prove · Operate — rather than icons, badges or a hub page,
 * each of which was considered and each of which adds what this removes.
 */

export type SettingsHref = `/settings/${string}`;

export interface SettingsItem {
	readonly href: SettingsHref;
	readonly label: string;
}

export interface SettingsGroup {
	readonly label: string;
	readonly items: readonly SettingsItem[];
}

export const SETTINGS_GROUPS: readonly SettingsGroup[] = [
	{
		// Four kinds of key. LLM provider keys and CMK encryption keys are the two
		// a user is most likely to confuse — they now sit side by side under one
		// label instead of being split by Billing.
		label: "Keys & access",
		items: [
			{ href: "/settings/api-keys", label: "API Keys" },
			{ href: "/settings/providers", label: "LLM Providers" },
			{ href: "/settings/byok", label: "Encryption Keys" },
			{ href: "/settings/audit", label: "Audit signing key" },
		],
	},
	{
		// What Tracelane does with your traffic while you are not watching. Both
		// notify or spend on their own; both are plan-gated (`f_alerts`,
		// `f_online_evals`) and render their own honest not-entitled state.
		label: "Automation",
		items: [
			{ href: "/settings/alerts", label: "Alerts" },
			{ href: "/settings/evals", label: "Online Evals" },
		],
	},
	{
		// The organisation: who pays, who is in it, what it is called.
		label: "Workspace",
		items: [
			{ href: "/settings/billing", label: "Billing" },
			{ href: "/settings/team", label: "Team" },
			{ href: "/settings/workspace", label: "Workspace" },
		],
	},
	{
		// Personal, not workspace — the one page that follows the person.
		label: "You",
		items: [{ href: "/settings/account", label: "Account" }],
	},
];

/** Every settings page, in rail order. */
export const SETTINGS_ITEMS: readonly SettingsItem[] = SETTINGS_GROUPS.flatMap(
	(g) => g.items,
);

/**
 * The settings href a pathname belongs to — LONGEST prefix wins, so a
 * sub-route such as `/settings/api-keys/new` highlights API Keys, and
 * `/settings/audit` can never be shadowed by a sibling that happens to share
 * a prefix. `null` when the pathname is not under any settings page.
 */
export function activeSettingsHref(pathname: string): SettingsHref | null {
	let best: SettingsHref | null = null;
	for (const { href } of SETTINGS_ITEMS) {
		const matches = pathname === href || pathname.startsWith(`${href}/`);
		if (matches && (best === null || href.length > best.length)) best = href;
	}
	return best;
}
