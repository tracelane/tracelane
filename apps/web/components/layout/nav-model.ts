/**
 * nav-model — what the shipped navigation ACTUALLY renders, as pure data.
 *
 * WHY THIS FILE EXISTS. The nav used to compute its own item list inline
 * while `e2e/fixtures/selectors.ts` carried a HAND-COPIED list of what it believed
 * the nav rendered. The two drifted the moment the left sidebar was replaced by a
 * horizontal bar: the spec went on asserting six per-item Settings links and a label
 * the bar no longer showed, and 9 of the L16 gate's 38 tests could never pass again.
 *
 * A spec that hand-copies what a component renders is a second source of truth, and
 * the second one is always the one that rots. So the derivation lives HERE, once:
 * the chrome renders from it and the E2E spec asserts against it. They cannot
 * disagree — if this list is wrong, the nav is wrong in exactly the same way.
 *
 * RENAMED from `top-nav-model.ts` 2026-08-15 (ADR-074 §6). The horizontal bar is
 * gone; a module called "top-nav" describing a left sidebar would be the same stale
 * claim this file was created to prevent, one level up.
 *
 * Pure TS on purpose (no JSX, no "use client"): importable from a Playwright spec,
 * a vitest node test, and a client component alike.
 */

import { sections } from "./nav-config";

/** Settings collapses to ONE sidebar-footer entry pointing at its first pane. */
export const SETTINGS_HREF = "/settings/api-keys";
export const SUPPORT_HREF = "/support";

/**
 * ADR-074 §6 names two items shorter than nav-config does. This is the ONLY place
 * that transform is defined.
 */
export function shortLabel(href: string, label: string): string {
	if (href === "/signatures") return "Signatures";
	if (href === "/slo") return "SLO";
	return label;
}

/** nav-config's non-Settings sections, flattened — the sidebar's nine primary items. */
export const PRIMARY_ITEMS = sections
	.filter((s) => s.label !== "Settings")
	.flatMap((s) => s.items);

/**
 * Every primary link the sidebar renders, in render order, with the label as
 * RENDERED. `Sidebar` maps this; `global-chrome.spec.ts` asserts against it.
 *
 * Settings and Support are NOT in this list any more. ADR-074 §6 moves Settings to
 * the sidebar footer and Support into the account menu, which is what keeps the rail
 * at nine items. They are still swept — see ALL_CHROME_ROUTES.
 */
export const NAV_ITEMS: readonly { href: string; label: string }[] =
	PRIMARY_ITEMS.map((i) => ({
		href: i.href,
		label: shortLabel(i.href, i.label),
	}));

/**
 * Every route reachable from the chrome — the sidebar's primary items PLUS the full
 * Settings group PLUS Support. The dead-button sweep walks this, so a newly added
 * nav route is swept the day it ships rather than whenever someone remembers to
 * extend a literal array.
 *
 * `/settings/account` is listed EXPLICITLY. It renders and is reachable from
 * `SettingsNav.tsx`, but it is absent from `nav-config.tsx`, so until 2026-08-15 it
 * fell outside this array and therefore outside the sweep — a live surface nothing
 * checked. Found by the R12 before-inventory
 * (`docs/internal/R12_BEFORE_INVENTORY.md`), not by a failure.
 */
export const ACCOUNT_HREF = "/settings/account";

export const ALL_CHROME_ROUTES: readonly string[] = [
	...sections.flatMap((s) => s.items.map((i) => i.href)),
	ACCOUNT_HREF,
	SUPPORT_HREF,
];
