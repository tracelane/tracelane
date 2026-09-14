"use client";

/**
 * SettingsNav — the navigation for the /settings section (`SET-36`).
 *
 * Two renderings of ONE list (`settings-nav-config.ts`):
 *
 * - `sm` and up: a left rail of four named groups, in the same small-caps
 *   vocabulary the sidebar uses for Observe · Prove · Operate
 *   (`RAIL_GROUP_LABEL` is imported, not copied, so the two cannot drift).
 * - below `sm`: ONE native `<select>` whose `<optgroup>`s are the same four
 *   groups. This replaces a horizontal strip of ten tabs that was wider than
 *   any phone and scrolled in its own track — a native control is the one
 *   thing a phone renders well without any CSS from us.
 *
 * The active page is chosen by longest-prefix match and announced with
 * `aria-current="page"` on the rail, never by colour alone.
 */

import { RAIL_GROUP_LABEL } from "@/components/layout/nav-config";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { SETTINGS_GROUPS, activeSettingsHref } from "./settings-nav-config";

/*
 * ACTIVE is `--surface-3`, HOVER is `--surface-hover`, and the pair has to be
 * read in both themes. Active was `--surface-2` and hover a 50% wash of the
 * same token: in LIGHT that ordered correctly by accident, but in DARK
 * `--surface-hover` (#202125) is LIGHTER than `--surface-2` (#1c1d20), so
 * hovering an inactive tab made it read louder than the tab you are actually
 * on. `--surface-3` is the declared press/active step and sits above the hover
 * step in BOTH themes, which is the only way this ordering survives a palette
 * swap.
 */
const ITEM_ACTIVE =
	"block rounded-md px-3 py-1.5 text-sm font-medium text-ink bg-surface-3 whitespace-nowrap";
const ITEM_IDLE =
	"block rounded-md px-3 py-1.5 text-sm text-ink-2 whitespace-nowrap hover:text-ink hover:bg-surface-hover transition-colors";

export function SettingsNav() {
	const pathname = usePathname();
	const router = useRouter();
	const active = activeSettingsHref(pathname);

	return (
		<>
			{/* < sm — one control. `value` is controlled so the select follows the
			    route (a back-button navigation must not leave it on the old page). */}
			<label className="block sm:hidden">
				<span className="sr-only">Settings section</span>
				<select
					value={active ?? ""}
					onChange={(e) => router.push(e.target.value)}
					className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink"
				>
					{SETTINGS_GROUPS.map((group) => (
						<optgroup key={group.label} label={group.label}>
							{group.items.map((item) => (
								<option key={item.href} value={item.href}>
									{item.label}
								</option>
							))}
						</optgroup>
					))}
				</select>
			</label>

			{/* ≥ sm — the grouped rail. `w-44` fits the longest label ("Audit
			    signing key") on one line; a label that wraps is a design change,
			    not something to hide with an ellipsis. */}
			<nav
				aria-label="Settings"
				className="hidden shrink-0 sm:flex sm:w-44 sm:flex-col sm:gap-5"
			>
				{SETTINGS_GROUPS.map((group) => (
					<div key={group.label}>
						<p className={RAIL_GROUP_LABEL}>{group.label}</p>
						<ul className="flex flex-col gap-0.5">
							{group.items.map((item) => {
								const isActive = item.href === active;
								return (
									<li key={item.href}>
										<Link
											href={item.href}
											aria-current={isActive ? "page" : undefined}
											className={isActive ? ITEM_ACTIVE : ITEM_IDLE}
										>
											{item.label}
										</Link>
									</li>
								);
							})}
						</ul>
					</div>
				))}
			</nav>
		</>
	);
}
