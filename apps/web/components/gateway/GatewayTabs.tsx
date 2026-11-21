"use client";
/** The Gateway settings tab strip: fixed tabs, then feature-detected slots. */

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { GATEWAY_TABS } from "./tabs-config";

export interface SlotTab {
	id: string;
	label: string;
}

// shrink-0: in a scrolling flex row the tabs must keep their width, or on a phone they
// squeeze into each other and overlap (B-641).
const ACTIVE =
	"shrink-0 border-b-2 border-action px-3 py-2 text-sm font-medium text-ink whitespace-nowrap";
const IDLE =
	"shrink-0 border-b-2 border-transparent px-3 py-2 text-sm text-ink-2 whitespace-nowrap hover:text-ink transition-colors";

export function GatewayTabs({ slots }: { slots: SlotTab[] }) {
	const pathname = usePathname();
	const router = useRouter();
	const tabs = [
		...GATEWAY_TABS.map((t) => ({ href: t.href as string, label: t.label })),
		...slots.map((s) => ({
			href: `/settings/gateway/${s.id}`,
			label: s.label,
		})),
	];
	// Longest-prefix match, so a sub-route (e.g. `/limits/x`) keeps its tab active.
	const current = tabs
		.filter((t) => pathname === t.href || pathname.startsWith(`${t.href}/`))
		.sort((a, b) => b.href.length - a.href.length)[0]?.href;
	return (
		<>
			{/* On a phone, 15+ tabs do not fit a row: a picker lists every section. */}
			<label className="mb-5 block sm:hidden">
				<span className="sr-only">Gateway settings section</span>
				<select
					className="w-full rounded-control border border-line bg-surface px-3 py-2 text-sm text-ink"
					value={current ?? tabs[0]?.href}
					onChange={(e) => router.push(e.target.value)}
				>
					{tabs.map((t) => (
						<option key={t.href} value={t.href}>
							{t.label}
						</option>
					))}
				</select>
			</label>
			<nav
				aria-label="Gateway settings"
				className="mb-5 hidden gap-1 overflow-x-auto border-b border-line sm:flex"
			>
				{tabs.map((t) => {
					const active = t.href === current;
					return (
						<Link
							key={t.href}
							href={t.href}
							aria-current={active ? "page" : undefined}
							className={active ? ACTIVE : IDLE}
						>
							{t.label}
						</Link>
					);
				})}
			</nav>
		</>
	);
}
