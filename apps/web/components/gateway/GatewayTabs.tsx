"use client";
/** The Gateway settings tab strip: fixed tabs, then feature-detected slots. */

import Link from "next/link";
import { usePathname } from "next/navigation";
import { GATEWAY_TABS } from "./tabs-config";

export interface SlotTab {
	id: string;
	label: string;
}

const ACTIVE =
	"border-b-2 border-action px-3 py-2 text-sm font-medium text-ink whitespace-nowrap";
const IDLE =
	"border-b-2 border-transparent px-3 py-2 text-sm text-ink-2 whitespace-nowrap hover:text-ink transition-colors";

export function GatewayTabs({ slots }: { slots: SlotTab[] }) {
	const pathname = usePathname();
	const tabs = [
		...GATEWAY_TABS.map((t) => ({ href: t.href as string, label: t.label })),
		...slots.map((s) => ({
			href: `/settings/gateway/${s.id}`,
			label: s.label,
		})),
	];
	return (
		<nav
			aria-label="Gateway settings"
			className="mb-5 flex gap-1 overflow-x-auto border-b border-line"
		>
			{tabs.map((t) => {
				const active = pathname === t.href;
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
	);
}
