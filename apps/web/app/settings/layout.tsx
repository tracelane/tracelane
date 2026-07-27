/**
 * Settings section layout — secondary nav tabs + content area.
 *
 * Shared by /settings/api-keys, /settings/billing, /settings/byok,
 * /settings/team, /settings/workspace.
 */

import { SettingsNav } from "@/components/settings/SettingsNav";
import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = { title: "Settings — Tracelane" };

export default function SettingsLayout({ children }: { children: ReactNode }) {
	return (
		<div className="px-2 py-3 sm:px-4 sm:py-4">
			<h1 className="text-xl font-semibold text-ink mb-6">Settings</h1>
			<div className="flex flex-col gap-6 sm:flex-row sm:gap-8">
				<SettingsNav />
				<div className="flex-1 min-w-0">{children}</div>
			</div>
		</div>
	);
}
