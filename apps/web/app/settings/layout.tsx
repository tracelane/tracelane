/**
 * Settings section layout — secondary nav tabs + content area.
 *
 * Shared by /settings/api-keys, /settings/billing, /settings/byok,
 * /settings/team, /settings/workspace.
 *
 * It also owns `<Providers>` (TanStack Query). That used to sit in the ROOT
 * layout, which put the react-query runtime on every route in the app while every
 * `useQuery`/`useMutation` in the tree lives under `components/settings/` —
 * `AlertsManager`, `ApiKeyManager`, `ByokKeyManager`, `ProfileManager`,
 * `ProviderKeyManager`, `TeamManager`, `WorkspaceManager`, all rendered by pages
 * under this layout. This is the narrowest boundary that covers all seven.
 * If a client component OUTSIDE /settings ever needs a query client, move the
 * provider up rather than mounting a second one — two clients means two caches.
 */

import { Providers } from "@/app/providers";
import { SettingsNav } from "@/components/settings/SettingsNav";
import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = { title: "Settings — Tracelane" };

export default function SettingsLayout({ children }: { children: ReactNode }) {
	return (
		<Providers>
			<div className="px-2 py-3 sm:px-4 sm:py-4">
				<h1 className="t-h1 mb-6">Settings</h1>
				<div className="flex flex-col gap-6 sm:flex-row sm:gap-8">
					<SettingsNav />
					<div className="flex-1 min-w-0">{children}</div>
				</div>
			</div>
		</Providers>
	);
}
