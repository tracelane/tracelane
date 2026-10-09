/**
 * The Gateway settings tab strip (`OG-60` §2) — plain TypeScript so a server layout, a
 * client component, the dead-button sweep and a node test can all import it.
 *
 * Fixed tabs exist on every deployment: each reads a route that is on `main` today. The
 * SLOT tabs (`GATEWAY_SLOTS`, `lib/gateway-controls.ts`) are feature-detected: a slot
 * appears only when the gateway answers its probe route.
 */

export interface GatewayTab {
	readonly href: `/settings/gateway${string}`;
	readonly label: string;
}

export const GATEWAY_TABS: readonly GatewayTab[] = [
	{ href: "/settings/gateway", label: "Overview" },
	{ href: "/settings/gateway/limits", label: "Limits & budgets" },
	{ href: "/settings/gateway/projects", label: "Projects" },
	{ href: "/settings/gateway/keys", label: "Key policy" },
	{ href: "/settings/gateway/spend-alerts", label: "Spend alerts" },
	{ href: "/settings/gateway/emergency", label: "Emergency" },
	{ href: "/settings/gateway/capture", label: "Content capture" },
];

/** Every route the Gateway area owns (for the dead-button sweep). */
export const GATEWAY_TAB_HREFS: readonly string[] = GATEWAY_TABS.map(
	(t) => t.href,
);
