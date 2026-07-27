/**
 * Root layout — loaded once, wraps every route.
 *
 * Provides: TanStack Query client, Zustand store initialisation,
 * global navigation shell, and font loading.
 *
 * Layout structure:
 *   <html>
 *     <body>
 *       <Providers>         ← TanStack Query + Zustand
 *         <AppShell>        ← framed sky-blue shell + TopNav (client)
 *           {children}      ← route content, inside the floating canvas
 *         </AppShell>
 *         <CommandPalette />
 *       </Providers>
 *     </body>
 *   </html>
 *
 * AppShell reads the pathname and renders route content bare (no frame/nav)
 * on the full-screen routes — /onboarding and the auth pages — so unauthenticated
 * or wizard flows never show app chrome.
 */

import { CommandPalette } from "@/components/command-palette/CommandPalette";
import { AppShell } from "@/components/layout/AppShell";
import { OrgSwitcher } from "@/components/layout/OrgSwitcher";
import type { Metadata, Viewport } from "next";
import { JetBrains_Mono, Plus_Jakarta_Sans } from "next/font/google";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import "./globals.css";

// No-flash theme seed (ADR-053). Runs synchronously before first paint and
// before hydration, setting <html data-theme> from the persisted `theme`
// cookie so the correct token set applies on the very first frame. Kept as an
// inline pre-paint script (not a server cookie read) so static routes
// stay statically prerendered. Light is the default.
const THEME_INIT = `(function(){try{var m=document.cookie.match(/(?:^|;\\s*)theme=(light|dark)/);document.documentElement.dataset.theme=(m&&m[1]==='dark')?'dark':'light';}catch(e){}})();`;

// Type (app design system): Plus Jakarta Sans UI + JetBrains Mono data/code (no
// serif in the app). Exposed as CSS vars that globals.css wires into --font-sans/-mono.
const plusJakarta = Plus_Jakarta_Sans({
	subsets: ["latin"],
	variable: "--font-plus-jakarta",
	display: "swap",
});
const jetbrainsMono = JetBrains_Mono({
	subsets: ["latin"],
	variable: "--font-jetbrains-mono",
	display: "swap",
});

export const metadata: Metadata = {
	title: {
		default: "Tracelane",
		template: "%s — Tracelane",
	},
	description:
		"Predictive reliability platform for AI agents. Full-fidelity traces, provider failover, and inline guardrails.",
	// Official Chisel brand assets (public/brand). The favicon swaps by browser
	// scheme (light asset = dark mark for light chrome, and vice-versa); the
	// apple-touch icon is the self-contained rounded-square app icon.
	// Favicon pinned to the light-mode logo style PERMANENTLY (founder-decided):
	// no `prefers-color-scheme` swap — the same light-mode mark shows in both
	// light and dark browser chrome.
	icons: {
		icon: [{ url: "/brand/favicon-light.png", type: "image/png" }],
		apple: { url: "/brand/logo-icon-light.png", type: "image/png" },
	},
};

// Explicit mobile viewport (Next injects this by default, but pin it so the
// dashboard always scales to the device — no zoomed-out desktop layout on phones).
export const viewport: Viewport = {
	width: "device-width",
	initialScale: 1,
};

export default function RootLayout({ children }: { children: ReactNode }) {
	return (
		<html
			lang="en"
			className={`${plusJakarta.variable} ${jetbrainsMono.variable}`}
			suppressHydrationWarning
		>
			<head>
				{/* biome-ignore lint/security/noDangerouslySetInnerHtml: trusted
				    static constant, no user input — the standard no-flash theme seed. */}
				<script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
			</head>
			<body>
				<Providers>
					<AppShell orgSlot={<OrgSwitcher />}>{children}</AppShell>
					<CommandPalette />
				</Providers>
			</body>
		</html>
	);
}
