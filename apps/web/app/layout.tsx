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
 *         <div flex>
 *           <Sidebar />     ← primary navigation (client component)
 *           <main>          ← route content
 *             {children}
 *           </main>
 *         </div>
 *       </Providers>
 *     </body>
 *   </html>
 *
 * The Sidebar is excluded from auth routes (/sign-in, /auth/callback)
 * to avoid showing navigation chrome to unauthenticated users. Route
 * detection uses the segment-based pathname pattern.
 */

import { CommandPalette } from "@/components/command-palette/CommandPalette";
import { OrgSwitcher } from "@/components/layout/OrgSwitcher";
import { Sidebar } from "@/components/layout/Sidebar";
import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import "./globals.css";

// No-flash theme seed (ADR-053). Runs synchronously before first paint and
// before hydration, setting <html data-theme> from the persisted `theme`
// cookie so the correct token set applies on the very first frame. Kept as an
// inline pre-paint script (not a server cookie read) so static routes
// stay statically prerendered. Light is the default.
const THEME_INIT = `(function(){try{var m=document.cookie.match(/(?:^|;\\s*)theme=(light|dark)/);document.documentElement.dataset.theme=(m&&m[1]==='dark')?'dark':'light';}catch(e){}})();`;

// Self-hosted type (ADR-053): Inter UI + JetBrains Mono data/code (no serif in
// the app). Exposed as CSS vars that globals.css wires into --font-sans/-mono.
const inter = Inter({
	subsets: ["latin"],
	variable: "--font-inter",
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
	icons: {
		icon: [
			{
				url: "/brand/favicon-light.png",
				media: "(prefers-color-scheme: light)",
				type: "image/png",
			},
			{
				url: "/brand/favicon-dark.png",
				media: "(prefers-color-scheme: dark)",
				type: "image/png",
			},
		],
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
			className={`${inter.variable} ${jetbrainsMono.variable}`}
			suppressHydrationWarning
		>
			<head>
				{/* biome-ignore lint/security/noDangerouslySetInnerHtml: trusted
				    static constant, no user input — the standard no-flash theme seed. */}
				<script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
			</head>
			<body>
				<Providers>
					<div className="flex min-h-screen bg-bg">
						<Sidebar orgSlot={<OrgSwitcher />} />
						{/* pt-14 clears the fixed mobile top bar; md:pt-0 restores the
						    unchanged desktop layout (the static sidebar owns the left). */}
						<main className="flex-1 overflow-auto pt-14 md:pt-0">
							{children}
						</main>
						<CommandPalette />
					</div>
				</Providers>
			</body>
		</html>
	);
}
