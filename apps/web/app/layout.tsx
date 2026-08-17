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
import { cookies } from "next/headers";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import "./globals.css";

// No-flash theme seed (ADR-053). Runs synchronously before first paint and
// before hydration, setting <html data-theme> from the persisted `theme`
// cookie so the correct token set applies on the very first frame. Kept as an
// inline pre-paint script (not a server cookie read) so static routes
// stay statically prerendered. Light is the default.
const THEME_INIT = `(function(){try{var m=document.cookie.match(/(?:^|;\\s*)theme=(light|dark)/);document.documentElement.dataset.theme=(m&&m[1]==='dark')?'dark':'light';}catch(e){}})();`;

// Type. INCUMBENT: Plus Jakarta Sans (UI) + JetBrains Mono (numerals, ids, hashes,
// seq, model names, code). Exposed as CSS vars that globals.css wires into
// --font-sans / --font-mono / --font-display.
//
// ADR-074 §4 TARGETS INTER. IT WAS TRIED ON 2026-08-15 AND REVERTED, FOR THE SECOND
// TIME, ON THE MEASUREMENT — under founder ruling R3, which set the gate and the
// consequence: "if it regresses, revert to Plus Jakarta and tell me — the font is not
// worth the route."
//
//   preloaded critical-path woff2   Plus Jakarta 67,752 B  →  Inter 88,912 B  (+21,160)
//   total woff2 emitted             145,288 B             →  305,208 B
//
// +21,160 B is the SAME figure the first revert recorded, reproduced to the byte.
// R3's premise was that a self-hosted, subset build "is a different measurement, not
// that one re-run". It is not: `next/font/google` already self-hosts (it downloads at
// BUILD time and serves from our origin — no runtime Google request), and it already
// subsets to `latin`. Pinning `weight: 400/500/600` per ADR-074 §4 changed nothing —
// 88,912 B either way, because next/font ships the variable face regardless. Inter's
// latin subset is simply 48,432 B against Plus Jakarta's 27,272 B.
//
// Beating it needs a CUSTOM glyph subset (pyftsubset) committed as a local woff2 — a
// real build step and a binary in the repo. Not taken without a ruling.
//
// `weight` is deliberately OMITTED: that makes next/font fetch the VARIABLE axis rather
// than static instances, which is what lets the type scale ask for weights between the
// named stops. Plus Jakarta's axis is 200–800.
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
		"The flight recorder for AI agents. Full-fidelity traces, a tamper-evident audit ledger you can verify offline, and inline heuristic guardrails.",
	// Brand assets (public/brand) — the ADR-074 geometric T monogram, monochrome.
	// The Chisel bracket-recorder mark it replaced is dead; do not resurrect it.
	// One polarity only (dark mark on light), pinned PERMANENTLY by founder decision:
	// no `prefers-color-scheme` swap, so the same mark shows in both browser chromes.
	// Every file is GENERATED and decode-verified by scripts/brand/build-brand-assets.py.
	icons: {
		icon: [
			{ url: "/brand/favicon-32.png", type: "image/png", sizes: "32x32" },
			{ url: "/brand/favicon-16.png", type: "image/png", sizes: "16x16" },
			{ url: "/brand/tracelane-mark.svg", type: "image/svg+xml" },
		],
		// B-252 CLOSED: this pointed at /brand/logo-icon-light.png, which 4088da73 deleted
		// — a 404 apple-touch icon in production from that commit until 2026-08-15. Every
		// file named here is generated and DECODE-VERIFIED by
		// scripts/brand/build-brand-assets.py, which refuses to emit a blank or solid
		// asset. Do not hand-edit these PNGs; change the geometry and rebuild.
		apple: {
			url: "/brand/apple-touch-icon.png",
			type: "image/png",
			sizes: "180x180",
		},
	},
};

// Explicit mobile viewport (Next injects this by default, but pin it so the
// dashboard always scales to the device — no zoomed-out desktop layout on phones).
export const viewport: Viewport = {
	width: "device-width",
	initialScale: 1,
};

export default async function RootLayout({
	children,
}: { children: ReactNode }) {
	// ADR-074 §6: the sidebar's collapsed state is read HERE, on the server, so the
	// first painted frame is already correct. Reading it in a client effect would
	// render expanded and then snap — the flash §6 explicitly calls out. This is a
	// server-render problem, which is why no component library solves it for you.
	const collapsed =
		(await cookies()).get("sidebar_state")?.value === "collapsed";

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
					<AppShell orgSlot={<OrgSwitcher />} defaultCollapsed={collapsed}>
						{children}
					</AppShell>
					<CommandPalette />
				</Providers>
			</body>
		</html>
	);
}
