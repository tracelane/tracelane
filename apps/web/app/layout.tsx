/**
 * Root layout — loaded once, wraps every route.
 *
 * Provides: the TanStack Query client, the global navigation shell, and font
 * loading.
 *
 * Layout structure:
 *   <html>
 *     <body>
 *       <AppShell>          ← sidebar rail + thin top bar, full-bleed content
 *         {children}        ← route content, on the `--canvas` ground
 *       </AppShell>
 *       <CommandPalette />
 *     </body>
 *   </html>
 *
 * NO `<Providers>` HERE ANY MORE. It mounts TanStack Query's QueryClientProvider,
 * and every `useQuery`/`useMutation` call site in this app is under
 * `components/settings/` — so a global mount shipped the react-query runtime
 * (chunk `8304`, 15,804 B raw / 5,279 B transferred, measured on a production
 * build) to /dashboard, /traces, /slo, /gateway, /audit and every other route
 * that never calls it. It now lives in `app/settings/layout.tsx`, the narrowest
 * layout that covers all seven consumers.
 * Consequence worth knowing: the query cache is scoped to the settings section,
 * so leaving /settings and returning refetches instead of serving a ≤30s-stale
 * entry. For tenant-scoped settings data that is the safer direction.
 *
 * TWO CLAIMS IN THIS BLOCK WERE FALSE AND ARE CORRECTED HERE (CLAUDE.md §17).
 *   · "Zustand store initialisation" / "TanStack Query + Zustand" — providers.tsx
 *     mounts a QueryClientProvider and nothing more, and `zustand` is not a
 *     dependency of this app. apps/web/CLAUDE.md already says "no Zustand"; the
 *     header here disagreed with both the code and that rule.
 *   · "framed sky-blue shell … inside the floating canvas" — AppShell has neither
 *     a frame nor a floating canvas (it dropped both with the sidebar move), and
 *     under the P0 palette there is no blue anywhere in the system to be framed
 *     in. The ground is `--canvas`, a warm neutral.
 *
 * AppShell reads the pathname and renders route content bare (no frame/nav)
 * on the full-screen routes — /onboarding and the auth pages — so unauthenticated
 * or wizard flows never show app chrome.
 */

import { CommandPalette } from "@/components/command-palette/CommandPalette";
import { AppShell } from "@/components/layout/AppShell";
import { OrgSwitcher } from "@/components/layout/OrgSwitcher";
import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { cookies } from "next/headers";
import type { ReactNode } from "react";
import "./globals.css";

// No-flash theme seed (ADR-053). Runs synchronously before first paint and
// before hydration, setting <html data-theme> from the persisted `theme`
// cookie so the correct token set applies on the very first frame. Kept as an
// inline pre-paint script (not a server cookie read) so static routes
// stay statically prerendered. Light is the default.
const THEME_INIT = `(function(){try{var m=document.cookie.match(/(?:^|;\\s*)theme=(light|dark)/);document.documentElement.dataset.theme=(m&&m[1]==='dark')?'dark':'light';}catch(e){}})();`;

// ── TYPE (P0.3, founder brief 2026-08-22) ───────────────────────────────────
//
// Geist (UI) + Geist Mono (numerals, ids, hashes, seq, model names, code).
// Exposed as CSS vars that globals.css wires into --font-sans / --font-mono /
// --font-display.
//
// THE BRIEF MADE THIS CONDITIONAL — "if Geist is already available or can be added
// cleanly without disrupting the application" — so it was MEASURED before it was
// taken, on both axes the condition covers:
//
// 1. DEPENDENCY COST: ZERO. Geist and Geist Mono are in `next/font/google`'s own
//    catalog (`next/dist/compiled/@next/font/dist/google/font-data.json`, 1,862
//    families, both present with a 100–900 variable axis and a `latin` subset).
//    next/font DOWNLOADS AT BUILD TIME AND SERVES FROM OUR ORIGIN — there is no
//    runtime Google request and no new package in package.json. The `geist` npm
//    package was NOT needed and is not installed.
//
// 2. PAYLOAD COST: IT IS A SAVING, WHICH INVERTS THE PRIOR RULING. Founder ruling
//    R3 set the gate for a font swap after Inter was tried and reverted TWICE on
//    the critical-path byte count ("if it regresses, revert to Plus Jakarta and
//    tell me — the font is not worth the route"). Inter cost +21,160 B. Measured
//    latin-subset woff2, fetched from fonts.gstatic.com on 2026-08-22:
//
//      sans   Plus Jakarta Sans 27,348 B  ->  Geist       29,400 B   (+2,052)
//      mono   JetBrains Mono    40,404 B  ->  Geist Mono  23,128 B  (-17,276)
//      ------------------------------------------------------------------------
//      critical-path preload    67,752 B  ->  52,528 B   (-15,224 B, -22.5%)
//
//    The win is entirely in the MONO face, and that matters here specifically
//    because this app sets `font-mono` on every numeral, id, hash and model name —
//    JetBrains Mono was the single largest font on the route and it was the one
//    doing the most work. R3's gate is satisfied in the customer's favour.
//
// `weight` is deliberately OMITTED: that makes next/font fetch the VARIABLE axis
// rather than static instances, which is what lets the type scale ask for weights
// between the named stops. Geist's axis is 100–900.
const geistSans = Geist({
	subsets: ["latin"],
	variable: "--font-geist-sans",
	display: "swap",
});
const geistMono = Geist_Mono({
	subsets: ["latin"],
	variable: "--font-geist-mono",
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
			className={`${geistSans.variable} ${geistMono.variable}`}
			suppressHydrationWarning
		>
			<head>
				{/* biome-ignore lint/security/noDangerouslySetInnerHtml: trusted
				    static constant, no user input — the standard no-flash theme seed. */}
				<script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
			</head>
			<body>
				<AppShell orgSlot={<OrgSwitcher />} defaultCollapsed={collapsed}>
					{children}
				</AppShell>
				<CommandPalette />
			</body>
		</html>
	);
}
