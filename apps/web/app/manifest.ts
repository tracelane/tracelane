import type { MetadataRoute } from "next";

/**
 * PWA web app manifest. Next serves this at /manifest.webmanifest and links it.
 * The splash/theme colour is a LITERAL by necessity — a JSON manifest cannot read a
 * CSS custom property — so it is one of only two places in the app that may hold a
 * hardcoded colour, and it must be re-synced by hand whenever the canvas token moves.
 */
export default function manifest(): MetadataRoute.Manifest {
	return {
		name: "Tracelane",
		short_name: "Tracelane",
		description:
			"The flight recorder for AI agents. Full-fidelity traces, a tamper-evident audit ledger you can verify offline, and inline heuristic guardrails.",
		start_url: "/",
		display: "standalone",
		background_color: "#f4f6fa",
		theme_color: "#f4f6fa",
		// B-252 CLOSED (2026-08-15). These pointed at /brand/logo-icon-light.png and
		// /brand/logo-icon-dark.png at a DECLARED 512x512. Commit 4088da73 deleted both
		// PNGs when the mark moved to inline SVG and left the references behind, so an
		// installed PWA had NO icon at all — in production, from that commit until now.
		//
		// Every size below is the TRUE decoded size, not a claim. A wrong declared size is
		// the same class of defect as a missing file: the manifest asserting something the
		// bytes do not support. Generated + decode-verified by
		// scripts/brand/build-brand-assets.py.
		icons: [
			{
				src: "/brand/pwa-192.png",
				sizes: "192x192",
				type: "image/png",
				purpose: "any",
			},
			{
				src: "/brand/pwa-512.png",
				sizes: "512x512",
				type: "image/png",
				purpose: "any",
			},
		],
	};
}
