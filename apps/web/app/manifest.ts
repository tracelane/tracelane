import type { MetadataRoute } from "next";

/**
 * PWA web app manifest — makes an installed Tracelane use the official Chisel
 * app icon (logo-icon-*, 512²) and the Tinted-Slate canvas as the splash/theme
 * color (ADR-053). Next serves this at /manifest.webmanifest and links it.
 */
export default function manifest(): MetadataRoute.Manifest {
	return {
		name: "Tracelane",
		short_name: "Tracelane",
		description:
			"Predictive reliability platform for AI agents. Full-fidelity traces, provider failover, and inline guardrails.",
		start_url: "/",
		display: "standalone",
		background_color: "#f4f6fa",
		theme_color: "#f4f6fa",
		icons: [
			{
				src: "/brand/logo-icon-light.png",
				sizes: "512x512",
				type: "image/png",
				purpose: "any",
			},
			{
				src: "/brand/logo-icon-dark.png",
				sizes: "512x512",
				type: "image/png",
				purpose: "any",
			},
		],
	};
}
