/**
 * TryItCurl — the "try it" moment on the Gateway page. A copyable curl that
 * sends a real request through the user's gateway, so a newcomer can watch a
 * request appear in the numbers above. Uses NEXT_PUBLIC_GATEWAY_URL (client-baked)
 * and a `tlane_<your_key>` PLACEHOLDER — we never echo a real key; the user mints
 * one under Settings. This is what the gateway IS, taught in one snippet.
 *
 * ── P1 DESIGN PASS (2026-08-22) ─────────────────────────────────────────────
 * The URL, the headers, the JSON payload, the auth example and every word of copy
 * are UNCHANGED — a developer copying this must get exactly the request they got
 * before. What changed is the surface it is served on.
 *
 * THE SNIPPET NOW SITS ON A REAL CODE SURFACE. It was `--surface` inside a
 * `rounded-lg` outline, i.e. the same plane as the page around it, which made a
 * command a reader is meant to copy read as a paragraph that happened to be
 * monospace. `--canvas-sunken` is the token for a recessed plane (it is what the
 * table headers and `<kbd>` use), bordered top and bottom so it holds its own
 * edge — which matters most in DARK, where the step between a card and the plane
 * under it is small and a borderless well would dissolve into the card.
 *
 * The panel is a quiet `<Card>` rather than a bare `rounded-lg` `<section>`: the
 * radius was the 8px CONTROL radius on a full-width PANEL, so it sat beside 18px
 * cards looking like an oversized button. `<Card>` renders a `<div>`, and nothing
 * is lost — the old `<section>` carried no accessible name, so it was never
 * exposed as a landmark; the `<h2>` inside is what names this block either way.
 */
"use client";

import { Card } from "@tracelanedev/ui";
import { useState } from "react";

const GATEWAY_URL =
	process.env.NEXT_PUBLIC_GATEWAY_URL ?? "https://gateway.tracelane.dev";

const CURL = `curl ${GATEWAY_URL}/v1/chat/completions \\
  -H "Authorization: Bearer tlane_<your_key>" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello from the gateway"}]}'`;

export function TryItCurl() {
	const [copied, setCopied] = useState(false);

	const copy = async () => {
		try {
			await navigator.clipboard.writeText(CURL);
			setCopied(true);
			setTimeout(() => setCopied(false), 1500);
		} catch {
			// clipboard blocked (no HTTPS / permission) — the text is selectable anyway.
		}
	};

	return (
		<Card quiet className="overflow-hidden">
			<div className="flex flex-wrap items-start justify-between gap-3 px-5 pb-4 pt-5">
				<div className="min-w-0">
					{/* `.t-card-title` — this is a CARD, not a page section, so it takes
					    the 13px sentence-case card role rather than the uppercase
					    eyebrow the four data sections above it use. */}
					<h2 className="t-card-title">Send a request through the gateway</h2>
					<p className="mt-1 max-w-2xl text-xs text-ink-3">
						Run this and watch it appear in the numbers above — that's the
						gateway proxying, capturing, and guarding the call.
					</p>
				</div>
				<button
					type="button"
					onClick={copy}
					className="shrink-0 rounded-md border border-line px-2.5 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
				>
					{copied ? "Copied ✓" : "Copy"}
				</button>
			</div>
			{/* The code surface. `border-y` is not decoration: in dark theme the step
			    from `--surface` to `--canvas-sunken` is a couple of percent, so without
			    its own hairline the well would have no edge at all. */}
			<div className="overflow-x-auto border-y border-line bg-canvas-sunken px-5 py-4">
				<pre className="font-mono text-xs leading-relaxed text-ink-2">
					{CURL}
				</pre>
			</div>
			<p className="px-5 py-3 text-2xs text-ink-3">
				Replace <span className="font-mono">tlane_&lt;your_key&gt;</span> with a
				key from{" "}
				<a
					href="/settings/api-keys"
					className="font-medium text-action-ink hover:underline"
				>
					Settings → API keys
				</a>
				. The gateway URL is your workspace's.
			</p>
		</Card>
	);
}
