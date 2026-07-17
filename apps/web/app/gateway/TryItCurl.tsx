/**
 * TryItCurl — the "try it" moment on the Gateway page. A copyable curl that
 * sends a real request through the user's gateway, so a newcomer can watch a
 * request appear in the numbers above. Uses NEXT_PUBLIC_GATEWAY_URL (client-baked)
 * and a `tlane_<your_key>` PLACEHOLDER — we never echo a real key; the user mints
 * one under Settings. This is what the gateway IS, taught in one snippet.
 */
"use client";

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
		<section className="rounded-lg border border-line">
			<div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
				<div>
					<h2 className="text-sm font-semibold text-ink">
						Send a request through the gateway
					</h2>
					<p className="mt-0.5 text-[12px] text-ink-3">
						Run this and watch it appear in the numbers above — that's the
						gateway proxying, capturing, and guarding the call.
					</p>
				</div>
				<button
					type="button"
					onClick={copy}
					className="shrink-0 rounded-md border border-line px-2.5 py-1.5 text-xs font-medium text-ink-2 transition-colors hover:border-line-2 hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
				>
					{copied ? "Copied ✓" : "Copy"}
				</button>
			</div>
			<div className="overflow-x-auto px-4 py-3">
				<pre className="font-mono text-[12px] leading-relaxed text-ink-2">
					{CURL}
				</pre>
			</div>
			<p className="border-t border-line px-4 py-2 text-[11px] text-ink-3">
				Replace <span className="font-mono">tlane_&lt;your_key&gt;</span> with a
				key from{" "}
				<a
					href="/settings/api-keys"
					className="font-medium text-accent-ink hover:underline"
				>
					Settings → API keys
				</a>
				. The gateway URL is your workspace's.
			</p>
		</section>
	);
}
