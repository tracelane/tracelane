/**
 * EmptyTraces — zero-state for the traces page.
 *
 * Shown when a tenant has no traces yet. Gives developers the minimal
 * install snippet so they can get their first trace without leaving the UI.
 *
 * ── THE DASHED BOX IS GONE (P0.9, 2026-08-22) ───────────────────────────────
 * This drew `rounded-xl border border-dashed border-line p-10`. A dashed
 * rectangle is the universal idiom for "content failed to load" — a broken
 * image, an unmounted region, a drop target all look like that — so the first
 * screen a new tenant ever sees was telling them the product was broken. The
 * shared `EmptyState` primitive dropped the same box in the same pass; this
 * component predates it and had quietly hand-rolled its own.
 *
 * WHY THIS IS NOT SIMPLY `<EmptyState>`, since that is the obvious question.
 * The primitive centres its `action` slot in a `flex-col items-center` column,
 * so a child sizes to its content — and the snippet panel below has to be
 * FULL WIDTH with its own horizontal scroll. Giving the primitive a
 * full-width action slot is a change to packages/ui. So this file matches the
 * primitive's VOCABULARY exactly instead — the same `h-9 w-9` `--surface-2`
 * icon chip, the same statement/explanation pair, the same measure on the
 * explanation — and only the layout differs.
 */

"use client";

import Link from "next/link";
import { useState } from "react";

// Point your existing Anthropic client at the gateway base URL — it routes the
// call and captures the trace. No SDK install needed for the proxy path.
const PYTHON_SNIPPET = `from anthropic import Anthropic

client = Anthropic(
    base_url="https://gateway.tracelane.dev",
    api_key="YOUR_TRACELANE_API_KEY",
)

message = client.messages.create(
    model="claude-haiku-4-5",
    max_tokens=64,
    messages=[{"role": "user", "content": "Hello, world!"}],
)
print(message.content)`;

const TS_SNIPPET = `import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  baseURL: "https://gateway.tracelane.dev",
  apiKey: "YOUR_TRACELANE_API_KEY",
});

const message = await client.messages.create({
  model: "claude-haiku-4-5",
  max_tokens: 64,
  messages: [{ role: "user", content: "Hello, world!" }],
});
console.log(message.content);`;

export function EmptyTraces({ gatewayUrl }: { gatewayUrl?: string }) {
	const [tab, setTab] = useState<"python" | "typescript">("python");

	const snippet = tab === "python" ? PYTHON_SNIPPET : TS_SNIPPET;

	return (
		// `px-4` + `py-6 sm:py-10`: the old flat `p-10` was 40px of padding on a
		// 360px phone, which left the snippet ~280px wide (P0.17).
		<div className="mx-auto mt-12 max-w-2xl px-4 py-6 text-center sm:py-10">
			<div className="mb-6 flex flex-col items-center gap-3">
				<span
					aria-hidden="true"
					className="grid h-9 w-9 place-items-center rounded-xl bg-surface-2 text-ink-2"
				>
					<svg
						aria-hidden="true"
						focusable="false"
						className="h-5 w-5"
						fill="none"
						viewBox="0 0 24 24"
						stroke="currentColor"
						strokeWidth={1.5}
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5M9 11.25v1.5M12 9v3.75m3-6v6"
						/>
					</svg>
				</span>
				<div className="space-y-1">
					<h2 className="text-sm font-medium text-ink">No traces yet</h2>
					<p className="mx-auto max-w-xs text-xs text-ink-2">
						Point your agent at the Tracelane gateway and your first trace will
						appear here within a second.
					</p>
				</div>
			</div>

			{/* The snippet panel is a real (quiet) card, so it picks up
			    `--radius-card` from `.surface-card` instead of the 8px control
			    radius it used to borrow. `overflow-hidden` clips the tab strip and
			    the <pre> to that radius. The strip is `--canvas-sunken`, the role
			    for a header band under the card surface — it was `bg-surface`,
			    an 80% white over an unknown parent, which is not a colour anyone
			    chose. */}
			<div className="surface-card surface-card--quiet mb-6 overflow-hidden border border-line text-left">
				<div className="flex border-b border-line bg-canvas-sunken">
					{(["python", "typescript"] as const).map((t) => (
						<button
							key={t}
							type="button"
							onClick={() => setTab(t)}
							className={`px-4 py-2 text-xs font-medium transition-colors ${
								tab === t
									? "text-ink border-b-2 border-action-ink -mb-px"
									: "text-ink-2 hover:text-ink"
							}`}
						>
							{t === "python" ? "Python" : "TypeScript"}
						</button>
					))}
				</div>
				<pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-ink">
					{snippet}
				</pre>
			</div>

			{gatewayUrl && (
				<p className="text-xs text-ink-3 mb-4">
					Gateway:{" "}
					<code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono break-all">
						{gatewayUrl}
					</code>
				</p>
			)}

			<div className="flex flex-wrap items-center justify-center gap-4">
				<Link
					href="/settings/api-keys"
					className="text-xs text-ink-2 hover:text-ink underline underline-offset-2 transition-colors"
				>
					Get your API key →
				</Link>
				<Link
					href="https://docs.tracelane.dev/sdk-python"
					target="_blank"
					rel="noopener noreferrer"
					className="text-xs text-ink-2 hover:text-ink underline underline-offset-2 transition-colors"
				>
					SDK docs →
				</Link>
			</div>
		</div>
	);
}
