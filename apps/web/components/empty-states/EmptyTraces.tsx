/**
 * EmptyTraces — zero-state for the traces page.
 *
 * Shown when a tenant has no traces yet. Gives developers the minimal
 * install snippet so they can get their first trace without leaving the UI.
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
		<div className="rounded-xl border border-dashed border-line p-10 text-center max-w-2xl mx-auto mt-12">
			<div className="mb-6">
				<div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-surface-2 mb-4">
					<svg
						aria-hidden="true"
						focusable="false"
						className="w-6 h-6 text-ink-2"
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
				</div>
				<h2 className="text-base font-semibold text-ink mb-1">No traces yet</h2>
				<p className="text-sm text-ink-2 max-w-sm mx-auto">
					Point your agent at the Tracelane gateway and your first trace will
					appear here within a second.
				</p>
			</div>

			<div className="text-left rounded-lg border border-line overflow-hidden mb-6">
				<div className="flex border-b border-line bg-surface/80">
					{(["python", "typescript"] as const).map((t) => (
						<button
							key={t}
							type="button"
							onClick={() => setTab(t)}
							className={`px-4 py-2 text-xs font-medium transition-colors ${
								tab === t
									? "text-ink border-b-2 border-accent-ink -mb-px"
									: "text-ink-2 hover:text-ink"
							}`}
						>
							{t === "python" ? "Python" : "TypeScript"}
						</button>
					))}
				</div>
				<pre className="p-4 text-xs font-mono text-ink overflow-x-auto bg-bg/50 leading-relaxed">
					{snippet}
				</pre>
			</div>

			{gatewayUrl && (
				<p className="text-xs text-ink-3 mb-4">
					Gateway:{" "}
					<code className="font-mono bg-surface-2 px-1.5 py-0.5 rounded">
						{gatewayUrl}
					</code>
				</p>
			)}

			<div className="flex items-center justify-center gap-4">
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
