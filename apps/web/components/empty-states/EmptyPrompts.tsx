/**
 * EmptyPrompts — zero-state for the prompts list page.
 *
 * Shown when the tenant has no prompts yet. Gives developers the HTTP API
 * snippets to author their first version and to promote it. There is no
 * `tlane prompt register` CLI command — do not advertise one.
 *
 * For the authoring form (in-dashboard), navigate to /prompts/<name> once a
 * prompt exists — the detail page has a built-in "Author new version" form.
 */

"use client";

import Link from "next/link";
import { useState } from "react";

const AUTHOR_SNIPPET = `POST /v1/prompts/{name}/versions
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "content": "You are a helpful assistant. {{user_query}}",
  "model_pin": "gpt-4o-mini",
  "template_variables": ["user_query"]
}

# Returns 201 + { prompt_version_id, version_number, sha256_hex }`;

const PROMOTE_SNIPPET = `POST /v1/prompts/{name}/promote
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "from_env": "staging",
  "to_env": "production",
  "to_version_id": "<prompt_version_id>",
  "eval_run_id": "<uuid>"
}

# Team plan ($249/mo) required for promote.
# Builder plan ($59/mo) can author versions — promote is gated.`;

export function EmptyPrompts() {
	const [tab, setTab] = useState<"author" | "promote">("author");

	const snippet = tab === "author" ? AUTHOR_SNIPPET : PROMOTE_SNIPPET;

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
							d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z"
						/>
					</svg>
				</div>
				<h2 className="text-base font-semibold text-ink mb-1">
					No prompts yet
				</h2>
				<p className="text-sm text-ink-2 max-w-sm mx-auto">
					Use <span className="font-medium text-ink">New prompt</span> above to
					name one and author its first version — or author via the HTTP API
					below, then promote through staging to production with eval-gated
					guardrails.
				</p>
			</div>

			<div className="text-left rounded-lg border border-line overflow-hidden mb-6">
				<div className="flex border-b border-line bg-surface/80">
					{(["author", "promote"] as const).map((t) => (
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
							{t === "author" ? "Author version" : "Promote"}
						</button>
					))}
				</div>
				<pre className="p-4 text-xs font-mono text-ink overflow-x-auto bg-bg/50 leading-relaxed">
					{snippet}
				</pre>
			</div>

			<div className="flex items-center justify-center gap-4">
				<Link
					href="https://docs.tracelane.dev/prompts"
					target="_blank"
					rel="noopener noreferrer"
					className="text-xs text-ink-2 hover:text-ink underline underline-offset-2 transition-colors"
				>
					Prompt API docs →
				</Link>
				<Link
					href="/audit"
					className="text-xs text-ink-2 hover:text-ink underline underline-offset-2 transition-colors"
				>
					Audit ledger →
				</Link>
			</div>
		</div>
	);
}
