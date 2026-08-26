/**
 * EmptyPrompts — zero-state for the prompts list page.
 *
 * Shown when the tenant has no prompts yet. Gives developers the HTTP API
 * snippets to author their first version and to promote it. There is no
 * `tlane prompt register` CLI command — do not advertise one.
 *
 * For the authoring form (in-dashboard), navigate to /prompts/<name> once a
 * prompt exists — the detail page has a built-in "Author new version" form.
 *
 * ── THE DASHED BOX IS GONE (P0.9, 2026-08-22) ───────────────────────────────
 * Same change, same reason, as EmptyTraces: this drew `rounded-xl border
 * border-dashed border-line p-10`, and a dashed rectangle is what a BROKEN
 * region looks like, not an empty one. The shared `EmptyState` primitive
 * dropped its own dashed box in the same pass. This component keeps its own
 * layout because the snippet panel must be full width with its own horizontal
 * scroll, which the primitive's centred `action` slot cannot give it — but it
 * now uses the primitive's exact vocabulary for the icon chip, the statement
 * and the explanation, so the two read as one component.
 */

"use client";

import Link from "next/link";
import { useState } from "react";

const AUTHOR_SNIPPET = `POST /v1/prompts/{name}/versions
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "content": "You are a helpful assistant.",
  "model_pin": "gpt-4o-mini"
}

# Returns 201 + { prompt_version_id, version_number, sha256_hex }
#
# \`template_variables\` is accepted and stored, but the gateway does NOT
# substitute placeholders — a \`{{var}}\` in the content is served literally.
# Interpolate on your side before sending. Omitted here so this snippet does
# not teach a substitution that does not happen.`;

const PROMOTE_SNIPPET = `POST /v1/prompts/{name}/promote
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "from_env": "staging",
  "to_env": "production",
  "to_version_id": "<prompt_version_id>",
  "override_reason": "why you are promoting without an eval run"
}

# Team plan ($249/mo) required for promote.
# Builder plan ($59/mo) can author versions — promote is gated.
#
# \`override_reason\` is shown rather than \`eval_run_id\` because eval runs
# are not produced yet: passing an \`eval_run_id\` returns 409 today. The
# override is recorded as an explicit, attributed bypass in the audit chain,
# which is the honest way to promote until eval runs exist.`;

export function EmptyPrompts() {
	const [tab, setTab] = useState<"author" | "promote">("author");

	const snippet = tab === "author" ? AUTHOR_SNIPPET : PROMOTE_SNIPPET;

	return (
		// `px-4` + `py-6 sm:py-10` rather than a flat `p-10`, which on a 360px
		// phone left the snippet ~280px wide (P0.17).
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
							d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z"
						/>
					</svg>
				</span>
				<div className="space-y-1">
					<h2 className="text-sm font-medium text-ink">No prompts yet</h2>
					<p className="mx-auto max-w-sm text-xs text-ink-2">
						Use <span className="font-medium text-ink">New prompt</span> above
						to name one and author its first version — or author via the HTTP
						API below, then promote through staging to production.
					</p>
				</div>
			</div>

			{/* The snippet panel is a real (quiet) card — `.surface-card` gives it
			    `--radius-card` instead of the 8px control radius, and
			    `overflow-hidden` clips the tab strip and the <pre> to it. The strip
			    is `--canvas-sunken`, the declared role for a header band; it was
			    `bg-surface`, an 80% white over an unknown parent. */}
			<div className="surface-card surface-card--quiet mb-6 overflow-hidden border border-line text-left">
				<div className="flex border-b border-line bg-canvas-sunken">
					{(["author", "promote"] as const).map((t) => (
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
							{t === "author" ? "Author version" : "Promote"}
						</button>
					))}
				</div>
				<pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-ink">
					{snippet}
				</pre>
			</div>

			<div className="flex flex-wrap items-center justify-center gap-4">
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
