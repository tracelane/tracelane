/**
 * EmptyEvals — zero-state for the eval scoreboard.
 *
 * Shown when INDEX.md hasn't been generated yet. Gives developers
 * the exact command to generate it and a link to the eval docs.
 */

"use client";

import Link from "next/link";
import { useState } from "react";

const PYTHON_EVAL_SNIPPET = `# evals/pain-points/PP-G1.eval.ts style — run with:
pnpm eval:run --suite=all

# Or target a single eval:
pnpm eval:run --id=PP-G1`;

// Escape the GitHub Actions `${{ secrets.X }}` placeholder so Biome's
// TS parser does not try to evaluate it as a JS template interpolation.
const CI_SNIPPET = `# .github/workflows/ci.yml — evals run as merge gate
- name: Run eval suite
  run: pnpm eval:run --suite=all
  env:
    TRACELANE_GATEWAY_URL: \${{ secrets.GATEWAY_URL }}
    TRACELANE_API_KEY: \${{ secrets.API_KEY }}`;

export function EmptyEvals() {
	const [tab, setTab] = useState<"local" | "ci">("local");

	const snippet = tab === "local" ? PYTHON_EVAL_SNIPPET : CI_SNIPPET;

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
							d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
						/>
					</svg>
				</div>
				<h2 className="text-base font-semibold text-ink mb-1">
					No eval results yet
				</h2>
				<p className="text-sm text-ink-2 max-w-sm mx-auto">
					Run the eval suite to generate{" "}
					<code className="font-mono text-xs bg-surface-2 px-1 rounded">
						evals/pain-points/INDEX.md
					</code>
					. Results appear here automatically.
				</p>
			</div>

			<div className="text-left rounded-lg border border-line overflow-hidden mb-6">
				<div className="flex border-b border-line bg-surface/80">
					{(["local", "ci"] as const).map((t) => (
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
							{t === "local" ? "Local" : "CI / GitHub Actions"}
						</button>
					))}
				</div>
				<pre className="p-4 text-xs font-mono text-ink overflow-x-auto bg-bg/50 leading-relaxed">
					{snippet}
				</pre>
			</div>

			<div className="flex items-center justify-center gap-4">
				<Link
					href="https://docs.tracelane.dev/eval-gates"
					target="_blank"
					rel="noopener noreferrer"
					className="text-xs text-ink-2 hover:text-ink underline underline-offset-2 transition-colors"
				>
					Eval gates docs →
				</Link>
				<Link
					href="https://docs.tracelane.dev/slo"
					target="_blank"
					rel="noopener noreferrer"
					className="text-xs text-ink-2 hover:text-ink underline underline-offset-2 transition-colors"
				>
					SLO reference →
				</Link>
			</div>
		</div>
	);
}
