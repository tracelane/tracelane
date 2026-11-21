import {
	COVERAGE_NOTE,
	type Coverage,
	type PolicyRef,
	type SeenTool,
	buildCoverage,
	protectedFlagOf,
} from "@/lib/coverage";
import { gatewayGet } from "@/lib/gateway";
import { Badge } from "@tracelanedev/ui";

/** Detail reads per page view; policies beyond this are shown as "Could not check". */
const MAX_DETAIL_READS = 25;

const isArray = (v: unknown): v is unknown[] => Array.isArray(v);

/** At most this many detail reads in flight (Workers allow about 6 outbound connections). */
const CONCURRENCY = 6;

export type LoadedCoverage = Coverage & { unchecked: number };

/** Read-only coverage from existing gateway data; `null` when a read failed (never zero). */
export async function loadCoverage(): Promise<LoadedCoverage | null> {
	let seen: SeenTool[];
	let policies: PolicyRef[];
	try {
		const [t, p] = await Promise.all([
			gatewayGet<{ tools?: unknown }>("/v1/mcp-tools"),
			gatewayGet<{ policies?: unknown }>("/v1/action-policies"),
		]);
		if (!isArray(t.tools) || !isArray(p.policies)) throw new Error("shape");
		seen = t.tools as SeenTool[];
		policies = p.policies as PolicyRef[];
	} catch (err) {
		console.warn("coverage: list read failed", err);
		return null;
	}
	const flags: Record<string, boolean | undefined> = {};
	const queue = policies.slice(0, MAX_DETAIL_READS);
	let failed = 0;
	const worker = async () => {
		for (let p = queue.shift(); p; p = queue.shift()) {
			try {
				const d = await gatewayGet<{ contract_jcs?: unknown }>(
					`/v1/action-policies/${encodeURIComponent(p.tool_ref)}`,
				);
				flags[p.tool_ref] = protectedFlagOf(d.contract_jcs);
			} catch {
				failed += 1;
				flags[p.tool_ref] = undefined;
			}
		}
	};
	await Promise.all(Array.from({ length: CONCURRENCY }, worker));
	if (failed > 0) console.warn(`coverage: ${failed} contract read(s) failed`);
	try {
		return {
			...buildCoverage(seen, policies, flags),
			unchecked: Math.max(0, policies.length - MAX_DETAIL_READS),
		};
	} catch (err) {
		// A malformed list element must read as "could not be loaded", never reject:
		// the page may return early on an actions-read failure and never await this.
		console.warn("coverage: malformed list", err);
		return null;
	}
}

export function CoveragePanel({
	coverage: c,
}: { coverage: LoadedCoverage | null }) {
	if (!c)
		return (
			<section aria-labelledby="coverage-title" className="space-y-1">
				<h3 id="coverage-title" className="text-sm font-semibold">
					Coverage
				</h3>
				<p className="text-sm text-ink-2">
					Coverage could not be loaded. {COVERAGE_NOTE}
				</p>
			</section>
		);
	return (
		<section aria-labelledby="coverage-title" className="space-y-2">
			<h3 id="coverage-title" className="text-sm font-semibold">
				Coverage
			</h3>
			<p className="text-sm">{c.sentence}</p>
			{c.unchecked > 0 && (
				<p className="text-sm text-ink-2">
					{c.unchecked} more tool{" "}
					{c.unchecked === 1 ? "policy was" : "policies were"} not checked on
					this page.
				</p>
			)}
			<p className="text-sm text-ink-2">{COVERAGE_NOTE}</p>
			{c.rows.length > 0 && (
				<ul className="divide-y divide-line rounded-card border border-line">
					{c.rows.map((r) => (
						<li
							key={r.key}
							className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2 text-sm"
						>
							<span className="font-mono">{r.tool}</span>
							<span className="flex-1 text-ink-2">
								{r.server}
								{r.seen ? "" : " · not seen yet"}
							</span>
							<Badge
								tone={
									r.state === "protected"
										? "ok"
										: r.state === "unchecked"
											? "warn"
											: "neutral"
								}
							>
								{r.state === "protected"
									? "Protected"
									: r.state === "unchecked"
										? "Could not check"
										: "Observed only"}
							</Badge>
						</li>
					))}
				</ul>
			)}
			{c.truncated && (
				<p className="text-xs text-ink-2">
					Showing the first 100 of {c.total} tools.
				</p>
			)}
		</section>
	);
}
