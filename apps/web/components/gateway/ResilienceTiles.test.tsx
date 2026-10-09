import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { ResilienceTiles } from "./ResilienceTiles";
it("no failures has no fabricated rescue rate", () => {
	const html = renderToStaticMarkup(
		<ResilienceTiles
			initial={{
				requests_with_failed_attempt: 0,
				rescued_by_failover: 0,
				rescued_by_retry: 0,
				rescue_rate_pct: null,
				rescue_added_ms_p50: null,
				attempt_records_since: "2026-09-19",
				agent_loops: {
					instances: 0,
					groups: 0,
					tool_calls: 0,
					unfingerprinted_tool_calls: 0,
					min_repeats: 3,
					window_secs: 300,
				},
			}}
			query="since=start&until=end"
		/>,
	);
	expect(html).toContain(
		"No provider failures in this range — nothing needed rescuing",
	);
	expect(html).not.toContain("100%");
	expect(html).toContain("No tool calls in this range.");
});
it("missing loop evidence is an error, not zero", () => {
	const html = renderToStaticMarkup(
		<ResilienceTiles
			initial={{
				requests_with_failed_attempt: 2,
				rescued_by_failover: 1,
				rescued_by_retry: 0,
				rescue_rate_pct: 50,
				rescue_added_ms_p50: 120,
				attempt_records_since: "2026-09-19",
				agent_loops: null,
			}}
			query="since=start"
		/>,
	);
	expect(html).toContain("Couldn&#x27;t load");
	expect(html).toContain("rescued=failover");
	expect(html).toContain("2026-09-19");
});
it("renders null rescue evidence as unavailable, never as zero rescues", () => {
	const html = renderToStaticMarkup(
		<ResilienceTiles
			query=""
			initial={{
				requests_with_failed_attempt: null,
				rescued_by_failover: null,
				rescued_by_retry: null,
				rescue_rate_pct: null,
				rescue_added_ms_p50: null,
			}}
		/>,
	);
	expect(html).toContain("Couldn&#x27;t load");
	expect(html).not.toContain("0 of");
	expect(html).not.toContain("nothing needed rescuing");
});
