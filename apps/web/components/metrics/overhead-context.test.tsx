import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { OverheadContext } from "./OverheadContext";
it("does not turn missing split fields into zeros", () => {
	const html = renderToStaticMarkup(
		<OverheadContext data={{ overhead_samples: 8 }} />,
	);
	expect(html).toContain("Measured on your real requests");
	expect(html).not.toContain("cold start");
	expect(html).not.toContain("Steady state");
	expect(html).not.toContain("Served from cache");
});
it("uses sample counts to distinguish zero time from no warm measurements", () => {
	const html = renderToStaticMarkup(
		<OverheadContext
			data={{
				overhead_samples: 5,
				warm_samples: 0,
				cold_start_samples: 5,
				overhead_warm_p50_ms: 0,
				overhead_warm_p95_ms: 0,
				cache_hit_samples: 2,
				cache_hit_served_p50_ms: 0,
				cache_hit_served_p95_ms: 1,
			}}
		/>,
	);
	expect(html).toContain("Steady state p50 — · p95 —");
	expect(html).toContain("5 of 5 requests paid a cold start");
	expect(html).toContain("Served from cache");
	expect(html).toContain("0 ms");
	expect(html).toContain("excluded");
});
