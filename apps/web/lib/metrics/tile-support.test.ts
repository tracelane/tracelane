import { expect, it } from "vitest";
import { METRICS } from "./registry";
import { tileSupport } from "./tile-support";

it("experiment entity metrics are not offered as context-free dashboard tiles", () => {
	for (const metric of Object.values(METRICS)) {
		if (metric.window !== "entity") continue;
		expect(tileSupport(metric.id)).toEqual({
			stat: false,
			series: false,
			breakdownDimensions: [],
		});
	}
});
