import { describe, expect, it } from "vitest";
import { evidenceValue, formatMinor } from "./actions";

describe("exact action amounts", () => {
	it("preserves every cent through the admitted integer boundary", () => {
		expect(formatMinor(Number.MAX_SAFE_INTEGER, "USD")).toBe(
			"$90,071,992,547,409.91",
		);
		expect(formatMinor(-Number.MAX_SAFE_INTEGER, "USD")).toBe(
			"-$90,071,992,547,409.91",
		);
	});
	it("keeps normal, sub-unit and currency-specific amounts", () => {
		expect(formatMinor(1500000, "USD")).toBe("$15,000.00");
		expect(formatMinor(-1, "USD")).toBe("-$0.01");
		expect(formatMinor(0, "USD")).toBe("$0.00");
		expect(formatMinor(123, "JPY")).toBe("¥123");
		expect(formatMinor(1234, "KWD")).toBe("KWD\u00a01.234");
		expect(formatMinor(Number.MAX_SAFE_INTEGER + 1, "USD")).toBeNull();
	});
	it("shows the exact bound amount through the shared evidence renderer", () => {
		const amount = {
			mode: "clear",
			value: { MinorUnits: Number.MAX_SAFE_INTEGER },
		} as const;
		expect(
			evidenceValue(amount, {
				amount,
				currency: { mode: "clear", value: { Currency: "USD" } },
			}),
		).toBe("$90,071,992,547,409.91");
	});
});
