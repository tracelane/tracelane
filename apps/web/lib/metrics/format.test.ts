import { describe, expect, it } from "vitest";
import {
	fmtCount,
	fmtDurationMs,
	fmtFraction,
	fmtPercent,
	fmtUsd,
	percentDecimals,
	sampleFloor,
} from "./format";

describe("sample floor — the smallest sample that can resolve the target", () => {
	it("derives from the target, never below 100", () => {
		expect(sampleFloor(0.999)).toBe(1000);
		expect(sampleFloor(0.99)).toBe(100);
		expect(sampleFloor(0.9995)).toBe(2000);
		expect(sampleFloor(0.5)).toBe(100);
		expect(sampleFloor(undefined)).toBe(100);
		expect(sampleFloor(1)).toBe(100);
	});
	it("decimals follow the sample", () => {
		expect(percentDecimals(70)).toBe(1);
		expect(percentDecimals(999)).toBe(1);
		expect(percentDecimals(1000)).toBe(2);
		expect(percentDecimals(99_999)).toBe(2);
		expect(percentDecimals(100_000)).toBe(3);
		expect(percentDecimals(0)).toBe(1);
	});
});

describe("fmtPercent — the 98.571% case", () => {
	it("one failure in 70 against a 99.9% target is neutral, 1 dp, below the floor", () => {
		const f = fmtPercent((69 / 70) * 100, { n: 70, target: 0.999 });
		expect(f.text).toBe("98.6%");
		expect(f.belowFloor).toBe(true);
		expect(f.floor).toBe(1000);
		expect(fmtFraction(1, 70)).toBe("1 of 70");
	});
	it("at or above the floor the tone applies and precision grows", () => {
		const f = fmtPercent(99.9, { n: 1000, target: 0.999 });
		expect(f.text).toBe("99.90%");
		expect(f.belowFloor).toBe(false);
	});
	it("zero traffic is NOT 100% and NOT 0% — it is no sample", () => {
		const f = fmtPercent(100, { n: 0, target: 0.999 });
		expect(f.noSample).toBe(true);
		expect(f.text).toBe("—");
	});
	it("a gateway-computed value with no n keeps 1 dp and no floor claim", () => {
		const f = fmtPercent(12.345, {});
		expect(f.text).toBe("12.3%");
		expect(f.belowFloor).toBe(false);
	});
});

describe("one formatter per kind", () => {
	it("currency: unknown is a dash, zero is $0.00, small is 4 dp", () => {
		expect(fmtUsd(null)).toBe("—");
		expect(fmtUsd(0)).toBe("$0.00");
		expect(fmtUsd(0.0042)).toBe("$0.0042");
		expect(fmtUsd(12.4)).toBe("$12.40");
		expect(fmtUsd(1234.5)).toBe("$1.2K");
	});
	it("duration: zero is the absence of a measurement", () => {
		expect(fmtDurationMs(0)).toBe("—");
		expect(fmtDurationMs(null)).toBe("—");
		expect(fmtDurationMs(245)).toBe("245.0ms");
		expect(fmtDurationMs(1234)).toBe("1.23s");
	});
	it("count groups thousands", () => {
		expect(fmtCount(1284)).toBe("1,284");
		expect(fmtCount(Number.NaN)).toBe("—");
	});
});
