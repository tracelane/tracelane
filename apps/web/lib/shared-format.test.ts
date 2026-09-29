import { fmtDur } from "@tracelanedev/ui";
import { expect, it } from "vitest";
import { formatDateTimeUtc } from "./format-date";
import { fmtBytes, fmtCount, fmtUsd } from "./metrics/format";
it("formats adaptive durations, including minutes and invalid values", () => {
	expect([0, 131, 1200, 1200000, 90000000, Number.NaN].map(fmtDur)).toEqual([
		"0µs",
		"131µs",
		"1.2ms",
		"1.20s",
		"1.5m",
		"—",
	]);
});
it("formats the same byte budget without exposing transport units", () => {
	expect(`${fmtBytes(131)} of ${fmtBytes(262144)}`).toBe("0.1 KiB of 256 KiB");
	expect(fmtBytes(3 * 1024 * 1024)).toBe("3 MiB");
	expect(fmtBytes(undefined)).toBe("—");
});
it("uses deterministic grouped counts, money and UTC dates", () => {
	expect(fmtCount(30806)).toBe("30,806");
	expect(fmtCount("18446744073709551615")).toBe("18,446,744,073,709,551,615");
	expect(fmtUsd(0.031234)).toBe("$0.0312");
	expect(fmtUsd(12.12345)).toBe("$12.12");
	expect(formatDateTimeUtc("2026-09-28 23:05:00")).toBe(
		"Sep 28, 2026 · 23:05 UTC",
	);
});

it("promotes duration units only when their displayed precision reaches the boundary", () => {
	expect(
		[
			999.4, 999.5, 999_949, 999_950, 999_999.5, 59_950_000, 59_995_000,
			3_599_500_000,
		].map(fmtDur),
	).toEqual([
		"999µs",
		"1.0ms",
		"999.9ms",
		"1.00s",
		"1.00s",
		"59.95s",
		"1.0m",
		"60.0m",
	]);
});
