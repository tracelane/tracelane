// @vitest-environment jsdom
/** The reporter is bounded (dedupe + a per-page cap) and never throws. */
import { beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => vi.resetModules());

describe("reportClientError", () => {
	it("beacons once per distinct message and caps a page at 10 reports", async () => {
		const beacon = vi.fn((_url: string, _body?: BodyInit) => true);
		Object.defineProperty(navigator, "sendBeacon", {
			configurable: true,
			value: beacon,
		});
		const { reportClientError } = await import("./report-error");
		reportClientError(new Error("same"), "window");
		reportClientError(new Error("same"), "window");
		expect(beacon).toHaveBeenCalledTimes(1);
		expect(beacon.mock.calls[0]?.[0]).toBe("/api/client-errors");
		for (let i = 0; i < 30; i++)
			reportClientError(new Error(`e${i}`), "rejection");
		expect(beacon).toHaveBeenCalledTimes(10);
	});

	it("never throws, even when the beacon itself does", async () => {
		Object.defineProperty(navigator, "sendBeacon", {
			configurable: true,
			value: () => {
				throw new Error("boom");
			},
		});
		const { reportClientError } = await import("./report-error");
		expect(() => reportClientError("x", "window")).not.toThrow();
	});
});
