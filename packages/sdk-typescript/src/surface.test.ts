/**
 * Breadth coverage across the public SDK surface.
 *
 * Importing `index.js` pulls in every instrumentation module, so a broken
 * top-level import (renamed export, syntax error) fails this file. Each
 * exported `instrument*` must also be a callable function — catching a
 * dropped or renamed entry point that a per-adapter test would miss.
 */

import { describe, expect, it } from "vitest";
import * as sdk from "./index.js";

const instrumentExports = Object.keys(sdk).filter((k) =>
	k.startsWith("instrument"),
);

describe("SDK public surface", () => {
	it("re-exports a substantial set of instrument* functions", () => {
		expect(instrumentExports.length).toBeGreaterThanOrEqual(18);
	});

	it("exposes init, shutdown, and autoInstrument", () => {
		expect(typeof sdk.init).toBe("function");
		expect(typeof sdk.shutdown).toBe("function");
		expect(typeof sdk.autoInstrument).toBe("function");
	});

	it("autoInstrument() throws with a pointer to the real API (no silent no-op; auto lands in v1.1)", () => {
		// It must NOT silently do nothing — an honest failure beats a fake wire.
		expect(() => sdk.autoInstrument()).toThrow(/v1\.1/);
		expect(() => sdk.autoInstrument()).toThrow(/instrumentAnthropic/);
	});

	it.each(instrumentExports)("%s is a callable function", (name) => {
		expect(typeof (sdk as Record<string, unknown>)[name]).toBe("function");
	});
});
