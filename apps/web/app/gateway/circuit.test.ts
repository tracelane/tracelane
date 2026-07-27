/**
 * Tests for the /gateway circuit-breaker presentation helpers (the first tests
 * for the /gateway surface). Locks the state→tone/label mapping the router-health
 * column depends on.
 */

import { describe, expect, it } from "vitest";
import { circuitLabel, circuitTone, circuitUnhealthy } from "./circuit";

describe("circuit breaker presentation", () => {
	it("tones: open=danger, half_open=warn, closed/unknown=ok", () => {
		expect(circuitTone("open")).toBe("danger");
		expect(circuitTone("half_open")).toBe("warn");
		expect(circuitTone("closed")).toBe("ok");
		expect(circuitTone("something-unexpected")).toBe("ok");
	});

	it("labels: open→Open, half_open→Half-open, else→Closed", () => {
		expect(circuitLabel("open")).toBe("Open");
		expect(circuitLabel("half_open")).toBe("Half-open");
		expect(circuitLabel("closed")).toBe("Closed");
		expect(circuitLabel("")).toBe("Closed");
	});

	it("unhealthy iff open or half_open", () => {
		expect(circuitUnhealthy("open")).toBe(true);
		expect(circuitUnhealthy("half_open")).toBe(true);
		expect(circuitUnhealthy("closed")).toBe(false);
	});
});
