import { ApiError } from "@/lib/api-fetch";
/**
 * Item 11 — react-query's default `retry: 2` retried a 403/404 exactly like
 * a transient fault, costing ~5s of skeleton on every entitlement/not-found
 * response before the SAME answer rendered. Retry only a real fault: a 5xx
 * `ApiError`, or a non-`ApiError` (a network failure — `apiFetch` never even
 * got a status).
 */
import { describe, expect, it } from "vitest";
import { shouldRetry } from "./providers";

describe("shouldRetry — only a fault, never a client error", () => {
	it("never retries a 403", () => {
		expect(shouldRetry(0, new ApiError(403, "forbidden"))).toBe(false);
	});

	it("never retries a 404", () => {
		expect(shouldRetry(0, new ApiError(404, "not found"))).toBe(false);
	});

	it("retries a 500, up to the failure-count ceiling", () => {
		expect(shouldRetry(0, new ApiError(500, "boom"))).toBe(true);
		expect(shouldRetry(1, new ApiError(500, "boom"))).toBe(true);
		expect(shouldRetry(2, new ApiError(500, "boom"))).toBe(false);
	});

	it("retries a 503", () => {
		expect(shouldRetry(0, new ApiError(503, "unavailable"))).toBe(true);
	});

	it("retries a plain network error (no ApiError / no status at all)", () => {
		expect(shouldRetry(0, new TypeError("Failed to fetch"))).toBe(true);
		expect(shouldRetry(2, new TypeError("Failed to fetch"))).toBe(false);
	});
});
