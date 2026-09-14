/**
 * OBS-01 proofs #2/#3 as unit tests: a rejected `q` (forced `?q=abc`) renders
 * the gateway's own message, and a zero-row SEARCH reads differently from a
 * zero-row FILTER. Both are pure functions extracted from `page.tsx`
 * specifically so this doesn't need a rendered RSC.
 */

import { describe, expect, it } from "vitest";
import { classifyTraceFetchError, noMatchCopy } from "./empty-state";

describe("classifyTraceFetchError", () => {
	it("classifies a 400 (e.g. `?q=abc` under the 4-char minimum) as rejected, carrying the gateway's own message", () => {
		const failure = classifyTraceFetchError({
			status: 400,
			message: "gateway responded 400",
			body: { error: "search term must be at least 4 characters" },
		});
		expect(failure).toEqual({
			kind: "rejected",
			message: "search term must be at least 4 characters",
		});
	});

	it("falls back to the GatewayError message when the body carries no `error` field", () => {
		const failure = classifyTraceFetchError({
			status: 422,
			message: "gateway responded 422",
			body: null,
		});
		expect(failure).toEqual({
			kind: "rejected",
			message: "gateway responded 422",
		});
	});

	it("classifies a 5xx as unreachable — NOT a validation failure", () => {
		expect(
			classifyTraceFetchError({
				status: 502,
				message: "gateway responded 502",
				body: null,
			}),
		).toEqual({ kind: "unreachable" });
	});

	it("classifies a transport failure (503, our own gatewayGet wrapper) as unreachable", () => {
		expect(
			classifyTraceFetchError({
				status: 503,
				message: "gateway unreachable: fetch failed",
				body: null,
			}),
		).toEqual({ kind: "unreachable" });
	});
});

describe("noMatchCopy — the two empty states differ", () => {
	it("names the search term when a search returned zero rows", () => {
		const copy = noMatchCopy("zzzzzzzz");
		expect(copy.title).toBe("No traces match `zzzzzzzz` in this window");
		expect(copy.title).not.toBe("No traces match these filters");
	});

	it("falls back to the generic filter copy when there is no search term", () => {
		const copy = noMatchCopy(undefined);
		expect(copy.title).toBe("No traces match these filters");
		expect(copy.title).not.toContain("`");
	});

	it("the two states are never the same string", () => {
		const withSearch = noMatchCopy("claude_code");
		const withoutSearch = noMatchCopy(undefined);
		expect(withSearch.title).not.toBe(withoutSearch.title);
		expect(withSearch.description).not.toBe(withoutSearch.description);
	});
});
