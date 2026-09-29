/**
 * B-521 (CX-22) — the alert-rule copy must match what the checker actually
 * evaluates. `quota_pct` is BILL-01/ADR-076's ingest-% metric, evaluated
 * MONTH-TO-DATE (`crates/gateway/src/alerts/checker.rs:406,561` dispatches it
 * to `quota_pct(tenant_id)`, which never reads `rule.window_minutes`) — but
 * the rules table printed `formatWindow(rule.window_minutes)` for every
 * metric alike, so a customer who set "5 minutes" read "5m" against a rule
 * that is actually evaluated over the calendar month. `METRIC_META.quota_pct`
 * also predates BILL-01's redefinition and still reads "Quota used", when the
 * metric is ingest bytes ÷ `ingest_bytes_included` (§23 — the number itself
 * stays a reference-table read, never a literal here).
 *
 * Pure-function tests only, per `.claude/rules/testing.md` — no DOM, no
 * network, no React Query.
 */

import { describe, expect, it } from "vitest";
import { METRIC_META, windowCellText } from "./AlertsManager";

describe("windowCellText", () => {
	it("prints 'month to date' for quota_pct — never a window figure the checker does not read", () => {
		expect(windowCellText({ metric: "quota_pct", window_minutes: 60 })).toBe(
			"month to date",
		);
	});

	it("prints 'month to date' for quota_pct regardless of the stored window_minutes value", () => {
		expect(
			windowCellText({ metric: "quota_pct", window_minutes: 44_640 }),
		).toBe("month to date");
	});

	it("still formats the real window for every windowed metric, unchanged", () => {
		expect(windowCellText({ metric: "error_rate", window_minutes: 60 })).toBe(
			"1h",
		);
		expect(windowCellText({ metric: "latency_p95", window_minutes: 5 })).toBe(
			"5m",
		);
		expect(windowCellText({ metric: "cost_usd", window_minutes: 1440 })).toBe(
			"1d",
		);
	});
});

describe("METRIC_META.quota_pct", () => {
	it("is labelled by what BILL-01/ADR-076 actually measures — ingest %, never the retired 'Quota used'", () => {
		expect(METRIC_META.quota_pct?.label).not.toBe("Quota used");
		expect(METRIC_META.quota_pct?.label).toContain("Ingest used");
		expect(METRIC_META.quota_pct?.unit).toBe("%");
	});
});
