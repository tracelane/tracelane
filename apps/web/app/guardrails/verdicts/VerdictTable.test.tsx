import type { GuardrailVerdict } from "@/lib/guardrails";
// @vitest-environment jsdom
/**
 * P1 fix: "A blocked request is stopped pre-flight… there is no trace to
 * open" used to render for EVERY expanded row, including `allow`/`warn`/
 * `redact` decisions that DO reach the model and DO produce a span — a false
 * claim for every non-block row. It must render only for `decision === "block"`.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { VerdictTable } from "./VerdictTable";

afterEach(cleanup);

function verdict(overrides: Partial<GuardrailVerdict>): GuardrailVerdict {
	return {
		correlation_id: "corr-1",
		side: "request",
		decision: "block",
		event_time: "2026-09-27 10:00:00.000000",
		total_latency_micros: 1200,
		rails: JSON.stringify([
			{ rail: "r2_secrets", outcome: "block", reason_code: "SECRET_DETECTED" },
		]),
		fail_open_rails: [],
		...overrides,
	};
}

function expandFirstRow() {
	// The expandable row is the first `tabIndex={0}` row in the table body.
	const rows = screen.getAllByRole("row");
	const row = rows[1];
	if (!row) throw new Error("expected a second row (the expandable one)");
	fireEvent.click(row);
}

it("shows the pre-flight / no-trace sentence for a block decision", () => {
	render(<VerdictTable verdicts={[verdict({ decision: "block" })]} />);
	expandFirstRow();
	expect(screen.getByText(/stopped pre-flight/)).toBeTruthy();
});

it("does NOT show the block-only sentence for an allow decision", () => {
	render(
		<VerdictTable
			verdicts={[
				verdict({
					decision: "allow",
					rails: JSON.stringify([{ rail: "r7_topic", outcome: "allow" }]),
				}),
			]}
		/>,
	);
	expandFirstRow();
	expect(screen.queryByText(/stopped pre-flight/)).toBeNull();
});

it("does NOT show the block-only sentence for a warn decision", () => {
	render(
		<VerdictTable
			verdicts={[
				verdict({
					decision: "warn",
					rails: JSON.stringify([
						{
							rail: "r3_pinning",
							outcome: "warn",
							reason_code: "TOOL_DEF_DRIFT",
						},
					]),
				}),
			]}
		/>,
	);
	expandFirstRow();
	expect(screen.queryByText(/stopped pre-flight/)).toBeNull();
});
