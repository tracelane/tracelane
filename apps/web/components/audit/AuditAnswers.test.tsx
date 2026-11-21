// @vitest-environment jsdom
// AUD-40 Part C: the three answers render first; the four mechanism steps are a disclosure.
import { summarizeAudit } from "@/app/audit/answer";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { AuditAnswers } from "./AuditAnswers";

afterEach(cleanup);

const facts = {
	verdict: { state: "verified", rows: 3, anchors: 1 } as const,
	hashChainValid: true,
	platformVerified: false,
	unanchoredTail: 0,
	checkedRows: 3,
	totalRows: 3,
};

it("renders the three questions with plain state words", () => {
	render(<AuditAnswers summary={summarizeAudit(facts)} />);
	const list = screen.getByLabelText("Audit answers");
	expect(within(list).getByText("Unchanged?")).toBeTruthy();
	expect(within(list).getByText("Signed and anchored?")).toBeTruthy();
	expect(within(list).getByText("How much was checked?")).toBeTruthy();
	expect(within(list).getAllByText("Yes")).toHaveLength(3);
});

it("a failed proof shows No in the danger ink, and partial coverage shows Partly", () => {
	render(
		<AuditAnswers
			summary={summarizeAudit({
				...facts,
				verdict: { state: "stripped" },
				checkedRows: 3,
				totalRows: 30,
			})}
		/>,
	);
	const no = screen.getByText("No");
	expect(no.className).toContain("text-danger-ink");
	expect(screen.getByText("Partly")).toBeTruthy();
});

it("unknown answers read 'Not established', never Yes", () => {
	render(
		<AuditAnswers
			summary={summarizeAudit({
				...facts,
				verdict: { state: "unrooted_window" },
			})}
		/>,
	);
	expect(screen.getAllByText("Not established").length).toBeGreaterThanOrEqual(
		2,
	);
	expect(screen.queryAllByText("Yes")).toHaveLength(1);
});
