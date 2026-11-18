import { readFileSync } from "node:fs";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import {
	InvestigationFocus,
	type InvestigationFocusProps,
} from "./InvestigationFocus";

const baseline: InvestigationFocusProps = {
	windowLabel: "last 24 hours",
	modelErrorCount: 0,
	requestCount: 20,
	modelErrorDataAvailable: true,
	modelErrorsHref: "/traces?status=error&range=24h",
	signatureDataAvailable: true,
};

it("surfaces only the actual recorded failures and matching signature", () => {
	const html = renderToStaticMarkup(
		h(InvestigationFocus, {
			...baseline,
			modelErrorCount: 7,
			topSignature: {
				id: "AFT-TEST-001",
				hits: 3,
				href: "/traces?signature_id=AFT-TEST-001",
			},
		}),
	);
	expect(html).toContain("7 recorded");
	expect(html).toContain("Failed model calls");
	expect(html).toContain("View traces with errors →");
	expect(html).toContain("AFT-TEST-001");
	expect(html).toContain("3 matches");
	expect(html).toContain("Investigate recorded signals");
	expect(html).toContain("status=error");
});

it("never calls unavailable data zero, and never infers task success", () => {
	const html = renderToStaticMarkup(
		h(InvestigationFocus, {
			...baseline,
			modelErrorDataAvailable: false,
			signatureDataAvailable: false,
		}),
	);
	expect(html).toContain("Unavailable");
	expect(html).not.toContain("0 recorded");
	expect(html).toContain("HTTP success alone does not prove");
});

it("a zero model-error window is not described as successful tasks", () => {
	const html = renderToStaticMarkup(h(InvestigationFocus, baseline));
	expect(html).toContain("0 recorded");
	expect(html).toContain("task outcomes may still fail");
	expect(html).not.toContain("All agents healthy");
});

it("distinguishes no model calls from zero errors", () => {
	const html = renderToStaticMarkup(
		h(InvestigationFocus, { ...baseline, requestCount: 0 }),
	);
	expect(html).toContain("No model calls recorded in this window.");
	expect(html).not.toContain("0 recorded");
});

it("passes only confirmed dashboard model counts to the focus card", () => {
	const page = readFileSync(
		new URL("../../app/dashboard/page.tsx", import.meta.url),
		"utf8",
	);
	const call = page.match(/<InvestigationFocus\b[\s\S]*?\/>/)?.[0];
	expect(call).toContain("requestCount={totalRequests}");
	expect(call).toContain("modelErrorCount={totalErrors}");
	expect(call).toContain("modelErrorDataAvailable={!dash && !usingFallback}");
});
