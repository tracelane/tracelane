import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { CanaryPanel } from "./CanaryPanel";
const initial = {
	canary_id: "split",
	stable_version_id: "stable",
	candidate_version_id: "candidate",
	candidate_percent: 17.25,
};
it("shows the saved reference percentage, identity requirement and workspace cache cost", () => {
	const html = renderToStaticMarkup(
		<CanaryPanel
			promptName="assistant"
			candidateVersionId="candidate"
			initial={initial}
			readStatus={200}
		/>,
	);
	expect(html).toContain("17.25% candidate");
	expect(html).toContain("82.75% stable");
	expect(html).toContain("percentage of prompt resolutions");
	expect(html).toContain("Workspace response caching is suspended");
	expect(html).toContain("Stop canary");
	expect(html).not.toContain("traffic");
	expect(html).not.toContain("min_requests");
});
it.each([
	[401, "Sign in to continue"],
	[403, "Access denied"],
	[503, "Couldn&#x27;t load canary configuration"],
])("distinguishes failed read %i", (status, message) => {
	const html = renderToStaticMarkup(
		<CanaryPanel
			promptName="assistant"
			candidateVersionId=""
			initial={null}
			readStatus={status as number}
		/>,
	);
	expect(html).toContain(message);
	expect(html).not.toContain("No active canary");
	expect(html).not.toContain("Start canary");
});
it("requires an explicit percentage instead of inventing a default", () => {
	const html = renderToStaticMarkup(
		<CanaryPanel
			promptName="assistant"
			candidateVersionId="candidate"
			initial={null}
			readStatus={200}
		/>,
	);
	expect(html).toContain('type="number"');
	expect(html).toContain('value=""');
	expect(html).toContain("No active canary");
});
