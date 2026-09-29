import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { PromotionPanel } from "./PromotionPanel";

it("explains candidate-bound evaluation and an explicit optional override", () => {
	const html = renderToStaticMarkup(
		<PromotionPanel promptName="assistant" candidateVersionId="candidate" />,
	);
	expect(html).toContain("passing evaluation for this candidate version");
	expect(html).toContain("explicit override reason");
	expect(html).not.toContain("on the roadmap");
	expect(html).not.toContain("once it ships");
	expect(html).not.toContain("Leave blank today");
	expect(html).not.toContain("override reason is required");
});
