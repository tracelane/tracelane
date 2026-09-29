// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { Button } from "@tracelanedev/ui";
import { afterEach, expect, it, vi } from "vitest";
afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
});
it("treats danger as colour and invokes the caller without native confirmation", () => {
	const action = vi.fn();
	vi.spyOn(window, "confirm").mockReturnValue(false);
	render(
		<Button variant="danger" onClick={action}>
			Revoke link
		</Button>,
	);
	fireEvent.click(screen.getByRole("button"));
	expect(window.confirm).not.toHaveBeenCalled();
	expect(action).toHaveBeenCalledOnce();
});
it("uses the declared control radius", () => {
	render(<Button>Go</Button>);
	expect(screen.getByRole("button").className).toContain("rounded-control");
});
it("bare controls retain caller layout without button chrome or sizing", () => {
	render(
		<Button variant="bare" className="h-6">
			Span
		</Button>,
	);
	const button = screen.getByRole("button");
	expect(button.className).not.toMatch(
		/\b(border|bg-surface|px-4|h-9|inline-flex|gap-2|font-medium)\b/,
	);
	expect(button.className).toContain("focus-visible:outline");
	expect(button.getAttribute("type")).toBe("button");
});
