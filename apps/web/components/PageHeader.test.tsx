import { cleanup, fireEvent, render, screen } from "@testing-library/react";
// @vitest-environment jsdom
// Founder 2026-11-18: less scrolling on a phone — page descriptions sit behind an info button.
import { PageHeader } from "@tracelanedev/ui";
import { afterEach, expect, it } from "vitest";

afterEach(cleanup);

it("phone_info_button_reveals_the_description", () => {
	render(<PageHeader title="Traces" description="Every recorded call." />);
	const info = screen.getByRole("button", { name: "About this page" });
	const desc = screen.getByText("Every recorded call.");
	expect(info.getAttribute("aria-expanded")).toBe("false");
	expect(desc.hasAttribute("data-open")).toBe(false);
	fireEvent.click(info);
	expect(info.getAttribute("aria-controls")).toBe(desc.id);
	expect(desc.hasAttribute("data-open")).toBe(true);
});

it("no_description_means_no_info_button", () => {
	render(<PageHeader title="Traces" />);
	expect(screen.queryByRole("button", { name: "About this page" })).toBeNull();
});

it("a_note_is_always_visible_and_needs_no_button", () => {
	render(
		<PageHeader title="Actions" note="Calls outside Tracelane are not seen." />,
	);
	expect(
		screen.getByText("Calls outside Tracelane are not seen.").className,
	).not.toContain("hidden");
	expect(screen.queryByRole("button", { name: "About this page" })).toBeNull();
});
