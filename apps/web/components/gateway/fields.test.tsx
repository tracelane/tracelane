// @vitest-environment jsdom
// Founder 2026-11-18: long panel descriptions go behind an info button, so Gateway settings
// pages scroll less. A danger panel (Emergency) keeps its warning in view.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { Panel } from "./fields";

afterEach(cleanup);

it("panel_description_is_behind_an_info_button_until_opened", () => {
	render(
		<Panel
			id="p"
			title="Guardrail integrations"
			description="Long explanation text."
		>
			<p>body</p>
		</Panel>,
	);
	const info = screen.getByRole("button", {
		name: "About Guardrail integrations",
	});
	expect(info.getAttribute("aria-expanded")).toBe("false");
	expect(screen.queryByText("Long explanation text.")).toBeNull();
	fireEvent.click(info);
	expect(info.getAttribute("aria-expanded")).toBe("true");
	expect(screen.getByText("Long explanation text.")).toBeTruthy();
	expect(screen.getByText("body")).toBeTruthy();
});

it("danger_panel_keeps_its_description_visible", () => {
	render(
		<Panel
			id="e"
			title="Emergency"
			tone="danger"
			description="Stops all traffic."
		>
			<p>body</p>
		</Panel>,
	);
	expect(screen.getByText("Stops all traffic.")).toBeTruthy();
	expect(screen.queryByRole("button", { name: "About Emergency" })).toBeNull();
});

it("panel_without_description_has_no_info_button", () => {
	render(
		<Panel title="Plain">
			<p>body</p>
		</Panel>,
	);
	expect(screen.queryByRole("button")).toBeNull();
});

it("a_status_note_stays_visible", () => {
	render(
		<Panel title="Add an integration" note="Limit reached.">
			<p>body</p>
		</Panel>,
	);
	expect(screen.getByText("Limit reached.")).toBeTruthy();
});

it("info_button_controls_the_note_only_while_open", () => {
	render(
		<Panel title="T" description="D.">
			<p>b</p>
		</Panel>,
	);
	const info = screen.getByRole("button", { name: "About T" });
	expect(info.getAttribute("aria-controls")).toBeNull();
	fireEvent.click(info);
	const id = info.getAttribute("aria-controls");
	expect(id && document.getElementById(id)?.textContent).toBe("D.");
});
