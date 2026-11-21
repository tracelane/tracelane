// @vitest-environment jsdom
import {
	cleanup,
	fireEvent,
	render,
	screen,
	waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { PolicyTemplates } from "./PolicyTemplates";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
	configurable: true,
	value: function () {
		this.setAttribute("open", "");
	},
});
Object.defineProperty(HTMLDialogElement.prototype, "close", {
	configurable: true,
	value: function () {
		this.removeAttribute("open");
	},
});
const SERVER = "11111111-1111-4111-8111-111111111111";
const servers = [{ id: SERVER, name: "Payments server" }];
const json = (d: unknown, status = 200) =>
	new Response(JSON.stringify(d), {
		status,
		headers: { "content-type": "application/json" },
	});

function fill() {
	fireEvent.change(screen.getByLabelText(/The tool's amount is in/), {
		target: { value: "cents" },
	});
	fireEvent.change(screen.getByLabelText(/Hold payments above/), {
		target: { value: "5000" },
	});
	fireEvent.change(screen.getByLabelText(/Approved beneficiaries/), {
		target: { value: "acme" },
	});
}

it("shows no preview or publish until the limit is entered, then summarizes the policy", () => {
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	expect(
		(
			screen.getByRole("button", {
				name: "Publish policy",
			}) as HTMLButtonElement
		).disabled,
	).toBe(true);
	fill();
	expect(
		screen.getByText(
			/Payments up to \$5,000\.00 to 1 approved beneficiary are allowed/,
		),
	).toBeTruthy();
	expect(
		(
			screen.getByRole("button", {
				name: "Publish policy",
			}) as HTMLButtonElement
		).disabled,
	).toBe(false);
});
it("a non-admin cannot publish and sees why", () => {
	render(<PolicyTemplates servers={servers} policies={[]} canEdit={false} />);
	fill();
	expect(
		(
			screen.getByRole("button", {
				name: "Publish policy",
			}) as HTMLButtonElement
		).disabled,
	).toBe(true);
	expect(screen.getByText(/Only workspace owners and admins/)).toBeTruthy();
});
it("shows field errors in plain words and blocks publishing", () => {
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	fireEvent.change(screen.getByLabelText(/Hold payments above/), {
		target: { value: "-3" },
	});
	expect(screen.getByText("Enter a whole number of 1 or more.")).toBeTruthy();
	expect(
		(
			screen.getByRole("button", {
				name: "Publish policy",
			}) as HTMLButtonElement
		).disabled,
	).toBe(true);
});
it("switching template changes the form", () => {
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	fireEvent.click(screen.getByRole("button", { name: "Customer data" }));
	expect(screen.getByLabelText(/Hold exports above/)).toBeTruthy();
});
it("publishes only after confirmation and shows the gateway's reason on refusal", async () => {
	const fetch = vi.fn().mockResolvedValueOnce(
		json(
			{
				error: "policy_invalid",
				reason: "The gateway did not accept this policy.",
			},
			422,
		),
	);
	vi.stubGlobal("fetch", fetch);
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	fill();
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	expect(fetch).not.toHaveBeenCalled();
	fireEvent.click(screen.getByRole("button", { name: "Publish" }));
	await screen.findAllByText("The gateway did not accept this policy.");
	const sent = JSON.parse(fetch.mock.calls[0]?.[1]?.body);
	expect(sent.server_id).toBe(SERVER);
	expect(sent).not.toHaveProperty("tenant_id");
	expect(sent).not.toHaveProperty("contract");
});
it("success says what was published and that it is recorded", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValueOnce(json({ published: true })),
	);
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	fill();
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	fireEvent.click(screen.getByRole("button", { name: "Publish" }));
	await waitFor(() => screen.getByText(/Published for release_payment/));
});
it("with no tool server it says to register one first", () => {
	render(<PolicyTemplates servers={[]} policies={[]} canEdit />);
	expect(screen.getByText(/Register a tool server first/)).toBeTruthy();
});
it("a republish says it replaces the current version", () => {
	render(
		<PolicyTemplates
			servers={servers}
			policies={[
				{
					tool_ref: "22222222-2222-4222-8222-222222222222",
					server_id: SERVER,
					tool_name: "release_payment",
					contract_version: 1,
					policy_version: 4,
				},
			]}
			canEdit
		/>,
	);
	fill();
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	expect(screen.getByText(/replaces version 4/)).toBeTruthy();
});
it("visible text carries no internal ids", () => {
	const { container } = render(
		<PolicyTemplates servers={servers} policies={[]} canEdit />,
	);
	expect(container.textContent).not.toMatch(/\b(ACT|SRE|ADR)-\d+|tenant|org_/i);
});

it("shows no raw JSON, ids or minor units in the preview", () => {
	const { container } = render(
		<PolicyTemplates servers={servers} policies={[]} canEdit />,
	);
	fill();
	expect(container.querySelector("pre")).toBeNull();
	expect(container.textContent).not.toMatch(
		/[0-9a-f]{8}-[0-9a-f]{4}|tool_ref|server_id|allow-small|500000/,
	);
});
it("publishing needs the amount unit, with no default", () => {
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	fireEvent.change(screen.getByLabelText(/Hold payments above/), {
		target: { value: "5000" },
	});
	fireEvent.change(screen.getByLabelText(/Approved beneficiaries/), {
		target: { value: "acme" },
	});
	expect(
		(
			screen.getByRole("button", {
				name: "Publish policy",
			}) as HTMLButtonElement
		).disabled,
	).toBe(true);
	expect(
		screen.getByText(
			"Say whether the tool's amount is in cents or in whole dollars.",
		),
	).toBeTruthy();
});
it("the confirmation states the limit in dollars and in the amount field", () => {
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	fill();
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	expect(
		screen.getByText(
			/Payments above \$5,000\.00 \(500000 in the amount field\) need approval\./,
		),
	).toBeTruthy();
});
it("the whole-dollar choice shows the dollar figure in the amount field", () => {
	render(<PolicyTemplates servers={servers} policies={[]} canEdit />);
	fill();
	fireEvent.change(screen.getByLabelText(/The tool's amount is in/), {
		target: { value: "whole_dollars" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Publish policy" }));
	expect(screen.getByText(/\(5000 in the amount field\)/)).toBeTruthy();
});
