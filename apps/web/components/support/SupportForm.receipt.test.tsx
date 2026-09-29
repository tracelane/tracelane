import SupportPage from "@/app/support/page";
// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { SupportForm } from "./SupportForm";
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});
it("does not promise an email response before submission", () => {
	render(<SupportPage />);
	expect(screen.queryByText(/follow up by email/i)).toBeNull();
	expect(screen.getByText(/Replies are not guaranteed/)).toBeTruthy();
});
it("acknowledges a saved request and its reference without promising delivery", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ ok: true, ref: "TL-12345678" }), {
				status: 201,
			}),
		),
	);
	render(<SupportForm />);
	fireEvent.change(screen.getByLabelText("Message"), {
		target: { value: "Please inspect this issue" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Send" }));
	expect(await screen.findByText("TL-12345678")).toBeTruthy();
	expect(screen.queryByText(/follow up by email/i)).toBeNull();
	expect(screen.getByText(/saved your question/)).toBeTruthy();
	expect(screen.getByText(/Replies are not guaranteed/)).toBeTruthy();
});
it("does not claim a receipt when saving fails", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn().mockResolvedValue(new Response("", { status: 503 })),
	);
	render(<SupportForm />);
	fireEvent.change(screen.getByLabelText("Message"), {
		target: { value: "Keep this unsaved message" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Send" }));
	expect(
		await screen.findByText("Couldn't send — please try again."),
	).toBeTruthy();
	expect((screen.getByLabelText("Message") as HTMLTextAreaElement).value).toBe(
		"Keep this unsaved message",
	);
	expect(screen.queryByText(/saved your question/)).toBeNull();
});
