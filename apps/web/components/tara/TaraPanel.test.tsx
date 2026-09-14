// @vitest-environment jsdom
/**
 * Tests for TaraPanel (OBS-40 §7 proof 4, TESTS list).
 *
 * Real DOM rendering (`@testing-library/react` + jsdom) is required here,
 * unlike the rest of this app's component tests
 * (`design-primitives-render.test.tsx`'s `renderToStaticMarkup`): the
 * behaviour under test — "check providers on mount, make no further call
 * when there are none" — lives in a `useEffect`, which an SSR string render
 * never runs at all.
 */

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TaraPanel } from "./TaraPanel";

function mockProviderKeys(keys: Array<{ provider_id: string; last4: string }>) {
	return vi.fn(async (input: RequestInfo | URL) => {
		const url = String(input);
		if (url.includes("/api/settings/provider-keys")) {
			return new Response(JSON.stringify(keys), { status: 200 });
		}
		throw new Error(`unexpected fetch in test: ${url}`);
	});
}

async function openPanel() {
	fireEvent.click(screen.getByRole("button", { name: "Ask Tara" }));
}

beforeEach(() => {
	// jsdom has no SpeechRecognition/speechSynthesis by default — each test
	// sets up what it needs explicitly.
	// biome-ignore lint/suspicious/noExplicitAny: resetting a possibly-absent global for test isolation
	(window as any).SpeechRecognition = undefined;
	// biome-ignore lint/suspicious/noExplicitAny: same as above
	(window as any).webkitSpeechRecognition = undefined;
});

afterEach(() => {
	// No global RTL auto-cleanup is registered for this app's vitest setup
	// (unlike a create-react-app-style project) — without this, three
	// `render()` calls across three tests leave three "Ask Tara" buttons in
	// the same jsdom document and every `getByRole` after the first throws
	// "found multiple elements".
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("no-provider state", () => {
	it("renders the Settings link and never calls /api/tara", async () => {
		const fetchMock = mockProviderKeys([]);
		vi.stubGlobal("fetch", fetchMock);

		render(<TaraPanel />);
		await openPanel();

		await screen.findByText(/Tara needs a connected provider/);
		expect(
			screen.getByRole("link", { name: /add one in Settings/ }),
		).toHaveAttribute("href", "/settings/providers");

		// The only fetch this component may make with zero usable providers is
		// the provider-keys check itself — never the chat endpoint.
		for (const call of fetchMock.mock.calls) {
			expect(String(call[0])).not.toContain("/api/tara");
		}
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
});

describe("mic visibility follows Web Speech API support", () => {
	it("shows the mic button when SpeechRecognition exists", async () => {
		// biome-ignore lint/suspicious/noExplicitAny: minimal test double, not a full SpeechRecognition
		(window as any).SpeechRecognition = function MockSpeechRecognition(
			this: unknown,
		) {
			return this;
		};
		vi.stubGlobal(
			"fetch",
			mockProviderKeys([{ provider_id: "anthropic", last4: "abcd" }]),
		);

		render(<TaraPanel />);
		await openPanel();
		await screen.findByPlaceholderText("type a question…");

		expect(
			await screen.findByRole("button", { name: "Ask by voice" }),
		).toBeInTheDocument();
	});

	it("hides the mic button (behind a tooltip) when neither constructor exists", async () => {
		vi.stubGlobal(
			"fetch",
			mockProviderKeys([{ provider_id: "anthropic", last4: "abcd" }]),
		);

		render(<TaraPanel />);
		await openPanel();
		await screen.findByPlaceholderText("type a question…");

		expect(
			screen.queryByRole("button", { name: "Ask by voice" }),
		).not.toBeInTheDocument();
		// The text input itself is still there — voice being unsupported never
		// blocks the typed path.
		expect(screen.getByPlaceholderText("type a question…")).toBeInTheDocument();
	});
});
