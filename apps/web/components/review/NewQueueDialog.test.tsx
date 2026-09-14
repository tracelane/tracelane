// @vitest-environment jsdom
/**
 * `EVL-29` — component tests for the "New queue" dialog.
 *
 * jsdom 25 does not implement `HTMLDialogElement.showModal()` at all (no
 * generated method on the prototype), so `Modal`'s mount effect
 * (`apps/web/components/Modal.tsx`) throws without a polyfill. The polyfill
 * below only supplies the missing native behaviour jsdom lacks — it changes
 * nothing about how `NewQueueDialog` itself behaves.
 */

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

if (
	typeof HTMLDialogElement !== "undefined" &&
	// biome-ignore lint/suspicious/noExplicitAny: polyfilling a missing jsdom API
	!(HTMLDialogElement.prototype as any).showModal
) {
	// biome-ignore lint/suspicious/noExplicitAny: polyfilling a missing jsdom API
	(HTMLDialogElement.prototype as any).showModal = function (
		this: HTMLDialogElement,
	) {
		this.setAttribute("open", "");
	};
	// biome-ignore lint/suspicious/noExplicitAny: polyfilling a missing jsdom API
	(HTMLDialogElement.prototype as any).close = function (
		this: HTMLDialogElement,
	) {
		this.removeAttribute("open");
		this.dispatchEvent(new Event("close"));
	};
}

const h = vi.hoisted(() => ({ refresh: vi.fn() }));
vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh: h.refresh }),
}));

import { NewQueueDialog } from "./NewQueueDialog";

const DATASETS = [
	{ dataset_id: "ds-1", name: "golden-support-set" },
	{ dataset_id: "ds-2", name: "regression-set" },
];

afterEach(cleanup);
beforeEach(() => {
	h.refresh.mockClear();
	vi.unstubAllGlobals();
});

/** Open the dialog and fill the smallest valid form: a name, and a single
 * rubric field whose key auto-becomes the reference (required + non-boolean
 * by default). */
function openAndFillMinimalForm(name = "My queue") {
	fireEvent.click(screen.getByTestId("nq-trigger"));
	fireEvent.change(screen.getByTestId("nq-name-input"), {
		target: { value: name },
	});
	fireEvent.change(screen.getByLabelText("Rubric field 1 key"), {
		target: { value: "note" },
	});
}

describe("NewQueueDialog — disabled state", () => {
	it("renders disabled with the explicit reason when the caller supplies one", () => {
		render(
			<NewQueueDialog
				datasets={DATASETS}
				disabledReason="A queue writes into a dataset — create one first."
			/>,
		);
		expect(screen.getByTestId("nq-trigger")).toBeDisabled();
		expect(screen.getByTestId("nq-disabled-reason")).toHaveTextContent(
			"A queue writes into a dataset — create one first.",
		);
		// The disabled trigger never opens — no form should be reachable.
		fireEvent.click(screen.getByTestId("nq-trigger"));
		expect(screen.queryByTestId("nq-submit")).not.toBeInTheDocument();
	});

	it("refuses to open even without an explicit reason when there are no datasets (R222 defence in depth)", () => {
		render(<NewQueueDialog datasets={[]} disabledReason={null} />);
		expect(screen.getByTestId("nq-trigger")).toBeDisabled();
		expect(screen.getByTestId("nq-disabled-reason")).toHaveTextContent(
			"Create a dataset first.",
		);
	});

	it("is enabled when datasets exist and no reason was given", () => {
		render(<NewQueueDialog datasets={DATASETS} disabledReason={null} />);
		expect(screen.getByTestId("nq-trigger")).toBeEnabled();
	});
});

describe("NewQueueDialog — submit outcomes", () => {
	it("calls POST /api/annotation-queues exactly once and closes on success", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			status: 201,
			ok: true,
			json: async () => ({ id: "q-new" }),
		});
		vi.stubGlobal("fetch", fetchMock);

		render(<NewQueueDialog datasets={DATASETS} disabledReason={null} />);
		openAndFillMinimalForm("Low-score support replies");
		fireEvent.click(screen.getByTestId("nq-submit"));

		await screen.findByTestId("nq-trigger"); // dialog closed, trigger is back
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("/api/annotation-queues");
		expect(init.method).toBe("POST");
		const body = JSON.parse(init.body as string);
		expect(body.name).toBe("Low-score support replies");
		expect(body.default_dataset_id).toBe("ds-1");
		expect(h.refresh).toHaveBeenCalledTimes(1);
	});

	it("renders a server field error next to the offending field (queue_name_taken -> name)", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			status: 409,
			ok: false,
			json: async () => ({
				error: "queue_name_taken",
				field: "name",
				message: "A queue with that name already exists in this workspace.",
			}),
		});
		vi.stubGlobal("fetch", fetchMock);

		render(<NewQueueDialog datasets={DATASETS} disabledReason={null} />);
		openAndFillMinimalForm("Duplicate name");
		fireEvent.click(screen.getByTestId("nq-submit"));

		const err = await screen.findByTestId("nq-name-error");
		expect(err).toHaveTextContent(
			"A queue with that name already exists in this workspace.",
		);
		expect(screen.getByTestId("nq-name-input")).toHaveAttribute(
			"aria-invalid",
			"true",
		);
		// A field-scoped error does not ALSO duplicate into the generic banner.
		expect(screen.queryByTestId("nq-banner-error")).not.toBeInTheDocument();
		// The dialog stays open — the typed name is not lost.
		expect(screen.getByTestId("nq-submit")).toBeInTheDocument();
	});

	it("renders the cap error (queue_limit_reached) as a non-retryable banner", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			status: 409,
			ok: false,
			json: async () => ({
				error: "queue_limit_reached",
				message:
					"You have 50 active queues (the maximum). Archive one to create another.",
			}),
		});
		vi.stubGlobal("fetch", fetchMock);

		render(<NewQueueDialog datasets={DATASETS} disabledReason={null} />);
		openAndFillMinimalForm();
		fireEvent.click(screen.getByTestId("nq-submit"));

		const banner = await screen.findByTestId("nq-banner-error");
		expect(banner).toHaveTextContent(
			"You have 50 active queues (the maximum). Archive one to create another.",
		);
		expect(
			screen.queryByRole("button", { name: "Retry" }),
		).not.toBeInTheDocument();
	});

	it("a 5xx collapses to the generic 'could not reach the gateway' message, WITH a retry", async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			status: 502,
			ok: false,
			json: async () => ({
				error: "unavailable",
				reason: "gateway_unreachable",
			}),
		});
		vi.stubGlobal("fetch", fetchMock);

		render(<NewQueueDialog datasets={DATASETS} disabledReason={null} />);
		openAndFillMinimalForm();
		fireEvent.click(screen.getByTestId("nq-submit"));

		const banner = await screen.findByTestId("nq-banner-error");
		expect(banner).toHaveTextContent(
			"Could not reach the gateway — your queue was not created.",
		);
		expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
	});

	it("never double-submits: the button disables while the request is in flight", async () => {
		let resolveFetch: (v: unknown) => void = () => {};
		const fetchMock = vi.fn(
			() =>
				new Promise((resolve) => {
					resolveFetch = resolve;
				}),
		);
		vi.stubGlobal("fetch", fetchMock);

		render(<NewQueueDialog datasets={DATASETS} disabledReason={null} />);
		openAndFillMinimalForm();
		fireEvent.click(screen.getByTestId("nq-submit"));

		expect(screen.getByTestId("nq-submit")).toBeDisabled();
		fireEvent.click(screen.getByTestId("nq-submit")); // no-op while disabled
		expect(fetchMock).toHaveBeenCalledTimes(1);

		resolveFetch({ status: 201, ok: true, json: async () => ({}) });
		await screen.findByTestId("nq-trigger");
	});
});
