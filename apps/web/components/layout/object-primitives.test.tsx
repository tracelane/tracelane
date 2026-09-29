// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { DataTable } from "../../../../packages/ui/src/primitives/DataTable";
afterEach(cleanup);
const rows = [
	{ id: "a", n: 3 },
	{ id: "b", n: 1 },
	{ id: "c", n: 2 },
];
function TableTest() {
	const [selected, setSelected] = useState(new Set<string>());
	return (
		<>
			<output>{selected.size} selected</output>
			<DataTable
				label="Objects"
				rows={rows}
				rowId={(r) => r.id}
				columns={[
					{
						key: "n",
						header: "Number",
						cell: (r) => r.n,
						sortValue: (r) => r.n,
					},
				]}
				selected={selected}
				onSelectionChange={setSelected}
			/>
		</>
	);
}
it("selects a shift range, exposes mixed state, and clears the page", () => {
	render(<TableTest />);
	fireEvent.click(screen.getByLabelText("Select a"));
	fireEvent.click(screen.getByLabelText("Select c"), { shiftKey: true });
	expect(screen.getByText("3 selected")).toBeTruthy();
	fireEvent.click(screen.getByLabelText("Select b"));
	expect(
		(screen.getByLabelText("Select all on page") as HTMLInputElement)
			.indeterminate,
	).toBe(true);
	fireEvent.click(screen.getByLabelText("Select all on page"));
	fireEvent.click(screen.getByLabelText("Select all on page"));
	expect(screen.getByText("0 selected")).toBeTruthy();
});
it("sorts numbers and navigates rows using j/k; paging is explicit", () => {
	const activate = vi.fn();
	const next = vi.fn();
	render(
		<DataTable
			label="Objects"
			rows={rows}
			rowId={(r) => r.id}
			onActivate={activate}
			columns={[
				{ key: "n", header: "Number", cell: (r) => r.n, sortValue: (r) => r.n },
			]}
			page={{
				hasNext: true,
				hasPrevious: false,
				onNext: next,
				onPrevious: vi.fn(),
			}}
		/>,
	);
	fireEvent.click(screen.getByRole("button", { name: /Number/ }));
	const bodyRows = screen.getAllByRole("row").slice(1);
	if (!bodyRows[0] || !bodyRows[1]) throw new Error("Expected two data rows");
	expect(bodyRows[0]?.textContent).toBe("1");
	bodyRows[0]?.focus();
	fireEvent.keyDown(bodyRows[0], { key: "j" });
	expect(document.activeElement).toBe(bodyRows[1]);
	fireEvent.keyDown(bodyRows[1], { key: "Enter" });
	expect(activate).toHaveBeenCalledWith(rows[2]);
	fireEvent.click(screen.getByRole("button", { name: "Next page" }));
	expect(next).toHaveBeenCalledOnce();
	expect(
		(screen.getByRole("button", { name: "Previous page" }) as HTMLButtonElement)
			.disabled,
	).toBe(true);
});

import { waitFor } from "@testing-library/react";
import {
	ConfirmDialog,
	Dialog,
	usePeek,
} from "../../../../packages/ui/src/primitives/Dialog";
import { InlineEdit } from "../../../../packages/ui/src/primitives/InlineEdit";
import { ObjectActions } from "../../../../packages/ui/src/primitives/ObjectActions";
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
it("opens the same menu on right-click, skips disabled actions and restores focus on Escape", () => {
	const action = vi.fn();
	render(
		<ObjectActions
			actions={[
				{ label: "Delete", onSelect: action },
				{ label: "Locked", onSelect: action, disabled: true },
			]}
		>
			<span>Object</span>
		</ObjectActions>,
	);
	fireEvent.contextMenu(screen.getByText("Object"));
	expect(document.activeElement).toBe(
		screen.getByRole("menuitem", { name: "Delete" }),
	);
	fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
	expect(screen.queryByRole("menu")).toBeNull();
	expect(document.activeElement).toBe(
		screen.getByRole("button", { name: "Actions" }),
	);
	expect(action).not.toHaveBeenCalled();
});
it("requires the exact name before destructive confirmation", () => {
	const confirm = vi.fn();
	render(
		<ConfirmDialog
			open
			onClose={vi.fn()}
			onConfirm={confirm}
			title="Delete dataset"
			confirmText="Golden"
		>
			<p>Permanent</p>
		</ConfirmDialog>,
	);
	fireEvent.change(screen.getByLabelText("Confirmation name"), {
		target: { value: "golden" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Delete" }));
	expect(confirm).not.toHaveBeenCalled();
	fireEvent.change(screen.getByLabelText("Confirmation name"), {
		target: { value: "Golden" },
	});
	fireEvent.click(screen.getByRole("button", { name: "Delete" }));
	expect(confirm).toHaveBeenCalledOnce();
});
it("keeps other query parameters and follows browser navigation for peeks", () => {
	window.history.replaceState(null, "", "/?filter=bad&peek=a");
	function Peek() {
		const [value, change] = usePeek();
		return (
			<>
				<button type="button" onClick={() => change("b")}>
					Peek B
				</button>
				<Dialog
					drawer
					open={!!value}
					title={value ?? "Closed"}
					onClose={() => change(null)}
				>
					Details
				</Dialog>
			</>
		);
	}
	render(<Peek />);
	expect(
		screen.getByRole("dialog").getAttribute("aria-labelledby"),
	).toBeTruthy();
	fireEvent.click(screen.getByText("Peek B"));
	expect(window.location.search).toBe("?filter=bad&peek=b");
	fireEvent.click(screen.getByRole("button", { name: "Close" }));
	expect(window.location.search).toBe("?filter=bad");
	window.history.replaceState(null, "", "/?filter=bad&peek=a");
	fireEvent.popState(window);
	expect(screen.getByRole("heading", { name: "a" })).toBeTruthy();
});
it("keeps the editor open with its draft when saving fails", async () => {
	const save = vi.fn().mockRejectedValue(new Error("Write refused"));
	render(<InlineEdit label="Metadata" value="{}" onSave={save} />);
	fireEvent.click(screen.getByText("Edit Metadata"));
	fireEvent.change(screen.getByLabelText("Metadata"), {
		target: { value: '{"tag":"bad"}' },
	});
	fireEvent.click(screen.getByText("Save"));
	await waitFor(() =>
		expect(screen.getByRole("alert").textContent).toBe("Write refused"),
	);
	expect((screen.getByLabelText("Metadata") as HTMLInputElement).value).toBe(
		'{"tag":"bad"}',
	);
});
it("returns focus to the menu trigger on Tab", () => {
	render(<ObjectActions actions={[{ label: "Open", onSelect: vi.fn() }]} />);
	const trigger = screen.getByRole("button", { name: "Actions" });
	fireEvent.click(trigger);
	fireEvent.keyDown(screen.getByRole("menu"), { key: "Tab" });
	expect(screen.queryByRole("menu")).toBeNull();
	expect(document.activeElement).toBe(trigger);
});
it("only adds a history entry when opening from no peek", () => {
	window.history.replaceState(null, "", "/traces?range=day");
	function HistoryProbe() {
		const [peek, setPeek] = usePeek();
		return (
			<>
				<button type="button" onClick={() => setPeek("a")}>
					Open a
				</button>
				<button type="button" onClick={() => setPeek("b")}>
					Open b
				</button>
				<button type="button" onClick={() => setPeek(null)}>
					Close peek
				</button>
				<span>{peek}</span>
			</>
		);
	}
	render(<HistoryProbe />);
	const initial = window.history.length;
	fireEvent.click(screen.getByText("Open a"));
	expect(window.history.length).toBe(initial + 1);
	fireEvent.click(screen.getByText("Open b"));
	expect(window.history.length).toBe(initial + 1);
	fireEvent.click(screen.getByText("Close peek"));
	expect(window.history.length).toBe(initial + 1);
	expect(window.location.search).toBe("?range=day");
});
