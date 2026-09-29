// @vitest-environment jsdom
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
	currentObjectCommands,
	runObjectCommand,
	useObjectCommands,
} from "./object-commands";
afterEach(cleanup);
it("runs the page-owned handler and drops it when its object unmounts", () => {
	const open = vi.fn();
	function Page() {
		useObjectCommands([
			{
				id: "open-case",
				label: "New case",
				href: "",
				group: "action",
				onSelect: open,
			},
		]);
		return null;
	}
	const view = render(<Page />);
	expect(currentObjectCommands()).toEqual([
		{
			id: "open-case",
			label: "New case",
			href: "",
			group: "action",
			target: true,
		},
	]);
	act(() => runObjectCommand("open-case"));
	expect(open).toHaveBeenCalledOnce();
	view.unmount();
	expect(currentObjectCommands()).toEqual([]);
	runObjectCommand("open-case");
	expect(open).toHaveBeenCalledOnce();
});
it("keeps registrations and order on rerender while updating the handler", () => {
	const before = vi.fn();
	const after = vi.fn();
	function Page({ id, onSelect }: { id: string; onSelect: () => void }) {
		useObjectCommands([{ id, label: id, href: "", group: "action", onSelect }]);
		return null;
	}
	const view = render(
		<>
			<Page id="first" onSelect={before} />
			<Page id="second" onSelect={before} />
		</>,
	);
	const deletion = vi.spyOn(Map.prototype, "delete");
	view.rerender(
		<>
			<Page id="first" onSelect={after} />
			<Page id="second" onSelect={before} />
		</>,
	);
	expect(
		deletion.mock.calls.filter(([key]) => typeof key === "symbol"),
	).toHaveLength(0);
	expect(currentObjectCommands().map((c) => c.id)).toEqual(["first", "second"]);
	act(() => runObjectCommand("first"));
	expect(after).toHaveBeenCalledOnce();
	expect(before).not.toHaveBeenCalled();
	view.unmount();
	expect(currentObjectCommands()).toEqual([]);
});
