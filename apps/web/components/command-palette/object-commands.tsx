"use client";
import { Toast } from "@tracelanedev/ui";
import { useEffect, useRef, useState } from "react";
import type { Command } from "./commands";

type PageCommand = Command & { onSelect?: () => void };
const mounted = new Map<symbol, readonly PageCommand[]>();
/** Registration is scoped to the mounted page and disappears on navigation. No reads. */
export function useObjectCommands(commands: readonly PageCommand[]) {
	const key = useRef(Symbol());
	// Update in place after each committed render so handlers never close over stale data.
	useEffect(() => {
		mounted.set(key.current, commands);
	});
	useEffect(() => {
		const registration = key.current;
		return () => {
			mounted.delete(registration);
		};
	}, []);
}
export function currentObjectCommands(): Command[] {
	return [...mounted.values()].flatMap((commands) =>
		commands.map(({ onSelect, ...command }) => ({
			...command,
			target: !!onSelect,
		})),
	);
}
export function runObjectCommand(id: string) {
	const command = [...mounted.values()]
		.flat()
		.find((command) => command.id === id);
	command?.onSelect?.();
}
/** Navigation supplied by server pages; clipboard handling stays with the page. */
export function ObjectPageCommands({
	commands,
	copyHref,
}: { commands: Command[]; copyHref?: string }) {
	const [notice, setNotice] = useState<string | null>(null);
	useObjectCommands([
		...commands,
		...(copyHref
			? [
					{
						id: "object-copy-link",
						label: "Copy link",
						description: "Current object",
						href: "",
						group: "action" as const,
						onSelect: () => {
							void navigator.clipboard
								.writeText(new URL(copyHref, window.location.origin).href)
								.then(
									() => setNotice("Link copied"),
									() =>
										setNotice("Could not copy. Check clipboard permissions."),
								);
						},
					},
				]
			: []),
	]);
	return <Toast message={notice} onDismiss={() => setNotice(null)} />;
}
