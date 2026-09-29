"use client";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { Button } from "./Button";
export interface ObjectAction {
	label: string;
	onSelect: () => void;
	disabled?: boolean;
	reason?: string;
	danger?: boolean;
}
/** The same actions are available from the button and the object's context menu. */
export function ObjectActions({
	label = "Actions",
	actions,
	children,
}: { label?: string; actions: ObjectAction[]; children?: ReactNode }) {
	const [open, setOpen] = useState(false);
	const root = useRef<HTMLDivElement>(null);
	const menu = useRef<HTMLDivElement>(null);
	const [position, setPosition] = useState({ top: 0, left: 0 });
	function show() {
		const rect = trigger.current?.getBoundingClientRect();
		if (rect)
			setPosition({
				top: Math.max(8, Math.min(rect.bottom + 4, window.innerHeight - 240)),
				left: Math.max(8, Math.min(rect.right - 256, window.innerWidth - 264)),
			});
		setOpen(true);
	}
	const trigger = useRef<HTMLButtonElement>(null);
	useEffect(() => {
		if (!open) return;
		menu.current?.showPopover?.();
		menu.current
			?.querySelector<HTMLButtonElement>('[role="menuitem"]:not(:disabled)')
			?.focus();
		const outside = (e: PointerEvent) => {
			if (
				!root.current?.contains(e.target as Node) &&
				!menu.current?.contains(e.target as Node)
			)
				setOpen(false);
		};
		const moved = (event: Event) => {
			if (event.target instanceof Node && menu.current?.contains(event.target))
				return;
			const rect = trigger.current?.getBoundingClientRect();
			if (rect)
				setPosition({
					top: Math.max(8, Math.min(rect.bottom + 4, window.innerHeight - 240)),
					left: Math.max(
						8,
						Math.min(rect.right - 256, window.innerWidth - 264),
					),
				});
		};
		document.addEventListener("pointerdown", outside);
		window.addEventListener("scroll", moved, true);
		window.addEventListener("resize", moved);
		return () => {
			document.removeEventListener("pointerdown", outside);
			window.removeEventListener("scroll", moved, true);
			window.removeEventListener("resize", moved);
		};
	}, [open]);
	function close() {
		setOpen(false);
		trigger.current?.focus();
	}
	return (
		<div
			ref={root}
			className="relative"
			onContextMenu={(e) => {
				e.preventDefault();
				e.stopPropagation();
				show();
			}}
		>
			{children}
			<Button
				ref={trigger}
				variant="ghost"
				aria-label={label}
				aria-haspopup="menu"
				aria-expanded={open}
				onClick={(e) => {
					e.stopPropagation();
					if (open) close();
					else show();
				}}
			>
				•••<span className="sr-only">{label}</span>
			</Button>
			{open && (
				<div
					ref={menu}
					popover="manual"
					role="menu"
					style={{ ...position, bottom: "auto", right: "auto" }}
					aria-label={label}
					className="fixed m-0 z-50 w-64 max-h-60 overflow-y-auto rounded-control border border-line bg-surface p-1 shadow-overlay"
					onKeyDown={(e) => {
						if (e.key === "Escape") {
							e.preventDefault();
							close();
						}
						if (e.key === "Tab") {
							e.preventDefault();
							close();
						}
						if (["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) {
							e.preventDefault();
							const items = Array.from(
								e.currentTarget.querySelectorAll<HTMLButtonElement>(
									"button:not(:disabled)",
								),
							);
							const index = items.indexOf(
								document.activeElement as HTMLButtonElement,
							);
							items[
								e.key === "Home"
									? 0
									: e.key === "End"
										? items.length - 1
										: (index +
												(e.key === "ArrowDown" ? 1 : -1) +
												items.length) %
											items.length
							]?.focus();
						}
					}}
				>
					{actions.map((a) => (
						<button
							key={a.label}
							type="button"
							role="menuitem"
							disabled={a.disabled}
							title={a.reason}
							className={`block min-h-9 w-full rounded-control px-3 py-2 text-left text-sm hover:bg-surface-hover disabled:opacity-50 ${a.danger ? "text-danger-ink" : "text-ink"}`}
							onClick={(e) => {
								e.stopPropagation();
								close();
								a.onSelect();
							}}
						>
							{a.label}
							{a.disabled && a.reason && (
								<span className="block text-xs">{a.reason}</span>
							)}
						</button>
					))}
				</div>
			)}
		</div>
	);
}
