"use client";
import { type ReactNode, useEffect, useId, useRef, useState } from "react";
import { Button } from "./Button";
export function Dialog({
	open,
	onClose,
	title,
	children,
	drawer = false,
	busy = false,
}: {
	open: boolean;
	onClose: () => void;
	title: string;
	children: ReactNode;
	drawer?: boolean;
	busy?: boolean;
}) {
	const ref = useRef<HTMLDialogElement>(null);
	const id = useId();
	useEffect(() => {
		const node = ref.current;
		if (!node) return;
		const previous = document.activeElement as HTMLElement | null;
		if (open) {
			if (!node.open) node.showModal();
		} else if (node.open) node.close();
		return () => {
			if (node.open) node.close();
			previous?.focus();
		};
	}, [open]);
	return (
		<dialog
			ref={ref}
			aria-labelledby={id}
			onCancel={(e) => {
				e.preventDefault();
				if (!busy) onClose();
			}}
			className={`fixed max-h-dvh overflow-y-auto border border-line bg-surface p-6 text-ink shadow-overlay backdrop:bg-ink/30 ${drawer ? "inset-y-0 right-0 left-auto m-0 h-dvh w-full max-w-xl" : "m-auto w-full max-w-lg rounded-card"}`}
		>
			<div className="mb-5 flex items-start justify-between gap-4">
				<h2 id={id} className="text-lg font-semibold">
					{title}
				</h2>
				<Button
					aria-label="Close"
					variant="ghost"
					disabled={busy}
					onClick={onClose}
				>
					×
				</Button>
			</div>
			{open ? children : null}
		</dialog>
	);
}
export function ConfirmDialog({
	open,
	onClose,
	onConfirm,
	title,
	children,
	confirmLabel = "Delete",
	confirmText,
	busy = false,
	error,
}: {
	open: boolean;
	onClose: () => void;
	onConfirm: () => void;
	title: string;
	children: ReactNode;
	confirmLabel?: string;
	confirmText?: string;
	busy?: boolean;
	error?: string | null;
}) {
	const [typed, setTyped] = useState("");
	useEffect(() => {
		if (open) setTyped("");
	}, [open]);
	return (
		<Dialog open={open} onClose={onClose} title={title} busy={busy}>
			<div className="space-y-4">
				{children}
				{confirmText && (
					<label className="block text-sm">
						Type <strong>{confirmText}</strong> to confirm
						<input
							aria-label="Confirmation name"
							className="mt-2 block w-full rounded-control border border-line bg-surface p-2"
							value={typed}
							onChange={(e) => setTyped(e.target.value)}
						/>
					</label>
				)}
				{error && (
					<p role="alert" className="text-danger-ink">
						{error}
					</p>
				)}
				<div className="flex justify-end gap-2">
					<Button disabled={busy} onClick={onClose}>
						Cancel
					</Button>
					<Button
						variant="danger"
						disabled={busy || (!!confirmText && typed !== confirmText)}
						onClick={onConfirm}
					>
						{busy ? "Working…" : confirmLabel}
					</Button>
				</div>
			</div>
		</Dialog>
	);
}
/** Framework-neutral URL state; native history integrates with the app router. */
export function usePeek(parameter = "peek") {
	const [value, setValue] = useState<string | null>(null);
	useEffect(() => {
		const read = () =>
			setValue(new URL(window.location.href).searchParams.get(parameter));
		read();
		window.addEventListener("popstate", read);
		window.addEventListener("peekchange", read);
		return () => {
			window.removeEventListener("popstate", read);
			window.removeEventListener("peekchange", read);
		};
	}, [parameter]);
	function change(next: string | null) {
		const url = new URL(window.location.href);
		const opening = !!next && !url.searchParams.has(parameter);
		if (next) url.searchParams.set(parameter, next);
		else url.searchParams.delete(parameter);
		if (opening) window.history.pushState(null, "", url);
		else window.history.replaceState(null, "", url);
		setValue(next);
		window.dispatchEvent(new Event("peekchange"));
	}
	return [value, change] as const;
}
export function PeekDrawer({
	title,
	children,
	parameter = "peek",
	value,
}: { title: string; children: ReactNode; parameter?: string; value: string }) {
	const [peek, setPeek] = usePeek(parameter);
	return (
		<Dialog
			drawer
			open={peek === value}
			title={title}
			onClose={() => setPeek(null)}
		>
			{children}
		</Dialog>
	);
}
