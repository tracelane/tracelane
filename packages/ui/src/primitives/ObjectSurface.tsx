"use client";
import { type ReactNode, useRef, useState } from "react";
import { Button } from "./Button";
import { Dialog, usePeek } from "./Dialog";
import { type ObjectAction, ObjectActions } from "./ObjectActions";
import { Toast } from "./Toast";
/** A row or card with the same keyboard, context-menu and URL-peek contract. */
export function ObjectSurface({
	as = "tr",
	objectId,
	title,
	href,
	fields,
	children,
	className,
	actions = [],
	links = [],
	controls,
	id,
}: {
	as?: "tr" | "article";
	objectId: string;
	title: string;
	href: string;
	fields: { label: string; value: ReactNode }[];
	children: ReactNode;
	className?: string;
	id?: string;
	actions?: ObjectAction[];
	links?: { label: string; href: string }[];
	controls?: ReactNode;
}) {
	const [peek, setPeek] = usePeek();
	const [notice, setNotice] = useState<string | null>(null);
	const root = useRef<HTMLElement | null>(null);
	const Tag = as;
	const menuLabel = `Actions for ${title}`;
	const verbs: ObjectAction[] = [
		{ label: "Peek", onSelect: () => setPeek(objectId) },
		{ label: "Open full page", onSelect: () => window.location.assign(href) },
		...links.map((link) => ({
			label: link.label,
			onSelect: () => window.location.assign(link.href),
		})),
		...actions,
		{
			label: "Copy link",
			onSelect: () => {
				void navigator.clipboard
					.writeText(new URL(href, window.location.origin).href)
					.then(
						() => setNotice("Link copied"),
						() =>
							setNotice("Could not copy link. Check clipboard permissions."),
					);
			},
		},
	];
	const tools = (
		<>
			<ObjectActions label={menuLabel} actions={verbs} />
			{peek === objectId && (
				<Dialog
					drawer
					open={peek === objectId}
					title={title}
					onClose={() => setPeek(null)}
				>
					<dl className="space-y-4">
						{fields.map((field) => (
							<div key={field.label}>
								<dt className="text-xs text-ink-2">{field.label}</dt>
								<dd className="mt-1 break-words text-sm">
									{field.value ?? "—"}
								</dd>
							</div>
						))}
					</dl>
					<div className="mt-6 flex flex-wrap gap-2">
						<a className="text-sm underline" href={href}>
							Open full page
						</a>
						{links.map((link) => (
							<a
								key={link.label}
								className="text-sm underline"
								href={link.href}
							>
								{link.label}
							</a>
						))}
						{actions.map((action) => (
							<Button
								key={action.label}
								disabled={action.disabled}
								title={action.reason}
								variant={action.danger ? "danger" : "secondary"}
								onClick={() => {
									setPeek(null);
									action.onSelect();
								}}
							>
								{action.label}
							</Button>
						))}
						{controls}
					</div>
				</Dialog>
			)}
			<Toast message={notice} onDismiss={() => setNotice(null)} />
		</>
	);
	return (
		<Tag
			ref={(node) => {
				root.current = node;
			}}
			id={id}
			tabIndex={0}
			data-object-row={objectId}
			className={className}
			onContextMenu={(event) => {
				if (
					(event.target as HTMLElement).closest(
						"a,button,input,textarea,select,[contenteditable],[role=menu],dialog",
					)
				)
					return;
				event.preventDefault();
				root.current
					?.querySelector<HTMLButtonElement>('[aria-haspopup="menu"]')
					?.click();
			}}
			onKeyDown={(event) => {
				if (event.target !== event.currentTarget) return;
				if (event.key === "Enter") {
					event.preventDefault();
					setPeek(objectId);
				}
				if (["j", "k", "ArrowDown", "ArrowUp"].includes(event.key)) {
					event.preventDefault();
					const rows = Array.from(
						root.current?.parentElement?.querySelectorAll<HTMLElement>(
							":scope > [data-object-row]",
						) ?? [],
					);
					const index = rows.indexOf(event.currentTarget);
					rows[
						Math.max(
							0,
							Math.min(
								rows.length - 1,
								index + (["j", "ArrowDown"].includes(event.key) ? 1 : -1),
							),
						)
					]?.focus();
				}
			}}
		>
			{children}
			{as === "tr" ? (
				<td className="px-3 py-2">{tools}</td>
			) : (
				<div className="mt-3">{tools}</div>
			)}
		</Tag>
	);
}
