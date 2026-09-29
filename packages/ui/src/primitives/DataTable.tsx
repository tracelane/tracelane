"use client";

import { type ReactNode, useRef, useState } from "react";
import { Button } from "./Button";
import { TBody, TD, TH, THead, TR, Table } from "./Table";

export interface DataColumn<T> {
	key: string;
	header: ReactNode;
	cell: (row: T) => ReactNode;
	sortValue?: (row: T) => string | number;
	numeric?: boolean;
}
export interface DataTableProps<T> {
	label: string;
	rows: T[];
	columns: DataColumn<T>[];
	rowId: (row: T) => string;
	selected?: Set<string>;
	onSelectionChange?: (ids: Set<string>) => void;
	onActivate?: (row: T) => void;
	page?: {
		hasNext: boolean;
		hasPrevious: boolean;
		onNext: () => void;
		onPrevious: () => void;
	};
	disabled?: boolean;
}
export function DataTable<T>({
	label,
	rows,
	columns,
	rowId,
	selected,
	onSelectionChange,
	onActivate,
	page,
	disabled,
}: DataTableProps<T>) {
	const [sort, setSort] = useState<{ key: string; desc: boolean } | null>(null);
	const anchor = useRef<string | null>(null);
	const column = columns.find((c) => c.key === sort?.key);
	const shown = column?.sortValue
		? [...rows].sort((a, b) => {
				const av = column.sortValue?.(a) ?? "";
				const bv = column.sortValue?.(b) ?? "";
				return (
					(typeof av === "number" && typeof bv === "number"
						? av - bv
						: String(av).localeCompare(String(bv))) * (sort?.desc ? -1 : 1)
				);
			})
		: rows;
	const all = shown.length > 0 && shown.every((r) => selected?.has(rowId(r)));
	const some = shown.some((r) => selected?.has(rowId(r)));
	function toggle(id: string, shift: boolean) {
		if (disabled) return;
		const next = new Set(selected);
		const start = shown.findIndex((r) => rowId(r) === anchor.current);
		const end = shown.findIndex((r) => rowId(r) === id);
		if (shift && start >= 0)
			for (const row of shown.slice(
				Math.min(start, end),
				Math.max(start, end) + 1,
			))
				next.add(rowId(row));
		else if (next.has(id)) next.delete(id);
		else next.add(id);
		anchor.current = id;
		onSelectionChange?.(next);
	}
	return (
		<div className="min-w-0 rounded-card border border-line bg-surface">
			<Table aria-label={label}>
				<THead>
					<TR>
						{onSelectionChange && (
							<TH>
								<input
									type="checkbox"
									aria-label="Select all on page"
									disabled={disabled || !shown.length}
									checked={all}
									ref={(node) => {
										if (node) node.indeterminate = some && !all;
									}}
									onChange={() => {
										const next = new Set(selected);
										for (const row of shown) {
											if (all) next.delete(rowId(row));
											else next.add(rowId(row));
										}
										onSelectionChange(next);
									}}
									className="size-4"
								/>
							</TH>
						)}
						{columns.map((c) => (
							<TH
								key={c.key}
								numeric={c.numeric}
								aria-sort={
									sort?.key === c.key
										? sort.desc
											? "descending"
											: "ascending"
										: undefined
								}
							>
								{c.sortValue ? (
									<Button
										variant="ghost"
										size="sm"
										onClick={() =>
											setSort({
												key: c.key,
												desc: sort?.key === c.key && !sort.desc,
											})
										}
									>
										{c.header}
										{sort?.key === c.key ? (sort.desc ? " ↓" : " ↑") : " ↕"}
									</Button>
								) : (
									c.header
								)}
							</TH>
						))}
					</TR>
				</THead>
				<TBody>
					{shown.map((row) => (
						<TR
							key={rowId(row)}
							tabIndex={0}
							aria-selected={selected ? selected.has(rowId(row)) : undefined}
							interactive={!!onActivate}
							className={selected?.has(rowId(row)) ? "bg-surface-2" : undefined}
							onClick={(e) => {
								if (
									!(e.target as HTMLElement).closest(
										"button,a,input,select,textarea",
									)
								)
									onActivate?.(row);
							}}
							onKeyDown={(e) => {
								if (e.target !== e.currentTarget) return;
								if (e.key === "Enter") {
									e.preventDefault();
									onActivate?.(row);
								}
								if (e.key === " " && onSelectionChange && !disabled) {
									e.preventDefault();
									toggle(rowId(row), e.shiftKey);
								}
								if (["j", "k", "ArrowDown", "ArrowUp"].includes(e.key)) {
									e.preventDefault();
									const sibling = ["j", "ArrowDown"].includes(e.key)
										? e.currentTarget.nextElementSibling
										: e.currentTarget.previousElementSibling;
									(sibling as HTMLElement | null)?.focus();
								}
							}}
						>
							{onSelectionChange && (
								<TD>
									<input
										type="checkbox"
										aria-label={`Select ${rowId(row)}`}
										checked={selected?.has(rowId(row)) ?? false}
										disabled={disabled}
										onChange={() => {}}
										onClick={(e) => {
											e.stopPropagation();
											toggle(rowId(row), e.shiftKey);
										}}
										className="size-4"
									/>
								</TD>
							)}
							{columns.map((c) => (
								<TD key={c.key} numeric={c.numeric}>
									{c.cell(row)}
								</TD>
							))}
						</TR>
					))}
				</TBody>
			</Table>
			{!rows.length && <p className="p-6 text-ink-2">No items to show.</p>}
			{page && (
				<nav
					aria-label="Table pages"
					className="flex justify-end gap-2 border-t border-line p-3"
				>
					<Button
						disabled={disabled || !page.hasPrevious}
						onClick={page.onPrevious}
					>
						Previous page
					</Button>
					<Button disabled={disabled || !page.hasNext} onClick={page.onNext}>
						Next page
					</Button>
				</nav>
			)}
		</div>
	);
}
