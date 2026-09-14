"use client";

/**
 * TileFrame — the client-owned wrapper around one tile's grid cell.
 *
 * Owns THREE things no RSC can own: the literal Tailwind width class (so a
 * resize is an instant CSS reflow, no round trip needed to see it), the
 * hover/focus-visible resize+move+remove controls (one overlay for every
 * shape — stat, series, breakdown, and every error/empty state — rather than
 * each shape building its own, which is how the stat branch shipped with NO
 * `group` ancestor and its controls were invisible at every hover regardless
 * of `group-hover:opacity-100`), and the optimistic width/height state.
 *
 * WIDTH resize is pure CSS — the new class renders instantly and the PATCH
 * happens in the background; on failure the width reverts and a toast says
 * so. No `router.refresh()` is needed because nothing server-rendered
 * changes shape.
 *
 * HEIGHT resize is different: the actual chart pixel height is computed
 * server-side from `tile.height` (`TileContainer` → `MetricChart
 * height={heightPxFor(...)}`), so a real resize needs a fresh RSC payload.
 * The local `height` state still updates optimistically (so the resize
 * skeleton — `TileSkeleton` — renders at the TARGET size immediately) while
 * `router.refresh()` runs inside a transition; `isPending` gates the
 * skeleton so the customer never sees a chart drawn at the old height inside
 * a box sized for the new one.
 *
 * MOVE / REMOVE change the tile array itself (order or count), which only
 * the server can resolve correctly (position, `tileIndex`, `totalTiles`),
 * so both always go through `router.refresh()`.
 *
 * `dashboard_tiles.height`, the PATCH route's `move`→`position` translation,
 * and this component all shipped together, 2026-09-07 — see the spec's
 * "Tile sizing" section for the full root-cause and design.
 *
 * DIVIDER tiles (spec §9, same day) reuse this exact wrapper for move/remove,
 * but never resize: `TileControls`'s `sizeControls={false}` suppresses the
 * W±/H± buttons for shape="divider", so a divider's width/height state here
 * is set once (12/"compact") and never cycles.
 */

import {
	type TileHeight,
	type TileShape,
	type TileWidth,
	WIDTH_CLASS,
	cycleHeight,
	cycleWidth,
} from "@/lib/metrics/tile-support";
import { cn } from "@tracelanedev/ui";
import { useRouter } from "next/navigation";
import {
	type ReactNode,
	useEffect,
	useRef,
	useState,
	useTransition,
} from "react";
import { type BusyKind, TileControls } from "./TileControls";
import { TileSkeleton } from "./TileSkeleton";

interface Props {
	dashboardId: string;
	tileId: string;
	tileIndex: number;
	totalTiles: number;
	canEdit: boolean;
	initialWidth: TileWidth;
	initialHeight: TileHeight;
	shape: TileShape;
	children: ReactNode;
}

export function TileFrame({
	dashboardId,
	tileId,
	tileIndex,
	totalTiles,
	canEdit,
	initialWidth,
	initialHeight,
	shape,
	children,
}: Props) {
	const router = useRouter();
	const [width, setWidth] = useState<TileWidth>(initialWidth);
	const [height, setHeight] = useState<TileHeight>(initialHeight);
	const [busy, setBusy] = useState<BusyKind>(null);
	const [toast, setToast] = useState<string | null>(null);
	const [isPending, startTransition] = useTransition();
	const wasPending = useRef(false);
	const toastTimer = useRef<ReturnType<typeof setTimeout> | undefined>(
		undefined,
	);

	// Clear `busy` on the FALLING edge of `isPending` — i.e. once a
	// `router.refresh()` triggered below actually completes, never on the
	// render that merely starts it (isPending is still false at that instant).
	useEffect(() => {
		if (wasPending.current && !isPending) setBusy(null);
		wasPending.current = isPending;
	}, [isPending]);

	useEffect(() => () => clearTimeout(toastTimer.current), []);

	function flash(message: string) {
		setToast(message);
		clearTimeout(toastTimer.current);
		toastTimer.current = setTimeout(() => setToast(null), 4000);
	}

	async function patchTile(body: Record<string, unknown>): Promise<boolean> {
		try {
			const res = await fetch(
				`/api/dashboards/${dashboardId}/tiles/${tileId}`,
				{
					method: "PATCH",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(body),
				},
			);
			return res.ok;
		} catch {
			return false;
		}
	}

	async function handleResizeWidth(dir: "narrower" | "wider") {
		if (busy) return;
		const next = cycleWidth(width, dir);
		if (next === width) return;
		const prev = width;
		setBusy("width");
		setWidth(next); // optimistic: instant CSS reflow, no refresh needed
		const ok = await patchTile({ width: next });
		if (!ok) {
			setWidth(prev);
			flash("Couldn't resize — width reverted");
		}
		setBusy(null);
	}

	async function handleResizeHeight(dir: "shorter" | "taller") {
		if (busy) return;
		const next = cycleHeight(height, dir);
		if (next === height) return;
		const prev = height;
		setBusy("height");
		setHeight(next); // optimistic: sizes the resize skeleton immediately
		const ok = await patchTile({ height: next });
		if (!ok) {
			setHeight(prev);
			setBusy(null);
			flash("Couldn't resize — height reverted");
			return;
		}
		// The real chart is server-rendered at the new height; the skeleton
		// above (gated on `busy === "height" && isPending`) covers the gap.
		startTransition(() => router.refresh());
	}

	async function handleMove(direction: "up" | "down") {
		if (busy) return;
		setBusy("move");
		const targetPosition = tileIndex + (direction === "up" ? -1 : 1);
		const ok = await patchTile({ position: targetPosition });
		if (!ok) {
			setBusy(null);
			flash("Couldn't move tile — try again");
			return;
		}
		startTransition(() => router.refresh());
	}

	async function handleRemove() {
		if (busy) return;
		setBusy("remove");
		let ok = false;
		try {
			const res = await fetch(
				`/api/dashboards/${dashboardId}/tiles/${tileId}`,
				{ method: "DELETE" },
			);
			ok = res.ok;
		} catch {
			ok = false;
		}
		if (!ok) {
			setBusy(null);
			flash("Couldn't remove tile — try again");
			return;
		}
		startTransition(() => router.refresh());
	}

	// Only reachable via H+/H-, which TileControls never renders for a divider
	// (`sizeControls={false}` below) — so `showResizeSkeleton` is structurally
	// unreachable for shape="divider" even though TypeScript cannot see that
	// through the button-click callback. The cast reflects that invariant
	// rather than widening TileSkeleton's own prop type for a case it will
	// never actually receive.
	const showResizeSkeleton = busy === "height" && isPending;

	return (
		<div className={cn(WIDTH_CLASS[width], "group relative")}>
			{showResizeSkeleton ? (
				<TileSkeleton
					shape={shape as "stat" | "series" | "breakdown"}
					height={height}
				/>
			) : (
				children
			)}
			{canEdit && (
				<div className="pointer-events-none absolute right-2 top-2 z-10 opacity-0 transition-opacity focus-within:opacity-100 group-focus-within:opacity-100 group-hover:opacity-100">
					<div className="pointer-events-auto rounded-[var(--radius-control)] border border-line bg-surface p-1 shadow-[var(--shadow-overlay)]">
						<TileControls
							tileIndex={tileIndex}
							totalTiles={totalTiles}
							width={width}
							height={height}
							busy={busy}
							sizeControls={shape !== "divider"}
							onMove={handleMove}
							onRemove={handleRemove}
							onResizeWidth={handleResizeWidth}
							onResizeHeight={handleResizeHeight}
						/>
					</div>
				</div>
			)}
			{toast && (
				<output className="pointer-events-none absolute inset-x-2 bottom-2 z-10 block rounded-[var(--radius-control)] border border-line bg-surface px-2 py-1 text-2xs text-danger-ink shadow-[var(--shadow-overlay)]">
					{toast}
				</output>
			)}
		</div>
	);
}
