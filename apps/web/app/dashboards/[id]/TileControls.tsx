"use client";

/**
 * TileControls — the presentational button cluster for one tile: resize
 * width (narrower/wider, cycles 4→6→12), resize height (shorter/taller,
 * cycles compact→regular→tall), move up/down, and remove. All state and
 * network calls live in the parent `TileFrame`; this component only renders
 * buttons and reports intent via callbacks, so it stays keyboard-reachable
 * and testable without duplicating fetch logic.
 *
 * `aria-label`s on every button (spec §3); `disabled` reflects both the
 * in-flight state (`busy`) and the boundary of each cycle (width can't go
 * narrower than 4, height can't go shorter than compact, etc.) so a control
 * that would be a no-op is never presented as live.
 *
 * `sizeControls={false}` (spec §9, divider tiles, 2026-09-07) hides the four
 * W±/H± buttons entirely — a divider has exactly one valid size, so a resize
 * control here would always be a no-op. Move/remove stay.
 */

import type { TileHeight, TileWidth } from "@/lib/metrics/tile-support";

export type BusyKind = "width" | "height" | "move" | "remove" | null;

const BTN =
	"rounded px-1.5 py-0.5 text-2xs font-medium text-ink-3 transition-colors hover:bg-surface-2 hover:text-ink disabled:cursor-not-allowed disabled:opacity-30 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring";

interface Props {
	tileIndex: number;
	totalTiles: number;
	width: TileWidth;
	height: TileHeight;
	busy: BusyKind;
	/** Show the W±/H± resize buttons. Default `true`; `false` for a divider
	 * tile, which has exactly one valid size. */
	sizeControls?: boolean;
	onMove: (direction: "up" | "down") => void;
	onRemove: () => void;
	onResizeWidth: (dir: "narrower" | "wider") => void;
	onResizeHeight: (dir: "shorter" | "taller") => void;
}

export function TileControls({
	tileIndex,
	totalTiles,
	width,
	height,
	busy,
	sizeControls = true,
	onMove,
	onRemove,
	onResizeWidth,
	onResizeHeight,
}: Props) {
	const disabled = busy !== null;
	return (
		<fieldset
			className="m-0 flex min-w-0 items-center gap-0.5 border-0 p-0"
			aria-label="Tile controls"
		>
			{sizeControls && (
				<>
					<button
						type="button"
						onClick={() => onResizeWidth("narrower")}
						disabled={disabled || width === 4}
						aria-label="Make tile narrower"
						title="Narrower"
						className={BTN}
					>
						W−
					</button>
					<button
						type="button"
						onClick={() => onResizeWidth("wider")}
						disabled={disabled || width === 12}
						aria-label="Make tile wider"
						title="Wider"
						className={BTN}
					>
						W+
					</button>
					<button
						type="button"
						onClick={() => onResizeHeight("shorter")}
						disabled={disabled || height === "compact"}
						aria-label="Make tile shorter"
						title="Shorter"
						className={BTN}
					>
						H−
					</button>
					<button
						type="button"
						onClick={() => onResizeHeight("taller")}
						disabled={disabled || height === "tall"}
						aria-label="Make tile taller"
						title="Taller"
						className={BTN}
					>
						H+
					</button>
					<span aria-hidden="true" className="mx-0.5 h-3 w-px bg-line-2" />
				</>
			)}
			<button
				type="button"
				onClick={() => onMove("up")}
				disabled={disabled || tileIndex === 0}
				aria-label="Move tile up"
				title="Move up"
				className={BTN}
			>
				↑
			</button>
			<button
				type="button"
				onClick={() => onMove("down")}
				disabled={disabled || tileIndex === totalTiles - 1}
				aria-label="Move tile down"
				title="Move down"
				className={BTN}
			>
				↓
			</button>
			<button
				type="button"
				onClick={onRemove}
				disabled={disabled}
				aria-label="Remove tile"
				title="Remove tile"
				className="rounded px-1.5 py-0.5 text-2xs font-medium text-danger transition-colors hover:bg-danger/10 disabled:cursor-not-allowed disabled:opacity-30 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-focus-ring"
			>
				×
			</button>
		</fieldset>
	);
}
