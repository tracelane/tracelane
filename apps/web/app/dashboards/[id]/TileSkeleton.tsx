/**
 * TileSkeleton — the loading placeholder for a tile, shown in two places:
 *   1. Its own `Suspense` fallback in `page.tsx` while the tile's RSC data loads.
 *   2. `TileFrame`, while a height resize is in flight (spec §3: "loading state
 *      while saving") — the real chart's pixel height is server-rendered from
 *      `tile.height`, so a resize needs a fresh RSC payload; this fills the gap
 *      at the TARGET size rather than showing stale, mis-sized content.
 *
 * Height-aware on purpose: the founder's report was a tile "so slim the graph
 * wasn't visible", and a skeleton pinned to a fixed height would reproduce the
 * exact same tell during every load and every resize.
 */

import {
	CHART_HEIGHT_PX,
	STAT_MIN_HEIGHT_PX,
	type TileHeight,
} from "@/lib/metrics/tile-support";
import { Skeleton } from "@tracelanedev/ui";

export function TileSkeleton({
	shape,
	height,
}: {
	shape: "stat" | "series" | "breakdown";
	height: TileHeight;
}) {
	const px =
		shape === "stat" ? STAT_MIN_HEIGHT_PX[height] : CHART_HEIGHT_PX[height];
	return <Skeleton className="w-full" style={{ height: px }} />;
}
