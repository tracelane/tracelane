/**
 * PATCH  /api/dashboards/[id]/tiles/[tileId]  — update title / width / height / position.
 * DELETE /api/dashboards/[id]/tiles/[tileId]  — remove a tile (editor+).
 *
 * Position reorder: the caller sends a new `position` integer; the route swaps
 * tiles that would collide (a simple adjacent-swap model). The client
 * (`TileFrame.tsx`) computes the target absolute position from its own
 * `tileIndex ± 1` and sends THAT — this route has never accepted a `move`
 * field, and a prior client build that POSTed `{ move: "up" }` was a dead
 * button caught while building tile sizing (2026-09-07): every field on that
 * body was `undefined` here, `updates` stayed empty, and the route quietly
 * returned the tile UNCHANGED with a 200.
 *
 * A divider tile (DSH-13 §9, 2026-09-07) may change only `title` (its label)
 * and `position` — its `width`/`height` are pinned by the DB CHECK
 * (`dashboard_tiles_divider_shape_chk`) to 12/"compact", so a PATCH carrying
 * either for an EXISTING divider is a 400 naming the field, not a silent
 * no-op.
 *
 * tenant_id from session → internal UUID; dashboard id verified against tenant.
 */

import { db } from "@/db";
import { dashboardTiles, dashboards } from "@/db/schema";
import { requireSession } from "@/lib/auth";
import { upsertTenantId } from "@/lib/tenant";
import { and, eq } from "drizzle-orm";
import { type NextRequest, NextResponse } from "next/server";

function canEdit(role: string | null | undefined): boolean {
	return role === "owner" || role === "admin" || role === "member";
}

const MAX_TITLE_LEN = 60;
const VALID_WIDTHS = new Set([4, 6, 12] as const);
const VALID_HEIGHTS = new Set(["compact", "regular", "tall"] as const);

interface Params {
	params: Promise<{ id: string; tileId: string }>;
}

export async function PATCH(
	req: NextRequest,
	{ params }: Params,
): Promise<NextResponse> {
	const { id, tileId } = await params;
	const session = await requireSession();

	if (!canEdit(session.role)) {
		return NextResponse.json(
			{ error: "viewers cannot edit tiles" },
			{ status: 403 },
		);
	}

	let body: {
		title?: string;
		width?: number;
		height?: string;
		position?: number;
	};
	try {
		body = await req.json();
	} catch {
		return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
	}

	if (body.title !== undefined && body.title.length > MAX_TITLE_LEN) {
		return NextResponse.json(
			{ error: `title must be at most ${MAX_TITLE_LEN} characters` },
			{ status: 422 },
		);
	}
	if (body.width !== undefined && !VALID_WIDTHS.has(body.width as 4 | 6 | 12)) {
		return NextResponse.json(
			{ error: "width must be 4, 6, or 12" },
			{ status: 422 },
		);
	}
	if (
		body.height !== undefined &&
		!VALID_HEIGHTS.has(body.height as "compact" | "regular" | "tall")
	) {
		return NextResponse.json(
			{ error: "height must be compact, regular, or tall" },
			{ status: 422 },
		);
	}

	const tenantDbId = await upsertTenantId(session.tenantId);

	// Verify the dashboard belongs to this tenant before touching any tile.
	const [dashboard] = await db
		.select({ id: dashboards.id })
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!dashboard) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	// Verify the tile exists within this dashboard.
	const [tile] = await db
		.select()
		.from(dashboardTiles)
		.where(
			and(eq(dashboardTiles.id, tileId), eq(dashboardTiles.dashboardId, id)),
		)
		.limit(1);

	if (!tile) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	// A divider is pure layout — always 12 cols / compact height (DB-enforced).
	// It may only be renamed or moved.
	if (tile.shape === "divider") {
		if (body.width !== undefined) {
			return NextResponse.json(
				{
					error: "divider tiles cannot be resized (width is always 12)",
					field: "width",
				},
				{ status: 400 },
			);
		}
		if (body.height !== undefined) {
			return NextResponse.json(
				{
					error: 'divider tiles cannot be resized (height is always "compact")',
					field: "height",
				},
				{ status: 400 },
			);
		}
	}

	// A position outside the grid corrupts the order for every later insert (max+1).
	if (
		body.position !== undefined &&
		(!Number.isInteger(body.position) ||
			body.position < 0 ||
			body.position > 12)
	) {
		return NextResponse.json(
			{ error: "position must be an integer in 0..12" },
			{ status: 422 },
		);
	}
	// If a position change is requested, swap with the tile currently in that slot.
	// B-342: `dashboard_tiles_dashboard_position_uniq` forbids two tiles at one position, so
	// the swap goes THROUGH a temporary slot (-1, never user-supplied): target → -1, tile →
	// new slot, target → the tile's old slot. Three statements, never a violation; a crash
	// between them leaves the target at -1 (renders first, fixable), never a duplicate.
	let swapTargetId: string | null = null;
	if (body.position !== undefined && body.position !== tile.position) {
		const newPos = body.position;
		const [swapTarget] = await db
			.select({ id: dashboardTiles.id, position: dashboardTiles.position })
			.from(dashboardTiles)
			.where(
				and(
					eq(dashboardTiles.dashboardId, id),
					eq(dashboardTiles.position, newPos),
				),
			)
			.limit(1);

		if (swapTarget && swapTarget.id !== tileId) {
			swapTargetId = swapTarget.id;
			await db
				.update(dashboardTiles)
				.set({ position: -1 })
				.where(eq(dashboardTiles.id, swapTarget.id));
		}
	}

	const updates: Partial<typeof dashboardTiles.$inferInsert> = {};
	if (body.title !== undefined) updates.title = body.title;
	if (body.width !== undefined) updates.width = body.width;
	if (body.height !== undefined) updates.height = body.height;
	if (body.position !== undefined) updates.position = body.position;

	if (Object.keys(updates).length === 0) {
		return NextResponse.json(tile);
	}

	const [updated] = await db
		.update(dashboardTiles)
		.set(updates)
		.where(
			and(eq(dashboardTiles.id, tileId), eq(dashboardTiles.dashboardId, id)),
		)
		.returning();
	if (swapTargetId !== null) {
		await db
			.update(dashboardTiles)
			.set({ position: tile.position })
			.where(eq(dashboardTiles.id, swapTargetId));
	}

	// Touch the dashboard so the list re-sorts.
	await db
		.update(dashboards)
		.set({ updatedAt: new Date() })
		.where(eq(dashboards.id, id));

	return NextResponse.json(updated);
}

export async function DELETE(
	_req: NextRequest,
	{ params }: Params,
): Promise<NextResponse> {
	const { id, tileId } = await params;
	const session = await requireSession();

	if (!canEdit(session.role)) {
		return NextResponse.json(
			{ error: "viewers cannot delete tiles" },
			{ status: 403 },
		);
	}

	const tenantDbId = await upsertTenantId(session.tenantId);

	const [dashboard] = await db
		.select({ id: dashboards.id })
		.from(dashboards)
		.where(and(eq(dashboards.id, id), eq(dashboards.tenantId, tenantDbId)))
		.limit(1);

	if (!dashboard) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	const [tile] = await db
		.select({ id: dashboardTiles.id })
		.from(dashboardTiles)
		.where(
			and(eq(dashboardTiles.id, tileId), eq(dashboardTiles.dashboardId, id)),
		)
		.limit(1);

	if (!tile) {
		return NextResponse.json({ error: "not found" }, { status: 404 });
	}

	await db
		.delete(dashboardTiles)
		.where(
			and(eq(dashboardTiles.id, tileId), eq(dashboardTiles.dashboardId, id)),
		);

	// Touch the dashboard.
	await db
		.update(dashboards)
		.set({ updatedAt: new Date() })
		.where(eq(dashboards.id, id));

	return new NextResponse(null, { status: 204 });
}
