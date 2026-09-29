import { forwardParams, gatewayGet, gatewayGetText } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { datasetError } from "../../shared";

/** Lowercase ASCII, digits and hyphens only — a filename byte, not a display label. */
function slugify(name: string): string {
	const s = name
		.trim()
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
	return s.length > 0 ? s : "dataset";
}

/**
 * `EVL-31` slice 1. The gateway sends a generic `dataset.jsonl`
 * (`crates/gateway/src/dataset_routes.rs`); this rewrites `Content-Disposition`
 * to the dataset's own name so two exports downloaded side by side are
 * distinguishable without opening either.
 */
export async function GET(
	req: NextRequest,
	context: { params: Promise<{ id: string }> },
) {
	const { id } = await context.params;
	const qs = forwardParams(req.nextUrl.searchParams, ["format"]);
	if (!qs.has("format")) qs.set("format", "jsonl");
	try {
		const [dataset, body] = await Promise.all([
			gatewayGet<{ name: string }>(`/v1/datasets/${encodeURIComponent(id)}`),
			gatewayGetText(`/v1/datasets/${encodeURIComponent(id)}/export?${qs}`),
		]);
		return new NextResponse(body, {
			status: 200,
			headers: {
				"content-type": "application/x-ndjson",
				"content-disposition": `attachment; filename="${slugify(dataset.name)}.jsonl"`,
			},
		});
	} catch (err) {
		return datasetError(err);
	}
}
