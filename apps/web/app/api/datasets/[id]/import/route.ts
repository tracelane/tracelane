import { forwardParams, gatewayPostText } from "@/lib/gateway";
import { type NextRequest, NextResponse } from "next/server";
import { datasetError } from "../../shared";

/**
 * `EVL-31` slice 1. The body is forwarded as RAW TEXT, never re-encoded JSON —
 * `gatewayPost` always `JSON.stringify`s its argument, which would wrap a
 * JSONL file's bytes in one giant quoted string instead of sending the
 * newline-delimited objects the gateway parses line by line. `gatewayPostText`
 * exists for exactly this shape (spec §2).
 */
export async function POST(
	req: NextRequest,
	context: { params: Promise<{ id: string }> },
) {
	const { id } = await context.params;
	const qs = forwardParams(req.nextUrl.searchParams, ["format"]);
	if (!qs.has("format")) qs.set("format", "jsonl");
	const text = await req.text();
	try {
		return NextResponse.json(
			await gatewayPostText(
				`/v1/datasets/${encodeURIComponent(id)}/import?${qs}`,
				text,
				req.headers.get("content-type") ?? "application/x-ndjson",
			),
		);
	} catch (err) {
		return datasetError(err);
	}
}
