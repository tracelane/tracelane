export type DatasetLimits = {
	items_max: number;
	import_bytes_max: number;
	item_input_bytes_max: number;
	expected_output_bytes_max: number;
	metadata_bytes_max: number;
};
export type DatasetItem = {
	item_id: string;
	name: string;
	input: unknown;
	system?: unknown;
	expected_output: string | null;
	expected_output_reason?: string;
	metadata?: Record<string, unknown>;
	source_trace_id: string | null;
	source_span_id: string;
};
export type ImportResult = {
	added: number;
	deduped: number;
	rejected_count: number;
	rejected: { line: number; reason: string }[];
};
export const ownerReason = "Only a workspace owner can change datasets";
export const bytes = (text: string) => new TextEncoder().encode(text).length;
export async function datasetResponse<T>(response: Response): Promise<T> {
	const data =
		response.status === 204 ? null : await response.json().catch(() => null);
	if (!response.ok) {
		if (data?.error === "role_forbidden") throw new Error(ownerReason);
		if (data?.error === "entitlement_required")
			throw new Error(
				"Datasets aren't included in this plan. See plans in Settings → Billing.",
			);
		if (data?.error === "dataset_full")
			throw new Error(
				`Nothing was imported. This file has ${data.incoming ?? data.requested} cases; the dataset has ${data.headroom} slots left.`,
			);
		if (data?.error === "import_too_large")
			throw new Error(
				`Nothing was imported. File size ${data.got_bytes} bytes exceeds ${data.max_bytes} bytes.`,
			);
		throw new Error(
			data?.message ??
				data?.error ??
				`Request refused (${response.status}). Retry.`,
		);
	}
	return data as T;
}
export function parseMetadata(text: string) {
	const value = JSON.parse(text);
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Metadata must be a JSON object.");
	return value as Record<string, unknown>;
}
