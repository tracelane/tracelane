"use client";
import { DataTable } from "@tracelanedev/ui";
import type { DatasetItem, DatasetLimits } from "../management";
import { CaseInput } from "./CaseInput";
import { ItemRowActions } from "./ItemRowActions";
export function DatasetItems({
	datasetId,
	items,
	limits,
	canWrite,
}: {
	datasetId: string;
	items: DatasetItem[];
	limits?: DatasetLimits;
	canWrite: boolean;
}) {
	return (
		<DataTable
			label="Dataset cases"
			rows={items}
			rowId={(r) => r.item_id}
			columns={[
				{
					key: "name",
					header: "Case",
					sortValue: (r) => r.name,
					cell: (r) => (
						<span className="font-medium">{r.name || r.item_id}</span>
					),
				},
				{
					key: "input",
					header: "Input",
					cell: (r) => <CaseInput value={r.input} />,
				},
				{
					key: "reference",
					header: "Expected output",
					cell: (r) => (
						<span className="whitespace-pre-wrap">
							{r.expected_output ??
								(r.expected_output_reason === "output_not_captured"
									? "Output not captured"
									: "No expected output")}
						</span>
					),
				},
				{
					key: "source",
					header: "Source trace",
					cell: (r) =>
						r.source_trace_id ? (
							<a
								className="underline"
								href={`/traces/${r.source_trace_id}${r.source_span_id ? `?span=${encodeURIComponent(r.source_span_id)}` : ""}`}
							>
								{r.source_trace_id}
								{r.source_span_id && ` · span ${r.source_span_id}`}
							</a>
						) : (
							"No source trace"
						),
				},
				{
					key: "actions",
					header: "Actions",
					cell: (r) => (
						<ItemRowActions
							datasetId={datasetId}
							itemId={r.item_id}
							name={r.name}
							input={r.input}
							system={r.system}
							expectedOutput={r.expected_output}
							metadata={r.metadata}
							limits={limits}
							canWrite={canWrite}
						/>
					),
				},
			]}
		/>
	);
}
