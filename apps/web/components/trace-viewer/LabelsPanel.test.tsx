// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { LabelsPanel } from "./LabelsPanel";
afterEach(cleanup);

it("shows recorded labels, dropped counts and streamed output speed", () => {
	render(
		<LabelsPanel
			durationUs={2_000_000}
			minGenerationMs={50}
			attrs={{
				deployment_environment: "production",
				service_version: "r12",
				service_name: "checkout",
				tracelane_tags: ["priority", "customer"],
				tracelane_metadata: { team: "payments" },
				tracelane_labels_dropped: { metadata_keys: 1 },
				gen_ai_request_stream: true,
				gen_ai_response_time_to_first_chunk: 0.5,
				tracelane_gateway_overhead_us: 200_000,
				gen_ai_usage_output_tokens: 109,
			}}
		/>,
	);
	expect(screen.getByRole("region", { name: "Labels" })).toHaveTextContent(
		"Environment production · Release r12 · Service checkout",
	);
	expect(screen.getByText("payments")).toBeInTheDocument();
	expect(screen.getByText(/metadata_keys 1/)).toBeInTheDocument();
	expect(
		screen.getByRole("region", { name: "Output speed" }),
	).toHaveTextContent("84 tok/s");
});

it("distinguishes unmeasured buffered and too-short streamed calls", () => {
	const { rerender } = render(
		<LabelsPanel
			attrs={{ gen_ai_request_model: "gpt-4o", gen_ai_request_stream: false }}
			durationUs={2_000_000}
			minGenerationMs={50}
		/>,
	);
	expect(
		screen.getByRole("region", { name: "Output speed" }),
	).toHaveTextContent("Only measured for streamed responses");
	rerender(
		<LabelsPanel
			attrs={{
				gen_ai_request_model: "gpt-4o",
				gen_ai_request_stream: true,
				gen_ai_response_time_to_first_chunk: 0.1,
				gen_ai_usage_output_tokens: 10,
			}}
			durationUs={130_000}
			minGenerationMs={50}
		/>,
	);
	expect(
		screen.getByRole("region", { name: "Output speed" }),
	).toHaveTextContent("Too short to measure (< 50 ms of generation)");
});
