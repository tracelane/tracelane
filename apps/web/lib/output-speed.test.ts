import { expect, it } from "vitest";
import { outputSpeed } from "./output-speed";

it("matches the SQL output speed definition on a streamed fixture", () => {
	const attrs = {
		gen_ai_request_stream: true,
		gen_ai_response_time_to_first_chunk: 0.5,
		tracelane_gateway_overhead_us: 200_000,
		gen_ai_usage_output_tokens: 109,
	};
	expect(outputSpeed(attrs, 2_000_000, 50)).toEqual({
		value: 109 / 1.3,
		estimated: false,
	});
	expect(
		outputSpeed({ ...attrs, tracelane_usage_estimated: true }, 2_000_000, 50)
			?.estimated,
	).toBe(true);
	expect(
		outputSpeed({ ...attrs, gen_ai_request_stream: false }, 2_000_000, 50),
	).toBeNull();
	expect(outputSpeed(attrs, 710_000, 50)).toBeNull();
});
