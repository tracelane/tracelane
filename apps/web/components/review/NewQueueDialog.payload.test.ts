/**
 * `EVL-29` — pure-function tests for the "New queue" payload builder.
 *
 * Node environment (no DOM needed): `buildCreateQueuePayload` is a pure
 * function of form state, and `locationForError`/`moveRubricField` are pure
 * helpers alongside it.
 */

import { describe, expect, it } from "vitest";
import {
	MAX_QUEUE_WINDOW_HOURS,
	MAX_RUBRIC_KEY_LEN,
	type NewQueueFormState,
	buildCreateQueuePayload,
	emptyRubricField,
	initialFormState,
	locationForError,
	moveRubricField,
} from "./NewQueueDialog";

function withRubric(
	form: NewQueueFormState,
	rubric: NewQueueFormState["rubric"],
	referenceKey: string,
): NewQueueFormState {
	return { ...form, rubric, referenceKey };
}

function base(): NewQueueFormState {
	const form = initialFormState("ds-1");
	form.name = "Low-score support replies";
	return form;
}

describe("buildCreateQueuePayload", () => {
	it("builds the exact snake_case wire shape, with no extra keys", () => {
		const form = withRubric(
			base(),
			[
				{ ...emptyRubricField(), key: "note", label: "What went wrong?" },
				{
					...emptyRubricField(),
					key: "expected_answer",
					label: "Correct answer",
				},
			],
			"expected_answer",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(true);
		if (!result.ok) return;

		expect(Object.keys(result.body).sort()).toEqual(
			[
				"name",
				"filter",
				"rubric",
				"default_dataset_id",
				"expected_output_field",
			].sort(),
		);
		expect(Object.keys(result.body.filter).sort()).toEqual(
			["source", "window_hours"].sort(),
		);
		expect(Object.keys(result.body.filter.source).sort()).toEqual(
			["kind", "max_score"].sort(), // no `rubric` key — sourceRubric was blank
		);
		for (const r of result.body.rubric) {
			expect(Object.keys(r).sort()).toEqual(
				["key", "label", "type", "required"].sort(), // no options/min/max for `text`
			);
		}

		expect(result.body).toEqual({
			name: "Low-score support replies",
			filter: {
				source: { kind: "online_eval_score", max_score: 0.5 },
				window_hours: 168,
			},
			rubric: [
				{
					key: "note",
					label: "What went wrong?",
					type: "text",
					required: true,
				},
				{
					key: "expected_answer",
					label: "Correct answer",
					type: "text",
					required: true,
				},
			],
			default_dataset_id: "ds-1",
			expected_output_field: "expected_answer",
		});
	});

	it("includes `rubric` on the source only when a restriction is typed", () => {
		const form = base();
		form.sourceRubric = "helpfulness";
		form.rubric = [{ ...emptyRubricField(), key: "a" }];
		form.referenceKey = "a";
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.body.filter.source).toEqual({
			kind: "online_eval_score",
			max_score: 0.5,
			rubric: "helpfulness",
		});
	});

	it("emits `options` only for a choice field, `min`/`max` only for a score field", () => {
		const form = withRubric(
			base(),
			[
				{
					...emptyRubricField(),
					key: "category",
					type: "choice",
					options: "a, b , ,c",
				},
				{
					...emptyRubricField(),
					key: "confidence",
					type: "score",
					required: false,
					min: "0",
					max: "10",
				},
				{ ...emptyRubricField(), key: "note", type: "text" },
			],
			"note",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const [choice, score, text] = result.body.rubric;
		expect(choice).toMatchObject({ options: ["a", "b", "c"] });
		expect(choice && "min" in choice).toBe(false);
		expect(score).toMatchObject({ min: 0, max: 10 });
		expect(score && "options" in score).toBe(false);
		expect(text && "options" in text).toBe(false);
		expect(text && "min" in text).toBe(false);
	});

	it("clamps a window above the cap rather than sending an oversized one", () => {
		const form = base();
		form.windowHours = String(MAX_QUEUE_WINDOW_HOURS + 500);
		form.rubric = [{ ...emptyRubricField(), key: "a" }];
		form.referenceKey = "a";
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.body.filter.window_hours).toBe(MAX_QUEUE_WINDOW_HOURS);
	});

	it("refuses a window of zero", () => {
		const form = base();
		form.windowHours = "0";
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("window_out_of_range");
	});

	it("refuses a blank name", () => {
		const form = base();
		form.name = "   ";
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toEqual({
			code: "invalid_name",
			field: "name",
			message: expect.stringContaining("1..="),
		});
	});

	it("refuses a name past the length cap", () => {
		const form = base();
		form.name = "x".repeat(300);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("invalid_name");
	});

	it("refuses with no dataset chosen", () => {
		const form = base();
		form.datasetId = "";
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.field).toBe("default_dataset_id");
	});

	it("refuses an empty rubric", () => {
		const form = base();
		form.rubric = [];
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("rubric_empty");
	});

	it("refuses duplicate rubric keys, naming the key", () => {
		const form = withRubric(
			base(),
			[
				{ ...emptyRubricField(), key: "note" },
				{ ...emptyRubricField(), key: "note" },
			],
			"note",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toMatchObject({
			code: "rubric_duplicate_key",
			field: "note",
		});
	});

	it("rubric keys are unique in every accepted payload", () => {
		const form = withRubric(
			base(),
			[
				{ ...emptyRubricField(), key: "a" },
				{ ...emptyRubricField(), key: "b" },
				{ ...emptyRubricField(), key: "c" },
			],
			"a",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const keys = result.body.rubric.map((r) => r.key);
		expect(new Set(keys).size).toBe(keys.length);
	});

	it("refuses a rubric key over the length cap", () => {
		const form = withRubric(
			base(),
			[{ ...emptyRubricField(), key: "k".repeat(MAX_RUBRIC_KEY_LEN + 1) }],
			"",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("rubric_bad_key");
	});

	it("refuses a choice field with no options", () => {
		const form = withRubric(
			base(),
			[{ ...emptyRubricField(), key: "category", type: "choice", options: "" }],
			"category",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error).toMatchObject({
			code: "rubric_choice_needs_options",
			field: "category",
		});
	});

	it("refuses a score field with min >= max", () => {
		const form = withRubric(
			base(),
			[
				{
					...emptyRubricField(),
					key: "confidence",
					type: "score",
					min: "5",
					max: "5",
				},
			],
			"",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("rubric_score_bad_bounds");
	});

	it("the reference field must be one of the rubric keys", () => {
		const form = withRubric(
			base(),
			[{ ...emptyRubricField(), key: "note" }],
			"nope",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("expected_output_field_unknown");
	});

	it("a boolean field cannot be the reference (R223's carve-out)", () => {
		const form = withRubric(
			base(),
			[{ ...emptyRubricField(), key: "escalate", type: "boolean" }],
			"escalate",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("expected_output_field_not_usable");
	});

	it("an optional field cannot be the reference", () => {
		const form = withRubric(
			base(),
			[{ ...emptyRubricField(), key: "note", required: false }],
			"note",
		);
		const result = buildCreateQueuePayload(form);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("expected_output_field_optional");
	});
});

describe("locationForError", () => {
	const rubric = [
		{ ...emptyRubricField(), key: "a" },
		{ ...emptyRubricField(), key: "b" },
	];

	it("maps a rubric-scoped code to the matching row by key", () => {
		expect(
			locationForError(
				{ code: "rubric_duplicate_key", field: "b", message: "" },
				rubric,
			),
		).toEqual({ rubricIndex: 1 });
	});

	it("falls back to the banner when the field does not match any row", () => {
		expect(
			locationForError(
				{ code: "rubric_duplicate_key", field: "zzz", message: "" },
				rubric,
			),
		).toBe("banner");
	});

	it("maps known non-rubric codes to their control", () => {
		expect(
			locationForError({ code: "invalid_name", message: "" }, rubric),
		).toBe("name");
		expect(
			locationForError({ code: "dataset_not_found", message: "" }, rubric),
		).toBe("dataset");
		expect(
			locationForError(
				{ code: "expected_output_field_not_usable", message: "" },
				rubric,
			),
		).toBe("reference");
	});

	it("an unknown code falls back to the banner", () => {
		expect(
			locationForError({ code: "store_failed", message: "" }, rubric),
		).toBe("banner");
		expect(
			locationForError({ code: "gateway_unreachable", message: "" }, rubric),
		).toBe("banner");
	});
});

describe("moveRubricField", () => {
	it("swaps two adjacent rows", () => {
		const fields = [
			{ ...emptyRubricField(), key: "a" },
			{ ...emptyRubricField(), key: "b" },
		];
		const moved = moveRubricField(fields, 0, 1);
		expect(moved.map((f) => f.key)).toEqual(["b", "a"]);
	});

	it("is a no-op past either boundary", () => {
		const fields = [{ ...emptyRubricField(), key: "a" }];
		expect(moveRubricField(fields, 0, -1)).toBe(fields);
		expect(moveRubricField(fields, 0, 1)).toBe(fields);
	});
});
