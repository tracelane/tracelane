/**
 * `EVL-03` §2/§3 — "Save as prompt version" builds this payload and posts it
 * to the EXISTING `POST /api/prompts/[name]/versions` (no new route; that
 * route already forwards the raw body verbatim to the gateway's
 * `POST /v1/prompts/{name}/versions`). Codex's save dialog (§10 A5, its half)
 * calls this pure function; it never builds the body itself.
 *
 * WHAT A PROMPT VERSION IS, PRECISELY (spec §3): a system instruction, never
 * the messages or tools. `content` is the system field VERBATIM — unrendered,
 * untrimmed, byte-equal to what the user sees (proof #6) — because
 * `prompt_eval.rs:1853` uses `version.content` as the system prompt and the
 * gateway stores `template_variables` without ever substituting them
 * (`prompt_routes.rs:160-163`). Trimming or rendering here would silently
 * change what gets saved from what the dialog showed.
 */
import { variablesIn } from "./playground-template";

export interface PromptVersionDraft {
	/** The playground's system field, exactly as typed — variables unrendered. */
	system: string;
	/** Column 1's model id. */
	model: string;
}

export interface PromptVersionPayload {
	content: string;
	model_pin: string;
	template_variables: string[];
}

export type BuildPromptVersionPayloadResult =
	| { ok: true; payload: PromptVersionPayload }
	| { ok: false; error: string };

export function buildPromptVersionPayload(
	draft: PromptVersionDraft,
): BuildPromptVersionPayloadResult {
	if (!draft.system.trim()) {
		return { ok: false, error: "the system prompt is empty — nothing to save" };
	}
	const model = draft.model.trim();
	if (!model) {
		return { ok: false, error: "select a model for column 1 before saving" };
	}
	return {
		ok: true,
		payload: {
			// Verbatim — NEVER `.trim()`ed or rendered. Proof #6 asserts this is
			// byte-equal to the system field the dialog showed.
			content: draft.system,
			model_pin: model,
			template_variables: variablesIn(draft.system),
		},
	};
}
