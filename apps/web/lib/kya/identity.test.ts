import { describe, expect, it } from "vitest";
import {
	decodeIdentityKey,
	encodeIdentityKey,
	identityHref,
	resolveIdentity,
} from "./identity";

describe("observed identity", () => {
	it("prefers the supplied name to the classified client, bounded and normalized", () => {
		const result = resolveIdentity({
			gen_ai_agent_name: "  CLAUDE-CODE  ",
			tracelane_client_name: "codex",
		});
		expect(result.agent).toMatchObject({
			key: "claude-code",
			label: "Claude Code",
		});
	});
	it("falls back to the classified client and leaves absent signals absent", () => {
		expect(
			resolveIdentity({ tracelane_client_name: "codex" }).agent,
		).toMatchObject({ key: "codex" });
		expect(resolveIdentity({})).toEqual({ agent: null, model: null });
	});
	it("uses the served model, folds dated route aliases, and keeps maker separate", () => {
		const a = resolveIdentity({
			gen_ai_response_model: "vertex/claude-haiku-4-5-20251001",
			gen_ai_request_model: "gpt-6-sol",
			gen_ai_system: "vertex",
		});
		expect(a.model).toMatchObject({
			key: "claude-haiku-4-5",
			makerId: "anthropic",
			providerId: "vertex",
		});
		const b = resolveIdentity({
			gen_ai_request_model: "llama-3.3-70b-versatile",
			gen_ai_system: "groq",
		});
		expect(b.model).toMatchObject({ makerId: "meta", providerId: "groq" });
	});
	it("keeps unknown identities visible with their raw key and a monogram", () => {
		const result = resolveIdentity({
			gen_ai_agent_name: "custom-agent",
			gen_ai_request_model: "unknown-model",
		});
		expect(result.agent).toMatchObject({
			label: "custom-agent",
			known: false,
			avatar: { kind: "monogram" },
		});
		expect(result.model).toMatchObject({
			label: "unknown-model",
			known: false,
			avatar: { kind: "monogram" },
		});
	});
	it("reserves drawable motifs for the three named celestial models", () => {
		for (const [model, glyph] of [
			["gpt-6-sol", "sun"],
			["gpt-6-luna", "moon"],
			["gpt-6-astra", "star"],
		]) {
			expect(
				resolveIdentity({ gen_ai_request_model: model }).model,
			).toMatchObject({ avatar: { kind: "motif", glyph } });
		}
		expect(
			resolveIdentity({ gen_ai_request_model: "claude-sonnet-4-6" }).model,
		).toMatchObject({
			avatar: { kind: "mark", src: "/kya/makers/anthropic.svg" },
		});
	});
});

it("dot names remain routable and cannot collide with reserved key escapes", () => {
	for (const name of [".", "..", "~.", "~.."]) {
		const identity = resolveIdentity({ gen_ai_agent_name: name }).agent;
		expect(identity).not.toBeNull();
		if (!identity) throw new Error("expected a named identity");
		const url = new URL(identityHref(identity), "http://local");
		expect(url.pathname.split("/")).toHaveLength(4);
		expect(decodeIdentityKey("agent", identity.key)).toBe(name);
	}
	expect(encodeIdentityKey("agent", ".")).toBe("~.");
	expect(encodeIdentityKey("model", "..")).toBe("~..");
});

it("folds ISO snapshots to the same model family as the gateway read", () => {
	expect(
		resolveIdentity({ gen_ai_response_model: "OpenAI/GPT-4o-2024-08-06" }).model
			?.key,
	).toBe("gpt-4o");
	expect(
		resolveIdentity({ gen_ai_response_model: "claude-haiku-4-5" }).model?.key,
	).toBe("claude-haiku-4-5");
});
