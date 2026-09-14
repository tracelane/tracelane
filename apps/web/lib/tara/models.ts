/**
 * Which model Tara calls, given the tenant's connected BYOK providers.
 *
 * Shared by the server route (`app/api/tara/route.ts`, which validates the
 * client's choice) and the client panel (`components/tara/TaraPanel.tsx`,
 * which offers it as the default so a user never has to know a model id to
 * ask a question). Plain data — no secrets, safe on either side.
 *
 * Only providers we can name a genuinely cheap, known-good chat model for
 * are listed (spec §2: "default the cheapest known per provider"). A
 * connected provider NOT in this map is real but unusable by Tara today —
 * it is left out of the picker rather than guessed at, because a wrong
 * model id would surface as an opaque gateway 400 instead of an honest
 * "not supported yet".
 */
export const TARA_DEFAULT_MODEL_FOR_PROVIDER: Readonly<Record<string, string>> =
	{
		anthropic: "claude-haiku-4-5-20251001",
		openai: "gpt-4o-mini",
		google: "gemini-2.0-flash",
		groq: "groq/llama-3.1-8b-instant",
	};

/** Preference order when a tenant has more than one usable provider — the
 * spec names Anthropic's Haiku and OpenAI's 4o-mini explicitly; anything
 * else is a reasonable low-cost fallback in the order it is most likely to
 * be a customer's actual production provider. */
const PROVIDER_PREFERENCE = ["anthropic", "openai", "google", "groq"] as const;

/**
 * Pick a default `{ providerId, model }` from the tenant's connected
 * provider ids, or `null` when none of them is one Tara knows a model for
 * (including the empty-list "no provider key at all" case).
 */
export function pickDefaultTaraModel(
	connectedProviderIds: readonly string[],
): { providerId: string; model: string } | null {
	const connected = new Set(connectedProviderIds);
	for (const id of PROVIDER_PREFERENCE) {
		if (!connected.has(id)) continue;
		const model = TARA_DEFAULT_MODEL_FOR_PROVIDER[id];
		if (model) return { providerId: id, model };
	}
	return null;
}
