import { PROVIDERS } from "@/components/settings/provider-catalog.generated";
import catalogData from "@/db/kya_catalog.v1.json";

export type IdentityKind = "agent" | "model";
export type IdentitySignals = Record<string, unknown>;
type Mark = { mark?: string; mark_source?: string; mark_license?: string };
type Catalog = {
	version: string;
	limits: {
		identities: number;
		cross_list: number;
		recent_traces: number;
		agent_name_chars: number;
	};
	fallback: { kind: "monogram" };
	makers: (Mark & { id: string; label: string })[];
	agents: (Mark & {
		id: string;
		label: string;
		maker?: string;
		kind: string;
	})[];
	models: {
		family: string;
		match: string;
		maker: string;
		label: string;
		avatar: { kind: "motif" | "maker_mark"; glyph?: string };
	}[];
};
export const catalog = catalogData as Catalog;
const modelPatterns = catalog.models.map((model) => ({
	model,
	pattern: new RegExp(model.match),
}));

export type IdentityAvatarData = {
	kind: "monogram" | "motif" | "mark";
	letter: string;
	hue: number;
	glyph?: string;
	src?: string;
};
export type IdentityRef = {
	kind: IdentityKind | "provider";
	key: string;
	rawKey: string;
	label: string;
	known: boolean;
	makerId?: string;
	makerLabel?: string;
	providerId?: string;
	description?: string;
	avatar: IdentityAvatarData;
};

function text(value: unknown): string {
	return typeof value === "string" ? value.trim() : "";
}
export function normalizeAgent(value: string): string {
	return Array.from(value.trim().toLowerCase())
		.slice(0, catalog.limits.agent_name_chars)
		.join("");
}
export const MODEL_DATE_SUFFIX = /-(?:\d{8}|\d{4}-\d{2}-\d{2})$/;
export function normalizeModel(value: string): string {
	return value
		.trim()
		.toLowerCase()
		.replace(/^([^/]+\/)+/, "")
		.replace(MODEL_DATE_SUFFIX, "");
}
export function encodeIdentityKey(kind: IdentityKind, key: string): string {
	if (!key) return kind === "agent" ? "~direct" : "~unidentified";
	return key.startsWith("~") || key === "." || key === ".." ? `~${key}` : key;
}
export function decodeIdentityKey(kind: IdentityKind, key: string): string {
	if (key === (kind === "agent" ? "~direct" : "~unidentified")) return "";
	return key.startsWith("~~") || key === "~." || key === "~.."
		? key.slice(1)
		: key;
}

function avatar(id: string, label: string, mark?: Mark): IdentityAvatarData {
	let hash = 2166136261;
	for (const char of id) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
	const base = {
		letter: Array.from(label.trim())[0]?.toUpperCase() || "?",
		hue: (hash >>> 0) % 360,
	};
	return mark?.mark && mark.mark_source && mark.mark_license
		? { ...base, kind: "mark", src: `/kya/${mark.mark}` }
		: { ...base, kind: "monogram" };
}

/** Catalog labels never decide the provider: that is a separate observed signal. */
export function identityForKey(
	kind: IdentityKind,
	encodedKey: string,
): IdentityRef {
	const key = decodeIdentityKey(kind, encodedKey);
	const agent =
		kind === "agent"
			? catalog.agents.find((entry) => entry.id === key)
			: undefined;
	const model =
		kind === "model"
			? modelPatterns.find(({ pattern }) => pattern.test(key))?.model
			: undefined;
	const makerId = agent?.maker ?? model?.maker;
	const maker = catalog.makers.find((entry) => entry.id === makerId);
	const label =
		agent?.label ??
		model?.label ??
		(key || (kind === "agent" ? "Direct API calls" : "Unidentified model"));
	const face = avatar(key || label, label, agent?.mark ? agent : maker);
	if (model?.avatar.kind === "motif") {
		face.kind = "motif";
		face.glyph = model.avatar.glyph;
		face.hue = avatar(makerId ?? key, label).hue;
	}
	return {
		kind,
		key: encodedKey,
		rawKey: key,
		label,
		known: Boolean(agent || model || !key),
		makerId,
		makerLabel: maker?.label,
		description:
			agent?.kind ?? (kind === "agent" && !key ? "No agent named" : undefined),
		avatar: face,
	};
}

export function providerIdentity(key: string): IdentityRef {
	const provider = PROVIDERS.find((entry) => entry.id === key);
	const label = provider?.label ?? (key || "Unknown provider");
	const maker = catalog.makers.find((entry) => entry.id === key);
	return {
		kind: "provider",
		key,
		rawKey: key,
		label,
		known: Boolean(provider),
		avatar: avatar(key, label, maker),
	};
}

/** The same normalized keys as the gateway aggregate; no network or storage. */
export function resolveIdentity(span: IdentitySignals): {
	agent: IdentityRef | null;
	model: IdentityRef | null;
} {
	const agentKey = normalizeAgent(
		text(span.gen_ai_agent_name) || text(span.tracelane_client_name),
	);
	const modelKey = normalizeModel(
		text(span.gen_ai_response_model) || text(span.gen_ai_request_model),
	);
	const model = modelKey
		? identityForKey("model", encodeIdentityKey("model", modelKey))
		: null;
	if (model)
		model.providerId =
			text(span.gen_ai_system) || text(span.gen_ai_provider_name) || undefined;
	return {
		agent: agentKey
			? identityForKey("agent", encodeIdentityKey("agent", agentKey))
			: null,
		model,
	};
}

export function identityHref(identity: IdentityRef): string {
	return `/agents/${identity.kind}/${encodeURIComponent(identity.key)}`;
}

/** Stored span attributes can be absent or malformed on historical rows. */
export function spanIdentity(attributes: string) {
	try {
		const value: unknown = JSON.parse(attributes);
		return resolveIdentity(
			value && typeof value === "object" ? (value as IdentitySignals) : {},
		);
	} catch {
		return resolveIdentity({});
	}
}
