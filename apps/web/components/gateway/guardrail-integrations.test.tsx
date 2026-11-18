// @vitest-environment jsdom
/**
 * Guardrail integrations (workspace guardrail hooks and their vendor adapters). Writes are
 * asserted on the body the gateway receives; a key is never rendered back.
 */
import {
	cleanup,
	fireEvent,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import plans from "../../db/plans.v3.json";
import {
	GuardrailIntegrations,
	type HookForm,
	buildHookUpload,
	emptyForm,
} from "./GuardrailIntegrations";
import { json, mockFetch, mount, openDialog, when } from "./test-utils";

/** A PUT to `guardrails/hooks/<generated id>`: the id is random, so match the prefix. */
const putHook = (res: () => Response) => (c: { method: string; url: string }) =>
	c.method === "PUT" &&
	/\/guardrails\/hooks\/[0-9a-f-]{36}$/.test(c.url.split("?")[0] ?? "")
		? res()
		: undefined;

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const limits = plans.policy.guardrail_hooks;
const KEY = "unit-test-vendor-key-do-not-use";
const SECRET = "unit-test-signing-secret-do-not-use-0123456789";
const form = (over: Partial<HookForm>): HookForm => ({
	...emptyForm,
	key: KEY,
	...over,
});
const upload = (f: HookForm) => {
	const r = buildHookUpload(f);
	if ("error" in r) throw new Error(r.error);
	return r;
};

const hook = (over: Record<string, unknown> = {}) => ({
	id: "11111111-1111-4111-8111-111111111111",
	config: {
		endpoint: "https://acme.cognitiveservices.azure.com",
		adapter: { kind: "azure_prompt_shields" },
		pre: true,
		post: false,
		timeout_ms: 2000,
		fail_mode: "closed",
		...over,
	},
	updated_at: "2026-11-16T08:00:00Z",
	credential_configured: true,
});

describe("buildHookUpload", () => {
	it("builds a Lakera upload with the fixed destination", () => {
		const r = upload(form({ kind: "lakera" }));
		expect(r.body).toEqual({
			config: {
				endpoint: "https://api.lakera.ai/v2/guard",
				adapter: { kind: "lakera" },
				pre: true,
				post: false,
				timeout_ms: 2000,
				fail_mode: "closed",
			},
			api_key: KEY,
		});
		expect(r.id).toMatch(/^[0-9a-f-]{36}$/);
	});
	it("builds an OpenAI Moderation upload with the fixed destination", () => {
		const r = upload(form({ kind: "openai_moderation", post: true }));
		expect(r.body.config).toMatchObject({
			endpoint: "https://api.openai.com/v1/moderations",
			adapter: { kind: "openai_moderation" },
			pre: true,
			post: true,
		});
	});
	it("builds an Azure Content Safety upload from the resource name and thresholds", () => {
		const r = upload(
			form({
				kind: "azure_content_safety",
				resource: "acme-prod",
				thresholds: { Hate: 2, SelfHarm: 4, Sexual: 6, Violence: 0 },
			}),
		);
		expect(r.body.config).toMatchObject({
			endpoint: "https://acme-prod.cognitiveservices.azure.com",
			adapter: {
				kind: "azure_content_safety",
				thresholds: { Hate: 2, SelfHarm: 4, Sexual: 6, Violence: 0 },
			},
		});
	});
	it("builds a Prompt Shields upload that runs before the model only", () => {
		const r = upload(
			form({ kind: "azure_prompt_shields", resource: "acme", post: true }),
		);
		expect(r.body.config).toMatchObject({
			endpoint: "https://acme.cognitiveservices.azure.com",
			adapter: { kind: "azure_prompt_shields" },
			pre: true,
			post: false,
		});
	});
	it("builds a custom endpoint upload with a signing secret", () => {
		const r = upload(
			form({
				kind: "custom",
				endpoint: "https://guard.example.com/check",
				key: SECRET,
				failMode: "open",
			}),
		);
		expect(r.body).toEqual({
			config: {
				endpoint: "https://guard.example.com/check",
				pre: true,
				post: false,
				timeout_ms: 2000,
				fail_mode: "open",
			},
			signing_secret: SECRET,
		});
	});
	it("refuses an Azure resource name that is not one label", () => {
		for (const resource of ["", "a.b", "Acme", "-acme", "acme_x", "x"]) {
			expect(
				buildHookUpload(form({ kind: "azure_prompt_shields", resource })),
				resource,
			).toHaveProperty("error");
		}
	});
	it("refuses a signing secret shorter than the minimum", () => {
		const short = "s".repeat(limits.min_secret_bytes - 1);
		expect(
			buildHookUpload(
				form({ kind: "custom", endpoint: "https://g.example.com", key: short }),
			),
		).toHaveProperty("error");
	});
	it("refuses a custom endpoint that is not https", () => {
		for (const endpoint of [
			"http://g.example.com",
			"g.example.com",
			"https://u:p@g.example.com",
			"https://g.example.com/?q=1",
		]) {
			expect(
				buildHookUpload(form({ kind: "custom", endpoint, key: SECRET })),
				endpoint,
			).toHaveProperty("error");
		}
	});
	it("refuses a timeout outside the allowed range", () => {
		for (const timeout of ["0", String(limits.timeout_ms + 1), "abc", ""]) {
			expect(
				buildHookUpload(form({ kind: "lakera", timeout })),
				timeout,
			).toHaveProperty("error");
		}
		expect(
			buildHookUpload(
				form({ kind: "lakera", timeout: String(limits.timeout_ms) }),
			),
		).not.toHaveProperty("error");
	});
	it("refuses an integration that runs at neither point", () => {
		expect(
			buildHookUpload(form({ kind: "lakera", pre: false, post: false })),
		).toHaveProperty("error");
		expect(
			buildHookUpload(
				form({
					kind: "azure_prompt_shields",
					resource: "acme",
					pre: false,
					post: true,
				}),
			),
		).toHaveProperty("error");
	});
	it("refuses an empty key", () => {
		expect(buildHookUpload(form({ kind: "lakera", key: "  " }))).toHaveProperty(
			"error",
		);
	});
});

describe("GuardrailIntegrations", () => {
	it("lists connected integrations with destination host, phases and failure setting", async () => {
		mockFetch(
			when("GET", "/guardrails/hooks", () =>
				json({
					hooks: [
						hook(),
						hook({
							id: "x",
							endpoint: "https://guard.example.com/check",
							adapter: undefined,
							post: true,
							fail_mode: "open",
						}),
					],
				}),
			),
		);
		mount(<GuardrailIntegrations />);
		const table = within(await screen.findByRole("table"));
		expect(table.getByText("Azure Prompt Shields")).toBeTruthy();
		expect(table.getByText("acme.cognitiveservices.azure.com")).toBeTruthy();
		expect(table.getByText("Your own endpoint")).toBeTruthy();
		expect(table.getByText("guard.example.com/check")).toBeTruthy();
		expect(
			table.getByText("Before the model, after the response"),
		).toBeTruthy();
		expect(table.getByText("Allow")).toBeTruthy();
		expect(table.getByText("Block")).toBeTruthy();
		expect(screen.getByText(`2 of ${limits.max_hooks} connected`)).toBeTruthy();
	});

	it("empty state explains built-in rails still run and offers the form", async () => {
		mockFetch(when("GET", "/guardrails/hooks", () => json({ hooks: [] })));
		mount(<GuardrailIntegrations />);
		expect(
			await screen.findByText(
				/No guardrail integrations. Built-in rails still run./,
			),
		).toBeTruthy();
		expect(
			screen.getByRole("button", { name: "Add integration" }),
		).toBeTruthy();
		// The failure setting must not promise a block it does not deliver.
		expect(
			screen.getByText(/error responses follow this setting/),
		).toBeTruthy();
		expect(document.body.textContent).not.toMatch(
			/wrong or unreadable answer always blocks/,
		);
	});

	it("adds an integration with one PUT and never shows the key again", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/hooks", () => json({ hooks: [] })),
			putHook(() =>
				json({ id: "1", config: hook().config, credential_configured: true }),
			),
		);
		mount(<GuardrailIntegrations />);
		fireEvent.change(await screen.findByLabelText(/^Integration/), {
			target: { value: "openai_moderation" },
		});
		fireEvent.change(screen.getByLabelText(/^API key/), {
			target: { value: KEY },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add integration" }));
		await waitFor(() =>
			expect(calls.some((c) => c.method === "PUT")).toBe(true),
		);
		const put = calls.filter((c) => c.method === "PUT");
		expect(put).toHaveLength(1);
		expect(put[0]?.body).toMatchObject({
			config: { adapter: { kind: "openai_moderation" } },
			api_key: KEY,
		});
		await waitFor(() =>
			expect(
				(screen.getByLabelText(/^API key/) as HTMLInputElement).value,
			).toBe(""),
		);
		expect(document.body.textContent).not.toContain(KEY);
	});

	it("deletes an integration after confirmation", async () => {
		const { calls } = mockFetch(
			when("GET", "/guardrails/hooks", () => json({ hooks: [hook()] })),
			when(
				"DELETE",
				"/guardrails/hooks/11111111-1111-4111-8111-111111111111",
				() => new Response(null, { status: 204 }),
			),
		);
		mount(<GuardrailIntegrations />);
		fireEvent.click(
			await screen.findByRole("button", {
				name: "Remove Azure Prompt Shields",
			}),
		);
		expect(calls.some((c) => c.method === "DELETE")).toBe(false);
		fireEvent.click(
			within(openDialog()).getByRole("button", { name: "Remove integration" }),
		);
		await waitFor(() =>
			expect(calls.some((c) => c.method === "DELETE")).toBe(true),
		);
	});

	it("disables adding at the workspace limit", async () => {
		mockFetch(
			when("GET", "/guardrails/hooks", () =>
				json({
					hooks: Array.from({ length: limits.max_hooks }, (_, i) =>
						hook({ endpoint: `https://r${i}.cognitiveservices.azure.com` }),
					).map((h, i) => ({ ...h, id: `id-${i}` })),
				}),
			),
		);
		mount(<GuardrailIntegrations />);
		const add = (await screen.findByRole("button", {
			name: "Add integration",
		})) as HTMLButtonElement;
		expect(add.disabled).toBe(true);
		expect(screen.getByText(/limit of \d+ integrations/)).toBeTruthy();
	});

	it("read-only role cannot add or delete (the gateway refuses the read)", async () => {
		mockFetch(
			when("GET", "/guardrails/hooks", () =>
				json({ error: "forbidden", required_role: "admin" }, 403),
			),
		);
		mount(<GuardrailIntegrations />, "viewer");
		expect(await screen.findByText(/role/i)).toBeTruthy();
		expect(
			screen.queryByRole("button", { name: "Add integration" }),
		).toBeNull();
		expect(screen.queryByRole("button", { name: /^Remove / })).toBeNull();
	});

	it("keeps one id across a retry so a lost reply cannot create a second integration", async () => {
		let n = 0;
		const { calls } = mockFetch(
			when("GET", "/guardrails/hooks", () => json({ hooks: [] })),
			putHook(() =>
				n++ === 0 ? json({ error: "hook_write_failed" }, 503) : json({}),
			),
		);
		mount(<GuardrailIntegrations />);
		fireEvent.change(await screen.findByLabelText(/^API key/), {
			target: { value: KEY },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add integration" }));
		expect(
			await screen.findByText(/may or may not have been saved/),
		).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: "Add integration" }));
		await waitFor(() =>
			expect(calls.filter((c) => c.method === "PUT")).toHaveLength(2),
		);
		const [first, second] = calls.filter((c) => c.method === "PUT");
		expect(first?.url).toBe(second?.url);
	});

	it("refuses a signing secret with surrounding spaces instead of trimming it", () => {
		expect(
			buildHookUpload(
				form({
					kind: "custom",
					endpoint: "https://g.example.com",
					key: ` ${SECRET}`,
				}),
			),
		).toHaveProperty("error");
	});

	it("shows a plain sentence when the gateway refuses the destination", async () => {
		mockFetch(
			when("GET", "/guardrails/hooks", () => json({ hooks: [] })),
			putHook(() => json({ error: "invalid_hook_destination" }, 400)),
		);
		mount(<GuardrailIntegrations />);
		fireEvent.change(await screen.findByLabelText(/^Integration/), {
			target: { value: "lakera" },
		});
		fireEvent.change(screen.getByLabelText(/^API key/), {
			target: { value: KEY },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add integration" }));
		expect(
			await screen.findByText(/destination could not be reached safely/),
		).toBeTruthy();
		expect(document.body.textContent).not.toContain(KEY);
	});
});

const AWS_KEY = "UNITTESTKEYID0000:unit-test-secret-do-not-use";
const SA_KEY = JSON.stringify(
	{
		type: "service_account",
		project_id: "unit-test-project",
		client_email: "unit-test@unit-test-project.iam.gserviceaccount.com",
		private_key: "unit-test-not-a-key",
	},
	null,
	2,
);
const bedrock = (over: Partial<HookForm> = {}) =>
	form({
		kind: "bedrock_guardrails",
		region: "eu-central-1",
		guardrailId: "abc123",
		guardrailVersion: "1",
		key: AWS_KEY,
		...over,
	});
const armor = (over: Partial<HookForm> = {}) =>
	form({
		kind: "google_model_armor",
		project: "acme-prod",
		location: "europe-west4",
		template: "tl-default",
		key: SA_KEY,
		...over,
	});
const presidio = (over: Partial<HookForm> = {}) =>
	form({
		kind: "presidio",
		endpoint: "https://presidio.acme.example/analyze",
		language: "en",
		entities: "PERSON, LOCATION",
		threshold: "0.6",
		action: "redact",
		key: SECRET,
		...over,
	});

describe("buildHookUpload: Bedrock, Model Armor, Presidio", () => {
	it("builds a Bedrock upload on the regional endpoint", () => {
		const r = upload(bedrock({ post: true }));
		expect(r.body).toEqual({
			config: {
				endpoint: "https://bedrock-runtime.eu-central-1.amazonaws.com",
				adapter: {
					kind: "bedrock_guardrails",
					region: "eu-central-1",
					guardrail_id: "abc123",
					guardrail_version: "1",
				},
				pre: true,
				post: true,
				timeout_ms: 2000,
				fail_mode: "closed",
			},
			api_key: AWS_KEY,
		});
	});
	it("accepts a Bedrock DRAFT version", () => {
		expect(
			upload(bedrock({ guardrailVersion: "DRAFT" })).body.config,
		).toMatchObject({ adapter: { guardrail_version: "DRAFT" } });
	});
	it("refuses a bad Bedrock region, ID or version", () => {
		for (const over of [
			{ region: "eu-central" },
			{ region: "EU-central-1" },
			{ guardrailId: "ABC" },
			{ guardrailId: "a/b" },
			{ guardrailVersion: "1.0" },
			{ guardrailVersion: "draft" },
		])
			expect(
				buildHookUpload(bedrock(over)),
				JSON.stringify(over),
			).toHaveProperty("error");
	});
	it("refuses temporary or malformed AWS keys", () => {
		for (const key of [
			"ASIAUNITTESTKEY00:secret",
			"UNITTESTKEYID0000:secret:session-token",
			"no-colon-here",
			"lowercasekey00000:secret",
			"UNITTESTKEYID0000:",
		])
			expect(buildHookUpload(bedrock({ key })), key).toHaveProperty("error");
	});
	it("builds a Model Armor upload on the regional endpoint", () => {
		const r = upload(armor({ post: true }));
		expect(r.body).toMatchObject({
			config: {
				endpoint: "https://modelarmor.europe-west4.rep.googleapis.com",
				adapter: {
					kind: "google_model_armor",
					project: "acme-prod",
					location: "europe-west4",
					template: "tl-default",
				},
				post: true,
			},
			api_key: SA_KEY,
		});
	});
	it("refuses bad Model Armor project, location or template", () => {
		for (const over of [
			{ project: "Acme-prod" },
			{ project: "acme" },
			{ location: "europe-west" },
			{ location: "europe/west4" },
			{ template: "a:b" },
			{ template: "" },
		])
			expect(buildHookUpload(armor(over)), JSON.stringify(over)).toHaveProperty(
				"error",
			);
	});
	it("refuses a service-account key that is not Google's", () => {
		const sa = JSON.parse(SA_KEY);
		for (const key of [
			"not json",
			JSON.stringify({ ...sa, token_uri: "https://evil.example/token" }),
			JSON.stringify({ ...sa, private_key: "" }),
			JSON.stringify({ project_id: "p" }),
		])
			expect(buildHookUpload(armor({ key })), key).toHaveProperty("error");
		expect(
			upload(
				armor({
					key: JSON.stringify({
						...sa,
						token_uri: "https://oauth2.googleapis.com/token",
					}),
				}),
			),
		).toBeTruthy();
	});
	it("builds a Presidio upload with entities, threshold and action", () => {
		const r = upload(presidio({ action: "block", post: true }));
		expect(r.body).toEqual({
			config: {
				endpoint: "https://presidio.acme.example/analyze",
				adapter: {
					kind: "presidio",
					language: "en",
					entities: ["PERSON", "LOCATION"],
					score_threshold: 0.6,
					action: "block",
				},
				pre: true,
				post: true,
				timeout_ms: 2000,
				fail_mode: "closed",
			},
			api_key: SECRET,
		});
	});
	it("normalises the Presidio entity list", () => {
		expect(
			upload(presidio({ entities: " person,, Phone_Number ,LOCATION " })).body
				.config,
		).toMatchObject({
			adapter: { entities: ["PERSON", "PHONE_NUMBER", "LOCATION"] },
		});
	});
	it("forces Presidio to block when it fails", () => {
		expect(upload(presidio({ failMode: "open" })).body.config).toMatchObject({
			fail_mode: "closed",
		});
	});
	it("never sends a fail-open Presidio integration", () => {
		for (const over of [{}, { action: "block" as const }, { post: true }])
			expect(
				upload(presidio({ failMode: "open", ...over })).body.config.fail_mode,
			).toBe("closed");
	});
	it("refuses a Presidio URL that is not plain https", () => {
		for (const endpoint of [
			"http://presidio.acme.example/analyze",
			"https://presidio.acme.example:5002/analyze",
			"https://u:p@presidio.acme.example/analyze",
			"https://presidio.acme.example/analyze?x=1",
			"not a url",
		])
			expect(buildHookUpload(presidio({ endpoint })), endpoint).toHaveProperty(
				"error",
			);
	});
	it("refuses bad Presidio entity types", () => {
		for (const entities of [
			"",
			" , ",
			"P",
			"PERSON-NAME",
			"PERSON, PERSON",
			Array.from({ length: 33 }, (_, i) => `E_${"A".repeat(i + 1)}`).join(","),
		])
			expect(buildHookUpload(presidio({ entities })), entities).toHaveProperty(
				"error",
			);
	});
	it("refuses a Presidio threshold outside 0 to 1", () => {
		for (const threshold of ["-0.1", "1.5", "abc", ""])
			expect(
				buildHookUpload(presidio({ threshold })),
				threshold,
			).toHaveProperty("error");
	});
	it("refuses a Presidio token shorter than the minimum", () => {
		expect(buildHookUpload(presidio({ key: "short" }))).toHaveProperty("error");
		expect(limits.min_secret_bytes).toBeGreaterThan(5);
	});
	it("refuses a Presidio language that is not two letters", () => {
		for (const language of ["EN", "eng", "e", ""])
			expect(buildHookUpload(presidio({ language })), language).toHaveProperty(
				"error",
			);
	});
});

describe("GuardrailIntegrations: Bedrock, Model Armor, Presidio", () => {
	it("lists the new vendors by name", async () => {
		mockFetch(
			when("GET", "/guardrails/hooks", () =>
				json({
					hooks: [
						hook({
							endpoint: "https://bedrock-runtime.eu-central-1.amazonaws.com",
							adapter: { kind: "bedrock_guardrails" },
						}),
						hook({
							endpoint: "https://modelarmor.europe-west4.rep.googleapis.com",
							adapter: { kind: "google_model_armor" },
						}),
					],
				}),
			),
		);
		mount(<GuardrailIntegrations />);
		const table = within(await screen.findByRole("table"));
		expect(table.getByText("AWS Bedrock Guardrails")).toBeTruthy();
		expect(table.getByText("Google Cloud Model Armor")).toBeTruthy();
		expect(
			table.getByText("bedrock-runtime.eu-central-1.amazonaws.com"),
		).toBeTruthy();
	});
	it("shows a Presidio destination with its path", async () => {
		mockFetch(
			when("GET", "/guardrails/hooks", () =>
				json({
					hooks: [
						hook({
							endpoint: "https://presidio.acme.example/analyze",
							adapter: { kind: "presidio" },
						}),
					],
				}),
			),
		);
		mount(<GuardrailIntegrations />);
		const table = within(await screen.findByRole("table"));
		expect(table.getByText("Microsoft Presidio (self-hosted)")).toBeTruthy();
		expect(table.getByText("presidio.acme.example/analyze")).toBeTruthy();
	});
	it("takes a Model Armor key in a multi-line field", async () => {
		mockFetch(when("GET", "/guardrails/hooks", () => json({ hooks: [] })));
		mount(<GuardrailIntegrations />);
		fireEvent.change(await screen.findByLabelText(/^Integration/), {
			target: { value: "google_model_armor" },
		});
		expect(screen.getByLabelText(/^Service-account key \(JSON\)/).tagName).toBe(
			"TEXTAREA",
		);
		expect(screen.getByLabelText(/^Project/)).toBeTruthy();
		expect(screen.getByLabelText(/^Location/)).toBeTruthy();
		expect(screen.getByLabelText(/^Template/)).toBeTruthy();
	});
	it("shows Presidio's failure setting fixed to block", async () => {
		mockFetch(when("GET", "/guardrails/hooks", () => json({ hooks: [] })));
		mount(<GuardrailIntegrations />);
		fireEvent.change(await screen.findByLabelText(/^Integration/), {
			target: { value: "presidio" },
		});
		const fail = screen.getByLabelText(
			/^If the integration fails or times out/,
		) as HTMLSelectElement;
		expect(fail.disabled).toBe(true);
		expect(fail.value).toBe("closed");
		expect(
			screen.getByText(/personal-data screening always blocks/i),
		).toBeTruthy();
		// Never claims redactions come back.
		expect(document.body.textContent).not.toMatch(/restor/i);
	});
});
