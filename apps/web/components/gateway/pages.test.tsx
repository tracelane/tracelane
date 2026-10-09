// @vitest-environment jsdom
/**
 * OG-60 §4 states, rendered, for Spend alerts, Projects, Key policy, Security (admin
 * access + roles), Change log and the feature-detected slot page.
 */
import {
	cleanup,
	fireEvent,
	screen,
	waitFor,
	within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminAccess, RoleMatrix } from "./AdminAccess";
import { ChangeLog } from "./ChangeLog";
import { KeyPolicyManager } from "./KeyPolicyManager";
import { ProjectsManager } from "./ProjectsManager";
import { SlotView, scrub } from "./SlotView";
import { SpendAlerts } from "./SpendAlerts";
import { json, mockFetch, mount, openDialog, when } from "./test-utils";

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

const project = (over: Record<string, unknown> = {}) => ({
	id: "11111111-1111-4111-8111-111111111111",
	name: "checkout",
	environments: ["production", "staging"],
	policy: null,
	createdAt: "2026-10-01T00:00:00Z",
	updatedAt: "2026-10-02T00:00:00Z",
	...over,
});

describe("Spend alerts", () => {
	it("no channels says alerts go nowhere; empty events says when they fire", async () => {
		mockFetch(
			when("GET", "/controls/alert-channels", () => json({ channels: [] })),
			when("GET", "/controls/alert-events", () => json({ events: [] })),
		);
		mount(<SpendAlerts />);
		expect(await screen.findByText(/delivered nowhere/)).toBeTruthy();
		expect(await screen.findByText(/No alerts have fired yet/)).toBeTruthy();
	});

	it("a webhook's signing secret is shown once, after creation", async () => {
		const f = mockFetch(
			when("GET", "/controls/alert-channels", () => json({ channels: [] })),
			when("GET", "/controls/alert-events", () => json({ events: [] })),
			when("POST", "/controls/alert-channels", () =>
				json(
					{
						id: "c1",
						kind: "webhook",
						name: "pager",
						target: "https://hooks.example.com/x",
						createdAt: "2026-10-05T00:00:00Z",
						signingSecret: "whsec_ONLYONCE",
					},
					201,
				),
			),
		);
		mount(<SpendAlerts />);
		await screen.findByText(/delivered nowhere/);
		fireEvent.change(screen.getByLabelText("Kind"), {
			target: { value: "webhook" },
		});
		fireEvent.change(screen.getByLabelText("Name"), {
			target: { value: "pager" },
		});
		fireEvent.change(screen.getByLabelText(/^Target/), {
			target: { value: "https://hooks.example.com/x" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add channel" }));
		expect(await screen.findByText("whsec_ONLYONCE")).toBeTruthy();
		expect(f.calls.find((c) => c.method === "POST")?.body).toEqual({
			kind: "webhook",
			name: "pager",
			target: "https://hooks.example.com/x",
		});
	});

	it("shows the gateway's refusal of a bad target beside the field", async () => {
		mockFetch(
			when("GET", "/controls/alert-channels", () => json({ channels: [] })),
			when("GET", "/controls/alert-events", () => json({ events: [] })),
			when("POST", "/controls/alert-channels", () =>
				json(
					{
						error: "invalid_field",
						field: "target",
						message: "the URL must be https://",
					},
					400,
				),
			),
		);
		mount(<SpendAlerts />);
		await screen.findByText(/delivered nowhere/);
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "n" } });
		fireEvent.change(screen.getByLabelText(/^Target/), {
			target: { value: "http://x" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Add channel" }));
		await waitFor(() =>
			expect(
				screen.getAllByText("the URL must be https://").length,
			).toBeGreaterThan(0),
		);
	});

	it("deleting asks first, then sends DELETE; a viewer cannot", async () => {
		const ch = [
			{
				id: "c1",
				kind: "email",
				name: "oncall",
				target: "a@b.co",
				createdAt: "2026-10-05T00:00:00Z",
			},
		];
		const f = mockFetch(
			when("GET", "/controls/alert-channels", () => json({ channels: ch })),
			when("GET", "/controls/alert-events", () => json({ events: [] })),
			when(
				"DELETE",
				"/controls/alert-channels/c1",
				() => new Response(null, { status: 204 }),
			),
		);
		mount(<SpendAlerts />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Delete oncall" }),
		);
		expect(f.calls.some((c) => c.method === "DELETE")).toBe(false);
		fireEvent.click(
			within(openDialog()).getByRole("button", { name: "Delete channel" }),
		);
		await waitFor(() =>
			expect(f.calls.some((c) => c.method === "DELETE")).toBe(true),
		);
		cleanup();
		mockFetch(
			when("GET", "/controls/alert-channels", () => json({ channels: ch })),
			when("GET", "/controls/alert-events", () => json({ events: [] })),
		);
		mount(<SpendAlerts />, "viewer");
		expect(
			(
				(await screen.findByRole("button", {
					name: "Delete oncall",
				})) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
});

describe("Projects", () => {
	it("empty says what that means for keys", async () => {
		mockFetch(when("GET", "/projects", () => json({ projects: [] })));
		mount(<ProjectsManager />);
		expect(await screen.findByText(/every key stands alone/)).toBeTruthy();
	});

	it("a failed read is not 'no projects'", async () => {
		mockFetch(
			when("GET", "/projects", () => json({ error: "unavailable" }, 503)),
		);
		mount(<ProjectsManager />);
		expect(await screen.findByText(/Couldn't load projects/)).toBeTruthy();
		expect(screen.queryByText(/every key stands alone/)).toBeNull();
	});

	it("a deployment with no control plane says so (the route 404s)", async () => {
		mockFetch(
			when("GET", "/projects", () => new Response("{}", { status: 404 })),
		);
		mount(<ProjectsManager />);
		expect(
			await screen.findByText(/projects needs a control plane/),
		).toBeTruthy();
	});

	it("archive is typed-confirmed and surfaces the gateway's 'project has keys' refusal", async () => {
		const f = mockFetch(
			when("GET", "/projects", () => json({ projects: [project()] })),
			when("DELETE", `/projects/${project().id}`, () =>
				json(
					{
						error: "project_has_keys",
						message:
							"2 live key(s) still belong to this project — move or revoke them first",
					},
					409,
				),
			),
		);
		mount(<ProjectsManager />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Archive checkout" }),
		);
		const d = openDialog();
		const go = within(d).getByRole("button", {
			name: "Archive project",
		}) as HTMLButtonElement;
		expect(go.disabled).toBe(true);
		fireEvent.change(within(d).getByLabelText("Confirmation name"), {
			target: { value: "checkout" },
		});
		fireEvent.click(go);
		expect(
			await within(d).findByText(/2 live key\(s\) still belong/),
		).toBeTruthy();
		expect(f.calls.some((c) => c.method === "DELETE")).toBe(true);
	});

	it("creates with the typed name and environments", async () => {
		const f = mockFetch(
			when("GET", "/projects", () => json({ projects: [] })),
			when("POST", "/projects", () => json(project(), 201)),
		);
		mount(<ProjectsManager />);
		await screen.findByText(/every key stands alone/);
		fireEvent.change(screen.getByLabelText(/New project name/), {
			target: { value: "checkout" },
		});
		fireEvent.change(screen.getByLabelText(/^Environments/), {
			target: { value: "production, staging" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create project" }));
		await waitFor(() =>
			expect(f.calls.find((c) => c.method === "POST")?.body).toEqual({
				name: "checkout",
				environments: ["production", "staging"],
			}),
		);
	});

	it("editing a project's policy PATCHes only the policy; a developer cannot save", async () => {
		const f = mockFetch(
			when("GET", "/projects", () => json({ projects: [project()] })),
			when("PATCH", `/projects/${project().id}`, () => json(project())),
		);
		mount(<ProjectsManager />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Edit checkout" }),
		);
		fireEvent.change(within(openDialog()).getByLabelText("Requests / min"), {
			target: { value: "120" },
		});
		fireEvent.click(
			within(openDialog()).getByRole("button", { name: "Save project policy" }),
		);
		await waitFor(() =>
			expect(f.calls.find((c) => c.method === "PATCH")?.body).toEqual({
				policy: { limits: { rpm: 120 } },
			}),
		);
		cleanup();
		mockFetch(when("GET", "/projects", () => json({ projects: [project()] })));
		mount(<ProjectsManager />, "developer");
		fireEvent.click(
			await screen.findByRole("button", { name: "Edit checkout" }),
		);
		expect(
			(
				within(openDialog()).getByRole("button", {
					name: "Save project policy",
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
});

describe("Key policy", () => {
	const keys = [{ id: "k1", name: "ci-key", keyPrefix: "tlane_ab12" }];
	it("empty points at API Keys", async () => {
		mockFetch(
			(c) => (c.url === "/api/settings/api-keys" ? json([]) : undefined),
			when("GET", "/projects", () => json({ projects: [] })),
		);
		mount(<KeyPolicyManager />);
		expect(await screen.findByText(/No API keys yet/)).toBeTruthy();
	});

	it("PATCHes the key's policy through the key proxy, as typed", async () => {
		const f = mockFetch(
			(c) => (c.url === "/api/settings/api-keys" ? json(keys) : undefined),
			when("GET", "/projects", () => json({ projects: [project()] })),
			(c) =>
				c.url === "/api/settings/api-keys/k1" && c.method === "GET"
					? json({
							id: "k1",
							name: "ci-key",
							projectId: null,
							environment: null,
							policy: null,
						})
					: undefined,
			(c) =>
				c.url === "/api/settings/api-keys/k1" && c.method === "PATCH"
					? json({
							id: "k1",
							name: "ci-key",
							projectId: project().id,
							environment: "staging",
							policy: { max_output_tokens: 1000 },
						})
					: undefined,
		);
		mount(<KeyPolicyManager />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Policy for ci-key" }),
		);
		fireEvent.change(await screen.findByLabelText("Max output tokens"), {
			target: { value: "1000" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save key policy" }));
		await waitFor(() =>
			expect(f.calls.find((c) => c.method === "PATCH")?.body).toEqual({
				policy: { max_output_tokens: 1000 },
			}),
		);
		fireEvent.change(screen.getByLabelText("Project"), {
			target: { value: project().id },
		});
		fireEvent.change(screen.getByLabelText("Environment"), {
			target: { value: "staging" },
		});
		fireEvent.click(
			screen.getByRole("button", { name: "Save project and environment" }),
		);
		await waitFor(() =>
			expect(f.calls.filter((c) => c.method === "PATCH")[1]?.body).toEqual({
				projectId: project().id,
				environment: "staging",
			}),
		);
	});

	it("a retiring key is read-only and says why", async () => {
		mockFetch(
			(c) => (c.url === "/api/settings/api-keys" ? json(keys) : undefined),
			when("GET", "/projects", () => json({ projects: [] })),
			(c) =>
				c.url === "/api/settings/api-keys/k1"
					? json({
							id: "k1",
							name: "ci-key",
							projectId: null,
							environment: null,
							policy: null,
							revokedAt: "2026-10-09T00:00:00Z",
						})
					: undefined,
		);
		mount(<KeyPolicyManager />);
		fireEvent.click(
			await screen.findByRole("button", { name: "Policy for ci-key" }),
		);
		expect(await screen.findByText(/This key is retiring/)).toBeTruthy();
		expect(
			(
				screen.getByRole("button", {
					name: "Save key policy",
				}) as HTMLButtonElement
			).disabled,
		).toBe(true);
	});
});

describe("Security", () => {
	const access = (over: Record<string, unknown> = {}) => ({
		admin_ip_allowlist: [],
		sso_required: false,
		updated_at: null,
		updated_by: null,
		your_ip: "203.0.113.9",
		your_ip_attested: true,
		max_ip_allowlist_entries: 50,
		...over,
	});

	it("shows the address the gateway sees and whether it was attested", async () => {
		mockFetch(when("GET", "/security/admin-access", () => json(access())));
		mount(<AdminAccess />);
		expect(await screen.findByText("203.0.113.9")).toBeTruthy();
		expect(screen.getByText("attested by the dashboard")).toBeTruthy();
		expect(screen.getByText(/accepted from any address/)).toBeTruthy();
	});

	it("an unattested address is flagged, not trusted", async () => {
		mockFetch(
			when("GET", "/security/admin-access", () =>
				json(access({ your_ip_attested: false })),
			),
		);
		mount(<AdminAccess />);
		expect(await screen.findByText("not attested")).toBeTruthy();
	});

	it("a lock-out refusal offers a typed override that sends acknowledge_lockout", async () => {
		const f = mockFetch(
			when("GET", "/security/admin-access", () => json(access())),
			(c) =>
				c.method === "PUT" &&
				!(c.body as { acknowledge_lockout?: boolean }).acknowledge_lockout
					? json(
							{
								error: "would_lock_you_out",
								reason: "ip",
								message:
									"this allowlist does not include the address this request came from",
							},
							409,
						)
					: undefined,
			when("PUT", "/security/admin-access", () =>
				json(access({ admin_ip_allowlist: ["198.51.100.0/24"] })),
			),
		);
		mount(<AdminAccess />);
		fireEvent.change(await screen.findByLabelText(/Admin IP allowlist/), {
			target: { value: "198.51.100.0/24" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save access rules" }));
		expect(await screen.findByText(/would lock you out/)).toBeTruthy();
		fireEvent.click(screen.getByRole("button", { name: "Save anyway…" }));
		const d = openDialog();
		const go = within(d).getByRole("button", {
			name: "Save anyway",
		}) as HTMLButtonElement;
		expect(go.disabled).toBe(true);
		fireEvent.change(within(d).getByLabelText("Confirmation name"), {
			target: { value: "lock me out" },
		});
		fireEvent.click(go);
		await waitFor(() =>
			expect(f.calls.filter((c) => c.method === "PUT").length).toBe(2),
		);
		expect(f.calls.filter((c) => c.method === "PUT")[1]?.body).toEqual({
			admin_ip_allowlist: ["198.51.100.0/24"],
			sso_required: false,
			acknowledge_lockout: true,
		});
	});

	it("'Add my address' appends the address as a /32", async () => {
		mockFetch(when("GET", "/security/admin-access", () => json(access())));
		mount(<AdminAccess />);
		fireEvent.click(
			await screen.findByRole("button", { name: /Add my address/ }),
		);
		expect(
			(screen.getByLabelText(/Admin IP allowlist/) as HTMLTextAreaElement)
				.value,
		).toBe("203.0.113.9/32");
	});

	it("a non-admin is told who may read it, not shown an empty form", async () => {
		mockFetch(
			when("GET", "/security/admin-access", () =>
				json({ error: "role_forbidden", required_role: "admin" }, 403),
			),
		);
		mount(<AdminAccess />, "developer");
		expect(
			await screen.findByText(/You can't view admin access rules/),
		).toBeTruthy();
		expect(screen.queryByLabelText(/Admin IP allowlist/)).toBeNull();
	});

	it("the role matrix renders every capability for every role from the generated mirror", () => {
		mount(<RoleMatrix />);
		expect(
			screen.getByLabelText("Owner / admin can manage controls"),
		).toBeTruthy();
		expect(screen.getByLabelText("Viewer cannot manage controls")).toBeTruthy();
		expect(screen.getByLabelText("Developer can mint keys")).toBeTruthy();
	});
});

describe("Change log", () => {
	const row = (id: number) => ({
		id,
		occurred_at: "2026-10-05T08:00:00Z",
		actor: "user_01",
		actor_role: "owner",
		actor_auth_method: "jwt",
		action: "workspace.pause",
		target_type: "workspace",
		target_id: "t1",
		before: { paused: false },
		after: { paused: true },
		ip: "203.0.113.9",
		user_agent: null,
		request_id: null,
	});

	it("unfiltered-empty and filtered-empty are different sentences", async () => {
		mockFetch(
			when("GET", "/audit/control-changes", () =>
				json({ items: [], next_cursor: null }),
			),
		);
		mount(<ChangeLog />);
		expect(
			await screen.findByText(/No control changes recorded yet/),
		).toBeTruthy();
		fireEvent.change(screen.getByLabelText(/^Action/), {
			target: { value: "x.y" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
		expect(
			await screen.findByText(/No changes match these filters/),
		).toBeTruthy();
	});

	it("a failed read is an error, not 'no changes'", async () => {
		mockFetch(
			when("GET", "/audit/control-changes", () =>
				json({ error: "control_audit_unavailable" }, 503),
			),
		);
		mount(<ChangeLog />);
		expect(
			await screen.findByText(/Couldn't load the control-change log/),
		).toBeTruthy();
		expect(screen.queryByText(/No control changes recorded yet/)).toBeNull();
	});

	it("sends the applied filters, pages by the gateway's cursor, and links the NDJSON download", async () => {
		const f = mockFetch((c) => {
			if (!c.url.includes("/audit/control-changes")) return undefined;
			return c.url.includes("cursor=2")
				? json({ items: [row(1)], next_cursor: null })
				: json({ items: [row(3), row(2)], next_cursor: 2 });
		});
		mount(<ChangeLog />);
		expect((await screen.findAllByText("workspace.pause")).length).toBe(2);
		fireEvent.click(screen.getByRole("button", { name: "Load older changes" }));
		await waitFor(() =>
			expect(screen.getAllByText("workspace.pause").length).toBe(3),
		);
		expect(screen.getByText("That is every matching change.")).toBeTruthy();
		expect(
			f.calls.some(
				(c) => c.url.includes("cursor=2") && c.url.includes("limit=50"),
			),
		).toBe(true);
		const dl = screen.getByRole("link", {
			name: /Download newest 500/,
		}) as HTMLAnchorElement;
		expect(dl.getAttribute("href")).toContain("format=ndjson");
		expect(screen.getAllByText("Oct 5, 2026 · 08:00 UTC").length).toBe(3);
	});
});

describe("Slot page", () => {
	// Routing is a whole-document editor: its slot stays read-only (the editors for cache
	// and OTel export are in `slot-editors.test.tsx`).
	const slot = {
		id: "routing",
		label: "Routing",
		probe: "routing",
		spec: "OG-11 / OG-12",
	};
	it("shows the route's live answer, scrubbed of anything credential-shaped", async () => {
		mockFetch(
			when("GET", "/routing", () =>
				json({
					enabled: true,
					headers: { Authorization: "Bearer abc" },
					apiKey: "sk-1",
					nested: { client_secret: "z", ttl: 4 },
				}),
			),
		);
		mount(<SlotView slot={slot} />);
		const pre = await screen.findByTestId("slot-json");
		expect(pre.textContent).toContain('"enabled": true');
		expect(pre.textContent).toContain('"ttl": 4');
		expect(pre.textContent).not.toMatch(/Bearer abc|sk-1|"z"/);
		expect(pre.textContent).toContain("[hidden]");
	});
	it("a route the gateway does not have says so; it never invents content", async () => {
		mockFetch(
			when("GET", "/routing", () => new Response("{}", { status: 404 })),
		);
		mount(<SlotView slot={slot} />);
		expect(
			await screen.findByText(/does not serve GET \/v1\/routing/),
		).toBeTruthy();
		expect(screen.queryByTestId("slot-json")).toBeNull();
	});
	it("scrub is depth- and length-bounded", () => {
		expect(
			(scrub(Array.from({ length: 80 }, (_, i) => i)) as number[]).length,
		).toBe(50);
	});
});
