/**
 * The portal error the user sees. Security review of #233 (L1): the gateway refuses an admin
 * on an SSO-required workspace with `error: "sso_required"` and a readable `message`, while the
 * route uses the SAME code (with `upgrade_url`) for "your plan lacks SSO". The UI showed the raw
 * code for the gateway case, so an admin could not tell "upgrade" from "sign in through SSO".
 */
import { beforeEach, expect, it, vi } from "vitest";

const res = vi.hoisted(() => ({ body: {} as unknown, status: 403 }));
vi.mock("@/lib/api-fetch", () => ({
	apiFetchRaw: vi.fn(async () => ({
		ok: false,
		status: res.status,
		json: async () => res.body,
	})),
}));

import { PortalUpgradeError, openPortal } from "./WorkspaceManager";

beforeEach(() => {
	res.status = 403;
});

it("a plan without SSO still routes to the upgrade page", async () => {
	res.body = { error: "sso_required", upgrade_url: "/settings/billing" };
	await expect(openPortal("sso")).rejects.toBeInstanceOf(PortalUpgradeError);
});

it("the gateway's SSO-session refusal shows its message, not the raw code", async () => {
	res.body = {
		error: "sso_required",
		message:
			"this workspace requires single sign-on for admin actions — sign in through your identity provider and retry",
	};
	const err = await openPortal("sso").catch((e: unknown) => e);
	expect(err).not.toBeInstanceOf(PortalUpgradeError);
	expect((err as Error).message).toMatch(
		/sign in through your identity provider/,
	);
});

it("a refusal with no message falls back to the code", async () => {
	res.body = { error: "ip_not_allowed" };
	await expect(openPortal("sso")).rejects.toThrow("ip_not_allowed");
});
