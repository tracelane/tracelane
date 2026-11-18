import { getRedirectError } from "next/dist/client/components/redirect";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ signOut: vi.fn(), session: true }));
vi.mock("@workos-inc/authkit-nextjs", () => ({ signOut: h.signOut }));
import { GET, POST } from "./route";
const origin = "https://app.example.test";
const logout =
	"https://api.workos.com/user_management/sessions/logout?session_id=synthetic";
beforeEach(() => {
	vi.stubEnv("NEXT_PUBLIC_WORKOS_REDIRECT_URI", `${origin}/auth/callback`);
	h.session = true;
	h.signOut.mockImplementation(async () => {
		h.session = false;
		throw getRedirectError(logout, "replace");
	});
});
afterEach(() => vi.unstubAllEnvs());
function post(value: string | null = origin) {
	return POST(
		new Request(`${origin}/sign-out`, {
			method: "POST",
			headers: value === null ? {} : { Origin: value },
		}),
	);
}
async function refused(value: string | null) {
	expect((await post(value)).status).toBe(403);
	expect(h.signOut).not.toHaveBeenCalled();
	expect(h.session).toBe(true);
}
it("post_same_origin_clears_session", async () => {
	expect((await post()).status).toBe(200);
	expect(h.session).toBe(false);
	expect(h.signOut).toHaveBeenCalledWith({ returnTo: `${origin}/sign-in` });
});
it("post_returns_workos_logout_url", async () => {
	const r = await post();
	expect(await r.json()).toEqual({ logout_url: logout });
	expect(r.headers.get("cache-control")).toBe("no-store");
});
it("post_without_session_returns_sign_in", async () => {
	h.signOut.mockImplementation(async () => {
		throw getRedirectError(`${origin}/sign-in`, "replace");
	});
	expect(await (await post()).json()).toEqual({ logout_url: "/sign-in" });
});
it("get_renders_confirm_page", () => {
	const r = GET();
	expect(r.status).toBe(303);
	expect(r.headers.get("location")).toBe("/sign-out/confirm");
});
it("get_does_not_clear_session", () => {
	expect(GET().headers.has("set-cookie")).toBe(false);
	expect(h.session).toBe(true);
});
it("get_does_not_call_sign_out", () => {
	GET();
	expect(h.signOut).not.toHaveBeenCalled();
});
it("post_cross_origin_refused", () => refused("https://evil.test"));
it("post_missing_origin_refused", () => refused(null));
it("post_null_origin_refused", () => refused("null"));
it("post_lookalike_origin_refused", () => refused(`${origin}.evil.test`));
it("post_http_origin_refused", () => refused("http://app.example.test"));
it("invalid_configuration_fails_closed", async () => {
	vi.stubEnv("NEXT_PUBLIC_WORKOS_REDIRECT_URI", "bad");
	expect((await post()).status).toBe(503);
	expect(h.signOut).not.toHaveBeenCalled();
});
it("unexpected_sdk_error_is_generic", async () => {
	h.signOut.mockRejectedValue(new Error("private detail"));
	const r = await post();
	expect(r.status).toBe(503);
	expect(await r.text()).not.toContain("private detail");
});
