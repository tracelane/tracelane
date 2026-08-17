/**
 * SET-26 — rendered proof that the email change is REACHABLE.
 *
 * The route handler tests prove the address moves. These prove the customer can
 * get at it: that Settings → Account actually renders the change form (not just
 * that a component file exists), that the submit is gated shut until all three
 * confirmations are typed, and that the endpoint the form posts to is backed by
 * a real route handler rather than a stale path.
 *
 * `renderToStaticMarkup` in the node env — same pattern as
 * `components/trace-viewer/transcript-spine-render.test.ts`.
 */

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
	EMAIL_CHANGE_ENDPOINT,
	canSubmitEmailChange,
} from "@/app/settings/account/email/validate";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { EmailChangeForm } from "./EmailChangeForm";
import { ProfileManager } from "./ProfileManager";

const h = createElement;
const EMAIL = "old@example.com";

const renderForm = (): string =>
	renderToStaticMarkup(h(EmailChangeForm, { email: EMAIL }));

/** ProfileManager uses react-query for the name/delete mutations, so it needs a
 * client in context; nothing else about it is mocked. */
const renderAccountUi = (): string =>
	renderToStaticMarkup(
		h(
			QueryClientProvider,
			{ client: new QueryClient() },
			h(ProfileManager, {
				initialName: "Ada",
				email: EMAIL,
				canDeleteOrg: false,
			}),
		),
	);

describe("SET-26 — the endpoint the form talks to exists", () => {
	it("resolves to a real route handler, so the button cannot post into a 404", () => {
		const routeFile = fileURLToPath(
			new URL(`../../app${EMAIL_CHANGE_ENDPOINT}/route.ts`, import.meta.url),
		);
		expect(existsSync(routeFile), routeFile).toBe(true);
	});
});

describe("SET-26 — Settings → Account offers the change", () => {
	it("no longer tells the customer their email is read-only", () => {
		const html = renderAccountUi();
		expect(html).not.toContain("not yet self-serve");
		expect(html).toContain("Change email");
	});

	it("renders the change form inside the account UI, not just standalone", () => {
		const html = renderAccountUi();
		expect(html).toContain('data-testid="email-change"');
		expect(html).toContain('id="new-email"');
		expect(html).toContain('id="new-email-confirm"');
		expect(html).toContain('id="current-email-confirm"');
	});

	it("still renders the existing name form and danger zone — nothing displaced", () => {
		const html = renderAccountUi();
		expect(html).toContain('id="profile-name"');
		expect(html).toContain("Delete my account");
	});
});

describe("SET-26 — the form asks for three confirmations and starts locked", () => {
	const html = renderForm();

	it("ships the button disabled on an empty form", () => {
		expect(html).toContain("Change email</button>");
		// the submit is rendered `disabled` before anything is typed
		expect(html).toMatch(/<button[^>]*disabled[^>]*>Change email<\/button>/);
	});

	it("labels all three fields so the confirmations are not guesswork", () => {
		expect(html).toContain("New email");
		expect(html).toContain("New email again");
		expect(html).toContain("Type your current email to confirm");
	});

	it("states that the new address must be verified before it is trusted", () => {
		expect(html).toContain("must be verified before it is trusted");
	});

	it("does not prefill the current address into a confirmation field", () => {
		// It appears as a placeholder hint only — prefilling would defeat the
		// point of asking the customer to type it.
		expect(html).toContain(`placeholder="${EMAIL}"`);
		expect(html).not.toContain(`value="${EMAIL}"`);
	});
});

describe("SET-26 — the client gate agrees with the server, in both directions", () => {
	const base = {
		currentEmail: EMAIL,
		newEmail: "new@example.com",
		confirmEmail: "new@example.com",
		confirmCurrentEmail: EMAIL,
	};

	it("stays locked until every field is right", () => {
		expect(canSubmitEmailChange({ ...base, newEmail: "" })).toBe(false);
		expect(canSubmitEmailChange({ ...base, confirmEmail: "" })).toBe(false);
		expect(canSubmitEmailChange({ ...base, confirmCurrentEmail: "" })).toBe(
			false,
		);
		expect(
			canSubmitEmailChange({ ...base, confirmEmail: "nwe@example.com" }),
		).toBe(false);
		expect(
			canSubmitEmailChange({
				...base,
				confirmCurrentEmail: "other@example.com",
			}),
		).toBe(false);
		expect(canSubmitEmailChange({ ...base, newEmail: "nope" })).toBe(false);
		// a no-op change
		expect(
			canSubmitEmailChange({
				...base,
				newEmail: EMAIL,
				confirmEmail: EMAIL,
			}),
		).toBe(false);
	});

	it("unlocks on a complete, well-formed change", () => {
		expect(canSubmitEmailChange(base)).toBe(true);
	});
});
