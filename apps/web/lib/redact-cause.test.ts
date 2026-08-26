/**
 * The credential must not survive into a log line — proven against the REAL error
 * shapes `@neondatabase/serverless` produces, including the `postgresql:/`
 * single-slash form that defeated B-276's redactor.
 */
import { describe, expect, it } from "vitest";
import { causeLine, passwordOf, redactUserinfo } from "./redact-cause";

const PW = "S3cr3t-P4ssw0rd";
const URL_POOLED = `postgresql://neondb_owner:${PW}@ep-x-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require`;

describe("redactUserinfo", () => {
	it("strips userinfo from the driver's full connection-string echo", () => {
		const msg = `Database connection string provided to \`neon()\` is not a valid URL. Connection string: '${URL_POOLED}'`;
		expect(redactUserinfo(msg)).not.toContain(PW);
	});

	// B-276: the redactor matched only `://` while the error path had reformatted
	// the scheme to `postgresql:/`, so it walked past the credential.
	it("still strips when the scheme has ONE slash (the B-276 shape)", () => {
		expect(
			redactUserinfo(
				`Connection string: postgresql:/neondb_owner:${PW}@ep-x/neondb`,
			),
		).not.toContain(PW);
	});

	it("handles the postgres:// alias", () => {
		expect(
			redactUserinfo(`bad url: postgres://neondb_owner:${PW}@ep-x/neondb`),
		).not.toContain(PW);
	});

	it("leaves a credential-free message intact — the diagnostic must survive", () => {
		const msg = "password authentication failed for user 'neondb_owner'";
		expect(redactUserinfo(msg)).toBe(msg);
	});
});

describe("causeLine", () => {
	it("carries the real cause when there is no credential in it", () => {
		const line = causeLine(
			"neon",
			new Error("Error connecting to database: fetch failed"),
			URL_POOLED,
		);
		expect(line).toContain("fetch failed");
		expect(line).toContain("neon");
		expect(line).not.toContain("withheld");
	});

	it("keeps the class name so the fallthrough bucket is no longer all we have", () => {
		expect(causeLine("neon", new Error("boom"), URL_POOLED)).toContain(
			"Error:",
		);
	});

	// The second layer. If the pattern ever fails, the exact-value check must
	// withhold the message rather than log it — B-276 says the pattern alone is
	// not a control.
	it("WITHHOLDS the message when the credential survives redaction", () => {
		// A shape the userinfo pattern cannot see: the password alone, no `user:pass@`.
		const line = causeLine(
			"neon",
			new Error(`upstream said: ${PW}`),
			URL_POOLED,
		);
		expect(line).not.toContain(PW);
		expect(line).toContain("withheld");
	});

	it("withholds when the whole connection string appears without userinfo syntax", () => {
		const line = causeLine(
			"neon",
			new Error(`config was ${URL_POOLED}`),
			URL_POOLED,
		);
		expect(line).not.toContain(PW);
	});

	it("is safe when DATABASE_URL is absent entirely", () => {
		expect(
			causeLine("gateway", new Error("gateway /health 503"), undefined),
		).toContain("503");
	});
});

describe("passwordOf", () => {
	it("extracts from both slash forms and returns undefined for junk", () => {
		expect(passwordOf(URL_POOLED)).toBe(PW);
		expect(passwordOf(`postgresql:/u:${PW}@h/d`)).toBe(PW);
		expect(passwordOf(undefined)).toBeUndefined();
		expect(passwordOf("not-a-url")).toBeUndefined();
	});
});
