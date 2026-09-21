/**
 * B-473 (REV-3) — the HTTP transport is gateway-backed, always.
 *
 * Two properties, both refutable:
 *   1. `assertHttpTransportIsGatewayBacked` THROWS when `CLICKHOUSE_URL` is set
 *      and passes when it is not — the refusal names the reason.
 *   2. `http.ts` never references `createReader` — the mode switch that chose
 *      the scope-less direct reader is structurally absent from the HTTP path.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { assertHttpTransportIsGatewayBacked } from "./http.js";

describe("B-473: the HTTP MCP transport is gateway-backed", () => {
	it("refuses to start with CLICKHOUSE_URL set, naming the reason", () => {
		expect(() =>
			assertHttpTransportIsGatewayBacked({
				CLICKHOUSE_URL: "http://127.0.0.1:8123",
			}),
		).toThrow(/read.*scope|B-473/);
	});

	it("starts without CLICKHOUSE_URL", () => {
		expect(() =>
			assertHttpTransportIsGatewayBacked({
				TRACELANE_GATEWAY_URL: "https://gateway.example",
			}),
		).not.toThrow();
	});

	it("never selects a reader by mode — the HTTP server registers GatewayReader, not createReader()", () => {
		// vitest runs from the package directory (`pnpm test`); the source is read
		// as text so the structural property is asserted on the bytes that ship.
		const src = readFileSync(join(process.cwd(), "src", "http.ts"), "utf8")
			.split("\n")
			.filter(
				(l) =>
					!l.trimStart().startsWith("//") && !l.trimStart().startsWith("*"),
			)
			.join("\n");
		expect(src).not.toMatch(
			/registerTraceTools\(\s*server,\s*createReader\(\)/,
		);
		expect(src).not.toMatch(/import\s*\{[^}]*createReader[^}]*\}\s*from/);
		expect(src).toMatch(
			/registerTraceTools\(\s*server,\s*new GatewayReader\(\)/,
		);
	});
});
