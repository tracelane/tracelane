import { spawnSync } from "node:child_process";
import {
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { type Server, createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { importHeliconeTraces } from "../src/commands/import-helicone.js";

let dir: string;
let server: Server;
let endpoint: string;
interface Payload {
	resourceSpans: {
		scopeSpans: {
			spans: {
				startTimeUnixNano: string;
				endTimeUnixNano: string;
				attributes: unknown[];
			}[];
		}[];
	}[];
}
let received: Payload[];
let failAt: number;
const request = (id: string) => ({
	request_id: id,
	request_created_at: "2026-09-21T12:00:00.000Z",
	response_created_at: "2026-09-21T12:00:00.250Z",
	response_status: 200,
	provider: "OPENAI",
	request_model: "gpt-4o-mini",
	prompt_tokens: 7,
	completion_tokens: 3,
	request_body: { messages: [{ role: "user", content: "hello" }] },
	response_body: { choices: [{ message: { content: "world" } }] },
	auth_hash: "do-not-export",
});
const opts = () => ({
	traces: join(dir, "history.json"),
	cursor: join(dir, "cursor.json"),
	endpoint,
	apiKey: "local-key",
});
beforeEach(async () => {
	dir = mkdtempSync(join(tmpdir(), "helicone-history-"));
	received = [];
	failAt = -1;
	server = createServer(async (req, res) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		expect(req.headers.authorization).toBe("Bearer local-key");
		expect(req.url).toBe("/v1/traces");
		if (received.length === failAt) {
			res.writeHead(503).end();
			return;
		}
		received.push(JSON.parse(body));
		res.writeHead(200, { "content-type": "application/json" }).end("{}");
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (!address || typeof address === "string") throw Error("no server");
	endpoint = `http://127.0.0.1:${address.port}`;
	writeFileSync(
		opts().traces,
		JSON.stringify({
			data: [
				request("one"),
				request("two"),
				request("one"),
				{ request_id: "bad" },
			],
			error: null,
		}),
	);
});
afterEach(async () => {
	await new Promise<void>((resolve) => server.close(() => resolve()));
	rmSync(dir, { recursive: true, force: true });
});
it("dry run counts agree with sends, preserve history, and resume sends nothing twice", async () => {
	const preview = await importHeliconeTraces({ ...opts(), dryRun: true });
	expect(preview).toEqual({
		imported: 2,
		skipped: 2,
		reasons: { duplicate_request_id: 1, invalid_timestamp: 1 },
	});
	expect(received).toHaveLength(0);
	expect(existsSync(opts().cursor)).toBe(false);
	expect(await importHeliconeTraces(opts())).toEqual(preview);
	expect(received).toHaveLength(2);
	const span = received[0].resourceSpans[0].scopeSpans[0].spans[0];
	expect(span.startTimeUnixNano).toBe(
		String(BigInt(Date.parse(request("one").request_created_at)) * 1000000n),
	);
	expect(span.endTimeUnixNano).toBe(
		String(BigInt(Date.parse(request("one").response_created_at)) * 1000000n),
	);
	expect(span.attributes).toContainEqual({
		key: "gen_ai.usage.input_tokens",
		value: { intValue: "7" },
	});
	expect(JSON.stringify(received)).toContain("hello");
	expect(JSON.stringify(received)).not.toContain("do-not-export");
	expect(await importHeliconeTraces(opts())).toEqual({
		imported: 0,
		skipped: 4,
		reasons: { already_processed: 4 },
	});
	expect(received).toHaveLength(2);
});
it("keeps the failed request at the cursor, resumes after failure, and has stable IDs", async () => {
	failAt = 1;
	await expect(importHeliconeTraces(opts())).rejects.toThrow("HTTP 503");
	expect(JSON.parse(readFileSync(opts().cursor, "utf8")).next).toBe(1);
	failAt = -1;
	const result = await importHeliconeTraces(opts());
	expect(result.imported).toBe(1);
	expect(received).toHaveLength(2);
	const original = received.map(
		(r) => r.resourceSpans[0].scopeSpans[0].spans[0],
	);
	rmSync(opts().cursor);
	await importHeliconeTraces(opts());
	expect(
		received.slice(2).map((r) => r.resourceSpans[0].scopeSpans[0].spans[0]),
	).toEqual(original);
});
it("refuses changed sources, destinations, credentials and corrupt cursors before sending", async () => {
	await importHeliconeTraces(opts());
	await expect(
		importHeliconeTraces({ ...opts(), apiKey: "other" }),
	).rejects.toThrow("cursor does not match");
	await expect(
		importHeliconeTraces({ ...opts(), endpoint: `${endpoint}/other` }),
	).rejects.toThrow();
	writeFileSync(opts().traces, "[]");
	await expect(importHeliconeTraces(opts())).rejects.toThrow(
		"cursor does not match",
	);
	writeFileSync(opts().cursor, '{"next":-1}');
	await expect(importHeliconeTraces(opts())).rejects.toThrow("cursor");
	expect(received).toHaveLength(2);
});
it("refuses concurrent imports and source errors without overwriting user files", async () => {
	writeFileSync(`${opts().cursor}.lock`, "owned elsewhere");
	await expect(importHeliconeTraces(opts())).rejects.toThrow("lock");
	expect(readFileSync(`${opts().cursor}.lock`, "utf8")).toBe("owned elsewhere");
	rmSync(`${opts().cursor}.lock`);
	writeFileSync(
		opts().traces,
		JSON.stringify({ error: "secret source error", data: null }),
	);
	await expect(importHeliconeTraces(opts())).rejects.toThrow("Helicone export");
	expect(received).toHaveLength(0);
});

it("reports invalid rows by reason without sending them", async () => {
	writeFileSync(
		opts().traces,
		JSON.stringify([
			null,
			{ ...request("bad-tokens"), prompt_tokens: -1 },
			{ ...request("bad-status"), response_status: 999 },
			{ ...request("reverse"), response_created_at: "2026-01-01T00:00:00Z" },
		]),
	);
	expect(await importHeliconeTraces(opts())).toEqual({
		imported: 0,
		skipped: 4,
		reasons: {
			missing_request_id: 1,
			invalid_tokens: 1,
			invalid_status: 1,
			invalid_timestamp: 1,
		},
	});
	expect(received).toHaveLength(0);
});

it("preserves fractional timestamps and accepts fractional millisecond durations", async () => {
	writeFileSync(
		opts().traces,
		JSON.stringify([
			{
				...request("precise"),
				request_created_at: "2026-09-21T12:00:00.123456789Z",
				response_created_at: "2026-09-21T12:00:00.234567890Z",
			},
			{
				...request("duration"),
				response_created_at: undefined,
				delay_ms: 250.5,
			},
		]),
	);
	expect((await importHeliconeTraces(opts())).imported).toBe(2);
	const first = received[0].resourceSpans[0].scopeSpans[0].spans[0];
	expect(first.startTimeUnixNano.endsWith("123456789")).toBe(true);
	expect(first.endTimeUnixNano.endsWith("234567890")).toBe(true);
	const second = received[1].resourceSpans[0].scopeSpans[0].spans[0];
	expect(
		BigInt(second.endTimeUnixNano) - BigInt(second.startTimeUnixNano),
	).toBe(250500000n);
	expect(first.attributes).toContainEqual({
		key: "tracelane.business_reference",
		value: { stringValue: "helicone:precise" },
	});
	expect(first.attributes).toContainEqual({
		key: "gen_ai.input.messages",
		value: {
			stringValue: JSON.stringify([
				{
					role: "user",
					parts: [
						{
							type: "text",
							content: JSON.stringify(request("precise").request_body),
						},
					],
				},
			]),
		},
	});
});

it("CLI exits 0 for dry-run and 1 for invalid export without printing its contents", () => {
	const args = [
		"--import",
		"tsx",
		"src/index.ts",
		"import-helicone",
		"--traces",
		opts().traces,
		"--endpoint",
		endpoint,
		"--dry-run",
	];
	const env = { ...process.env, TRACELANE_API_KEY: "local-key" };
	const good = spawnSync(process.execPath, args, { env, encoding: "utf8" });
	expect(good.status).toBe(0);
	expect(good.stdout).toContain("would import 2; skipped 2");
	writeFileSync(opts().traces, "secret malformed payload");
	const bad = spawnSync(process.execPath, args, { env, encoding: "utf8" });
	expect(bad.status).toBe(1);
	expect(bad.stderr).toContain("not valid JSON");
	expect(bad.stderr).not.toContain("secret malformed payload");
});
