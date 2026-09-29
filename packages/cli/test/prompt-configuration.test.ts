import { Command } from "commander";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
vi.mock("node:fs", () => ({
	readFileSync: () =>
		JSON.stringify({
			assertions: [{ kind: "contains", value: "hello" }],
			cases: [{ input: "hello" }],
		}),
}));
import { registerEvalCommand } from "../src/commands/eval.js";
import { registerPromptCommand } from "../src/commands/prompt.js";
let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
	fetchMock = vi
		.fn()
		.mockImplementation(
			async (url: string) =>
				new Response(
					JSON.stringify(
						url.endsWith("/evals")
							? { eval_run_id: "run" }
							: url.includes("/evals/")
								? {
										status: "passed",
										results: {
											cases: [{ score: 1, status: "passed" }],
											requested_cases: 1,
										},
									}
								: {
										prompt_version_id: "11111111-1111-4111-8111-111111111111",
										version_number: 1,
										content: "hello",
										sha256_hex: "a".repeat(64),
									},
					),
					{ status: 200 },
				),
		);
	vi.stubGlobal("fetch", fetchMock);
	vi.spyOn(process.stdout, "write").mockImplementation(() => true);
	vi.spyOn(console, "log").mockImplementation(() => {});
	vi.spyOn(console, "error").mockImplementation(() => {});
	vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});
it("show and diff inspect pointers, never cohort assignments", async () => {
	const program = new Command();
	registerPromptCommand(program);
	await program.parseAsync(
		["prompt", "show", "proof", "--env", "production", "--token", "test-token"],
		{ from: "user" },
	);
	expect(fetchMock.mock.calls[0]?.[0]).toContain(
		"/proof/configuration?env=production",
	);
	fetchMock.mockClear();
	await program.parseAsync(
		[
			"prompt",
			"diff",
			"proof",
			"--from-env",
			"production",
			"--to-env",
			"staging",
			"--token",
			"test-token",
		],
		{ from: "user" },
	);
	expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
		"http://localhost:8080/v1/prompts/proof/configuration?env=production",
		"http://localhost:8080/v1/prompts/proof/configuration?env=staging",
	]);
});
it("eval selects the configured environment version before starting its run", async () => {
	const program = new Command();
	registerEvalCommand(program);
	await program.parseAsync(
		[
			"eval",
			"run",
			"--prompt",
			"proof",
			"--env",
			"production",
			"--suite-file",
			"fixture.json",
			"--threshold",
			"0.8",
			"--token",
			"test-token",
		],
		{ from: "user" },
	);
	expect(fetchMock.mock.calls[0]?.[0]).toContain(
		"/proof/configuration?env=production",
	);
	expect(JSON.parse(fetchMock.mock.calls[1]?.[1].body).prompt_version_id).toBe(
		"11111111-1111-4111-8111-111111111111",
	);
});
