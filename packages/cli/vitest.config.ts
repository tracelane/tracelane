import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		// CLI tests spawn child processes; default 5s timeout is too tight
		// for first-run tsx compile + provider mock setup.
		testTimeout: 60_000,
		hookTimeout: 30_000,
	},
});
