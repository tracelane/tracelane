import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

// These editor-only messages must be in browser chunks, not the OpenNext server
// handler that /sign-in loads on its first request.
const messages = [
	"Each virtual model needs",
	"A locked rail cannot be changed",
];
const handler = readFileSync(
	".open-next/server-functions/default/apps/web/handler.mjs",
	"utf8",
);
const clientChunks = readdirSync(".next/static/chunks")
	.filter((name) => name.endsWith(".js"))
	.map((name) => readFileSync(join(".next/static/chunks", name), "utf8"));

for (const message of messages) {
	if (handler.includes(message)) {
		throw new Error(
			`Editor code entered the shared Worker handler: ${message}`,
		);
	}
	if (!clientChunks.some((chunk) => chunk.includes(message))) {
		throw new Error(`Editor code missing from browser chunks: ${message}`);
	}
}

console.log("[editor-isolation] OK — editors are in browser chunks only");
