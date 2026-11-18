import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { CONNECTION_PATHS, ConnectionPathPicker } from "./ConnectionPathPicker";

it("offers only documented first-trace integration routes", () => {
	expect(CONNECTION_PATHS.map((path) => path.href)).toEqual([
		"https://docs.tracelane.dev/quickstart",
		"https://docs.tracelane.dev/sdk-python",
		"https://docs.tracelane.dev/sdk-typescript",
		"https://docs.tracelane.dev/sdk-python",
	]);
});

it("distinguishes model-call gateway capture from SDK/OTLP and ledger events", () => {
	const html = renderToStaticMarkup(h(ConnectionPathPicker));
	expect(html).toContain("Want to capture more than a model call?");
	expect(html).toContain("not automatically chained");
	expect(html).toContain("ingest scope");
	expect(html).toContain("TypeScript SDK");
	expect(html).not.toContain("every agent step is automatically audited");
});

it("opens setup guides without losing reveal-once state", () => {
	const html = renderToStaticMarkup(h(ConnectionPathPicker));
	expect(html.match(/target="_blank"/g) ?? []).toHaveLength(4);
	expect(html.match(/rel="noopener noreferrer"/g) ?? []).toHaveLength(4);
	expect(html).toContain("OTLP/HTTP");
	expect(html).toContain("/v1/traces");
	expect(html).toContain("ingest-scoped key");
	expect(html).toContain(
		"The examples above route model calls through the gateway.",
	);
});
