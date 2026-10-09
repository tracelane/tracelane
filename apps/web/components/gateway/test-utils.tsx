/**
 * Shared harness for the Gateway settings render tests: a fresh query client, the role
 * context, a scripted `fetch` (the control relay), and the `<dialog>` shim jsdom lacks.
 * Test-only — not imported by any page.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { vi } from "vitest";
import { RoleProvider } from "./control";

Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
	configurable: true,
	value: function (this: HTMLDialogElement) {
		this.setAttribute("open", "");
	},
});
Object.defineProperty(HTMLDialogElement.prototype, "close", {
	configurable: true,
	value: function (this: HTMLDialogElement) {
		this.removeAttribute("open");
	},
});

export const json = (data: unknown, status = 200) =>
	new Response(data === null ? null : JSON.stringify(data), {
		status,
		headers: { "content-type": "application/json" },
	});

export type Call = { url: string; method: string; body: unknown };
type Handler = (c: Call) => Response | Promise<Response> | undefined;

/** Install a scripted fetch; the first handler returning a Response wins. */
export function mockFetch(...handlers: Handler[]) {
	const calls: Call[] = [];
	const f = vi.fn(async (input: string | URL, init?: RequestInit) => {
		const call: Call = {
			url: String(input),
			method: init?.method ?? "GET",
			body: init?.body ? JSON.parse(String(init.body)) : undefined,
		};
		calls.push(call);
		for (const h of handlers) {
			const r = await h(call);
			if (r) return r;
		}
		return json({ error: "unscripted" }, 500);
	});
	vi.stubGlobal("fetch", f);
	return { calls, fetch: f };
}

/** Match `METHOD path-suffix` (the relay prefix is ignored). */
export const when =
	(method: string, pathEnd: string, res: () => Response): Handler =>
	(c) =>
		c.method === method && c.url.split("?")[0]?.endsWith(pathEnd)
			? res()
			: undefined;

export function mount(ui: ReactNode, role: string | null = "owner") {
	const client = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	return render(
		<QueryClientProvider client={client}>
			<RoleProvider role={role}>{ui}</RoleProvider>
		</QueryClientProvider>,
	);
}

/** The one `<dialog>` that is open (every ConfirmDialog keeps its shell in the DOM). */
export function openDialog(): HTMLElement {
	const d = document.querySelector("dialog[open]");
	if (!d) throw new Error("no dialog is open");
	return d as HTMLElement;
}
