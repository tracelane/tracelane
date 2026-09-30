// @vitest-environment jsdom
/**
 * Live traces status (2026-09-27, found by the page-by-page audit: the toggle read
 * "Reconnecting…" 20 of 20 samples). The stream route sends a `partial` frame, a `full`
 * frame and then CLOSES by design; EventSource reports that normal close as an `error`
 * event with no data and reconnects. A close right after a fresh `full` frame is the
 * healthy cycle and must keep the status "Live".
 */
import {
	act,
	cleanup,
	fireEvent,
	render,
	screen,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { LiveTraces } from "./LiveTraces";

vi.mock("next/navigation", () => ({
	useRouter: () => ({ refresh: vi.fn() }),
	useSearchParams: () => new URLSearchParams("issue=truncated&range=7d"),
}));

class FakeEventSource {
	static last: FakeEventSource | null = null;
	listeners = new Map<string, ((e: Event) => void)[]>();
	url: string;
	constructor(url: string) {
		this.url = url;
		FakeEventSource.last = this;
	}
	addEventListener(type: string, fn: (e: Event) => void) {
		this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
	}
	removeEventListener() {}
	close() {}
	emit(type: string, data?: string) {
		const e = new MessageEvent(type, data === undefined ? {} : { data });
		for (const fn of this.listeners.get(type) ?? []) fn(e);
	}
}

beforeEach(() => {
	vi.stubGlobal("EventSource", FakeEventSource);
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function turnOn() {
	render(
		<LiveTraces streamParams="">
			<p>static list</p>
		</LiveTraces>,
	);
	fireEvent.click(screen.getByRole("button", { name: /live/i }));
}

it("stays Live when the stream closes normally right after a fresh frame", () => {
	turnOn();
	const es = FakeEventSource.last as FakeEventSource;
	act(() =>
		es.emit("full", JSON.stringify({ rows: [], stale: false, servedAt: 0 })),
	);
	expect(screen.getByText(/^Live/)).toBeTruthy();
	// the route's normal end-of-stream close, surfaced by EventSource as a data-less error
	act(() => es.emit("error"));
	expect(screen.queryByText(/Reconnecting/i)).toBeNull();
	expect(screen.getByText(/^Live/)).toBeTruthy();
});

it("says Reconnecting when the connection drops before any fresh frame", () => {
	turnOn();
	const es = FakeEventSource.last as FakeEventSource;
	act(() => es.emit("error"));
	expect(screen.getByText(/Reconnecting/i)).toBeTruthy();
});

it("keeps the issue-filtered empty live view distinct and offers a window-preserving clear", () => {
	render(
		<LiveTraces streamParams="issue=truncated">
			<p>static list</p>
		</LiveTraces>,
	);
	fireEvent.click(screen.getByRole("button", { name: /live/i }));
	const es = FakeEventSource.last as FakeEventSource;
	act(() =>
		es.emit("full", JSON.stringify({ rows: [], stale: false, servedAt: 0 })),
	);
	expect(
		screen.getByText("No traces in this window have Truncated."),
	).toBeTruthy();
	expect(
		screen.getByRole("link", { name: "Clear filter" }).getAttribute("href"),
	).toBe("/traces?range=7d");
});
