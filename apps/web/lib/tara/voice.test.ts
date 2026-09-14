import { describe, expect, it } from "vitest";
import { PREFERRED_FEMALE_VOICES, loadVoices, pickTaraVoice } from "./voice";

const v = (
	name: string,
	lang = "en-US",
	extra: Partial<{ default: boolean }> = {},
) => ({
	name,
	lang,
	...extra,
});

describe("pickTaraVoice — OBS-40, Tara is a female voice (founder 2026-09-07)", () => {
	it("prefers a neural female voice on Edge/Windows over the male default", () => {
		const voices = [
			v("Microsoft David - English (United States)", "en-US", {
				default: true,
			}),
			v("Microsoft Aria Online (Natural) - English (United States)"),
			v("Microsoft Guy Online (Natural) - English (United States)"),
		];
		expect(pickTaraVoice(voices)?.name).toContain("Aria");
	});

	it("picks Google UK English Female on Chrome, never Google UK English Male", () => {
		const voices = [
			v("Google UK English Male", "en-GB", { default: true }),
			v("Google UK English Female", "en-GB"),
			v("Google Deutsch", "de-DE"),
		];
		expect(pickTaraVoice(voices)?.name).toBe("Google UK English Female");
	});

	it("picks Samantha on macOS/iOS over Alex", () => {
		const voices = [
			v("Alex", "en-US", { default: true }),
			v("Samantha", "en-US"),
			v("Daniel", "en-GB"),
		];
		expect(pickTaraVoice(voices)?.name).toBe("Samantha");
	});

	it("honours a self-declared 'female' voice when no known name is present", () => {
		const voices = [
			v("Vendor Voice Male", "en-US", { default: true }),
			v("Vendor Voice Female", "en-US"),
		];
		expect(pickTaraVoice(voices)?.name).toBe("Vendor Voice Female");
	});

	it("never returns a known-male voice while any other English voice exists", () => {
		const voices = [
			v("Microsoft David", "en-US", { default: true }),
			v("Unknown Local", "en-US"),
		];
		expect(pickTaraVoice(voices)?.name).toBe("Unknown Local");
	});

	it("prefers English voices over other languages", () => {
		const voices = [
			v("Amelie", "fr-FR", { default: true }),
			v("Zira", "en-US"),
		];
		expect(pickTaraVoice(voices)?.name).toBe("Zira");
	});

	it("returns null for an empty list so the caller leaves the browser default", () => {
		expect(pickTaraVoice([])).toBeNull();
	});

	it("the preference list carries no known-male name (guards a careless edit)", () => {
		for (const p of PREFERRED_FEMALE_VOICES) {
			expect(["david", "mark", "guy", "alex", "daniel", "male"]).not.toContain(
				p,
			);
		}
	});
});

describe("loadVoices", () => {
	it("resolves immediately when voices are already loaded", async () => {
		const synth = {
			getVoices: () => [v("Samantha")] as unknown as SpeechSynthesisVoice[],
			addEventListener: () => {},
			removeEventListener: () => {},
		};
		expect((await loadVoices(synth)).length).toBe(1);
	});

	it("waits for voiceschanged, then resolves with the loaded list", async () => {
		const state: {
			list: SpeechSynthesisVoice[];
			handler: (() => void) | null;
		} = {
			list: [],
			handler: null,
		};
		const synth = {
			getVoices: () => state.list,
			addEventListener: (_: string, h: () => void) => {
				state.handler = h;
			},
			removeEventListener: () => {},
		};
		const p = loadVoices(synth as never, 5_000);
		state.list = [v("Aria")] as unknown as SpeechSynthesisVoice[];
		state.handler?.();
		expect((await p).length).toBe(1);
	});

	it("gives up after the timeout with whatever is there (never hangs the click)", async () => {
		const synth = {
			getVoices: () => [],
			addEventListener: () => {},
			removeEventListener: () => {},
		};
		expect(await loadVoices(synth as never, 10)).toEqual([]);
	});
});
