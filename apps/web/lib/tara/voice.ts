/**
 * Tara's read-aloud voice — OBS-40, founder ruling 2026-09-07: Tara is a
 * "smart, beautiful female voice", not the browser's default (which on most
 * platforms is male).
 *
 * Browser-side only (no TTS vendor, per the spec): `speechSynthesis` exposes
 * whatever voices the OS installed, with no gender field, so the only honest
 * selector is a preference list of voices KNOWN to be female by name, per
 * platform, then a name heuristic, then the browser default. The picker is a
 * pure function so the ordering is testable without a browser.
 */

export interface VoiceLike {
	name: string;
	lang: string;
	default?: boolean;
	localService?: boolean;
}

/**
 * Ordered by naturalness where we can know it (Microsoft "Natural"/"Online"
 * neural voices and Google's cloud voices first, then good local voices).
 * Matching is case-insensitive substring so "Microsoft Aria Online (Natural) -
 * English (United States)" matches "aria".
 */
export const PREFERRED_FEMALE_VOICES: readonly string[] = [
	// Edge / Windows neural voices
	"aria",
	"jenny",
	"sonia",
	"libby",
	"natasha",
	"emma",
	"michelle",
	"ana",
	// Chrome (Google cloud voices)
	"google uk english female",
	"google us english",
	"google australian english female",
	// macOS / iOS
	"samantha",
	"ava",
	"allison",
	"susan",
	"zoe",
	"karen",
	"moira",
	"tessa",
	"fiona",
	"kate",
	"serena",
	"victoria",
	// Windows local
	"zira",
	"hazel",
];

/** Names that are unmistakably male on the platforms above — never pick these. */
const KNOWN_MALE: readonly string[] = [
	"david",
	"mark",
	"guy",
	"ryan",
	"george",
	"daniel",
	"alex",
	"tom",
	"fred",
	"oliver",
	"james",
	"google uk english male",
	"male",
];

function isEnglish(v: VoiceLike): boolean {
	return v.lang.toLowerCase().startsWith("en");
}

function nameHas(v: VoiceLike, needle: string): boolean {
	return v.name.toLowerCase().includes(needle);
}

function looksMale(v: VoiceLike): boolean {
	return KNOWN_MALE.some((m) => nameHas(v, m));
}

/**
 * Pick Tara's voice from the browser's list. Returns `null` when the list is
 * empty or holds nothing usable — the caller then leaves the utterance's voice
 * unset (browser default) rather than inventing one.
 */
export function pickTaraVoice<T extends VoiceLike>(
	voices: readonly T[],
): T | null {
	if (voices.length === 0) return null;
	const english = voices.filter(isEnglish);
	const pool = english.length > 0 ? english : voices;

	for (const preferred of PREFERRED_FEMALE_VOICES) {
		const hit = pool.find((v) => nameHas(v, preferred) && !looksMale(v));
		if (hit) return hit;
	}
	// Any voice that says so itself.
	const selfDeclared = pool.find((v) => nameHas(v, "female"));
	if (selfDeclared) return selfDeclared;
	// Last resort: an English voice that is at least not known-male, preferring
	// non-default (the default is what the founder heard and rejected).
	const notMale = pool.filter((v) => !looksMale(v));
	const nonDefault = notMale.find((v) => !v.default);
	return nonDefault ?? notMale[0] ?? null;
}

/**
 * `speechSynthesis.getVoices()` is empty until the browser has loaded the list
 * (Chrome fires `voiceschanged` once, often after the first call). Resolve with
 * whatever is available within `timeoutMs` so the click never hangs.
 */
export function loadVoices(
	synth: Pick<
		SpeechSynthesis,
		"getVoices" | "addEventListener" | "removeEventListener"
	>,
	timeoutMs = 750,
): Promise<SpeechSynthesisVoice[]> {
	const now = synth.getVoices();
	if (now.length > 0) return Promise.resolve(now);
	return new Promise((resolve) => {
		let done = false;
		const finish = () => {
			if (done) return;
			done = true;
			synth.removeEventListener("voiceschanged", finish);
			resolve(synth.getVoices());
		};
		synth.addEventListener("voiceschanged", finish);
		setTimeout(finish, timeoutMs);
	});
}
