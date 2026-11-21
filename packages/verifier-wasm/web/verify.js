// Runs the Rust verifier (WebAssembly) on files read locally. Nothing here
// fetches: the .wasm is embedded in pkg/wasm-bytes.js so the page's CSP can
// set connect-src 'none'.
import init, { verify_bundle } from "./pkg/tracelane_verifier_wasm.js";
import wasmBase64 from "./pkg/wasm-bytes.js";

const MAX_BUNDLE_BYTES = 64 * 1024 * 1024; // the verifier's own limit; it re-checks
const MEANING = {
  4: "the bundle format or a proof in it is invalid",
  5: "trust input is missing or wrong (the public key or a TSA certificate)",
  6: "the recorded action events are inconsistent",
};
const $ = (id) => document.getElementById(id);
const state = { ready: false, zip: null, zipName: "", certs: [], certNames: [], note: "" };

const isZip = (b) => b.length > 3 && b[0] === 0x50 && b[1] === 0x4b;
const isCert = (b) => b[0] === 0x30 || new TextDecoder().decode(b.subarray(0, 10)) === "-----BEGIN";
const isKeyText = (b) => b.length <= 256 && /^\s*[A-Za-z0-9+/=]+\s*$/.test(new TextDecoder().decode(b));

async function accept(file, hint) {
  if (file.size > MAX_BUNDLE_BYTES) {
    state.zip = null;
    state.zipName = file.name;
    return showFail(4, `action bundle exceeds ${MAX_BUNDLE_BYTES} byte limit`);
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const kind = hint ?? (isZip(bytes) ? "zip" : isKeyText(bytes) ? "key" : isCert(bytes) ? "tsa" : null);
  if (kind === "zip") {
    state.zip = bytes;
    state.zipName = file.name;
  } else if (kind === "key") {
    $("key").value = new TextDecoder().decode(bytes).trim();
  } else if (kind === "tsa") {
    state.certs.push(bytes);
    state.certNames.push(file.name);
  } else {
    state.note = `Ignored ${file.name}: not a ZIP, a public key or a certificate. `;
  }
}

async function acceptAll(files, hint) {
  state.note = "";
  for (const file of files) await accept(file, hint);
  run();
}

function run() {
  $("zip-name").textContent = state.zipName;
  $("tsa-name").textContent = state.certNames.join(", ");
  $("result").hidden = true;
  if (!state.ready) return;
  const key = $("key").value;
  const missing = [];
  if (!state.zip) missing.push("evidence ZIP");
  if (!key.trim()) missing.push("public key");
  if (missing.length) {
    $("status").textContent = `${state.note}Waiting for: ${missing.join(", ")}`;
    return;
  }
  let out;
  try {
    out = JSON.parse(verify_bundle(state.zip, key, state.certs));
  } catch (e) {
    // A trap can leave the wasm heap and stack pointer in an undefined state: never reuse this
    // instance. Every later verification needs a fresh page.
    state.ready = false;
    return showFail(4, `the verifier stopped unexpectedly (${e}); reload the page before verifying again`);
  }
  if (!out.ok) return showFail(out.code, out.detail);
  const timeNote =
    state.certs.length && !out.report.timestamped
      ? " The signing time is NOT proven: no timestamp token matched a certificate you supplied."
      : "";
  show("pass", "PASS", `Chain, covering head and action semantics verified.${timeNote}`, out.summary);
  const body = $("report").tBodies[0];
  body.replaceChildren();
  flatten("", out.report, body);
  $("report").hidden = false;
}

function showFail(code, detail) {
  show("fail", `FAIL (code ${code})`, MEANING[code] ?? "verification failed", detail);
  $("report").hidden = true;
}

function show(cls, verdict, meaning, detail) {
  $("status").textContent = `${state.note}Verified locally: ${state.zipName}`;
  $("result").className = cls;
  $("verdict").textContent = verdict;
  $("meaning").textContent = meaning;
  $("detail").textContent = detail;
  $("result").hidden = false;
}

// One row per leaf of the report JSON, whatever its fields are. textContent
// only: values come from an untrusted bundle.
function flatten(prefix, value, body) {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) flatten(prefix ? `${prefix}.${k}` : k, v, body);
    return;
  }
  const row = body.insertRow();
  row.appendChild(document.createElement("th")).textContent = prefix;
  row.insertCell().textContent = Array.isArray(value)
    ? value.length
      ? `${value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ")} (${value.length})`
      : "none (0)"
    : String(value);
}

$("zip").addEventListener("change", (e) => acceptAll(e.target.files, "zip"));
$("key-file").addEventListener("change", (e) => acceptAll(e.target.files, "key"));
$("tsa").addEventListener("change", (e) => {
  state.certs = [];
  state.certNames = [];
  acceptAll(e.target.files, "tsa");
});
// Debounced: a keystroke must not re-verify up to 64 MiB each time.
let keyTimer;
$("key").addEventListener("input", () => {
  clearTimeout(keyTimer);
  keyTimer = setTimeout(run, 300);
});
const drop = $("drop");
for (const type of ["dragenter", "dragover"]) {
  drop.addEventListener(type, (e) => {
    e.preventDefault();
    drop.classList.add("over");
  });
}
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  acceptAll(e.dataTransfer.files);
});
// A file dropped outside the box must not navigate the tab away to it.
for (const type of ["dragover", "drop"]) window.addEventListener(type, (e) => e.preventDefault());

// Sample bundles exist only on a page that ships ./samples.js (embedded as base64, so loading a
// sample is not a fetch) and a #sample-good button. The standalone page has neither.
const samples = $("sample-good") ? await import("./samples.js") : null;
function loadSample(name) {
  state.certs = [];
  state.certNames = [];
  state.note = "";
  state.zip = Uint8Array.from(atob(samples[name]), (c) => c.charCodeAt(0));
  state.zipName = `${name}.zip (synthetic sample data)`;
  $("key").value = samples.publicKey;
  run();
}
if (samples) for (const name of ["good", "tampered"]) $(`sample-${name}`).addEventListener("click", () => loadSample(name));

try {
  await init({ module_or_path: Uint8Array.from(atob(wasmBase64), (c) => c.charCodeAt(0)) });
  state.ready = true;
  run();
} catch (e) {
  $("status").textContent = `The verifier could not start in this browser: ${e}`;
}
