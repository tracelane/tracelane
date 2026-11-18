<!-- tracelane:classification: PUBLIC -->
# `packages/verifier-wasm`

A static page that verifies a Tracelane **action evidence ZIP** in the browser. It runs the
Rust reference verifier ([`../verifier-rust`](../verifier-rust/), `action::bundle::verify_with_tsa`)
compiled to WebAssembly. No check is reimplemented in JavaScript.

Status: source only. The page is not hosted anywhere; serve `web/` yourself.

## What it does

You give the page three things, by drag-and-drop or file picker:

1. the evidence ZIP;
2. the workspace's Ed25519 public key, as a text file or pasted text (base64, or 64 hex
   characters; the same decoding as `tracelane-audit verify --pubkey`);
3. optionally, one or more TSA leaf certificates (DER or PEM).

It prints `PASS` with every field of the verifier's report, or `FAIL (code N)` with the
verifier's reason. Codes match the `tracelane-audit` exit codes: 4 format or proof, 5 trust
input (public key or TSA certificate), 6 action semantics.

The files are read locally. The page makes no network requests after it loads: the WebAssembly
binary is embedded in a script file rather than fetched, so the page's content security policy
can set `connect-src 'none'`. The browser then refuses any fetch, XHR or subresource request the
page might attempt. (A content security policy does not govern top-level navigation.)

## What a PASS shows, and what it does not

A PASS shows that the files match the bundle manifest, the ledger rows form an unbroken hash
chain with gap-free sequence numbers up to the signed head, the covering checkpoint verifies
under the public key **you supplied**, and the recorded action events are consistent (policy
decisions replay from the bundled policy and evidence; those that cannot are listed).

It does not show that the record is complete, that the recorded events are true, that the
recorded policy was the right one, or that the key belongs to the workspace. Row `event_time`
values are outside the row hash. No certificate revocation status is fetched or checked. A
timestamp is reported only when you supply the TSA certificate yourself; certificates and keys
inside the bundle never establish trust. The result is technical evidence about one file, not a
legal or regulatory conclusion.

## Build

Needs Rust with the `wasm32-unknown-unknown` target, `clang` (for `ring`), Node.js, and
`wasm-bindgen-cli` at the version pinned in `Cargo.toml`:

```bash
rustup target add wasm32-unknown-unknown
cargo install --locked wasm-bindgen-cli --version 0.2.120
packages/verifier-wasm/build.sh        # regenerates web/pkg/, prints the .wasm size and sha256
```

`web/pkg/` is generated and NOT checked in: an opaque binary in git could silently drift from
the verifier source, so a page could pass a bundle the CLI fails. Run `build.sh` before serving;
CI (`verifier-wasm` job) rebuilds it from source on every change to the verifier and runs the
wrapper tests and the browser proof against that fresh build. The release `.wasm` is about
1.1 MB (about 1.46 MB once base64-embedded). If you host the page, also send
`frame-ancestors 'none'` as an HTTP header; a meta-tag policy cannot set it. This crate is its own Cargo workspace,
so it is built from its own directory, not with `cargo build --workspace` at the repository root.

## Serve

Any static file server works; the page needs `http://` or `https://`, not `file://`.

```bash
python3 -m http.server --directory packages/verifier-wasm/web 8000
```

## Test

```bash
(cd packages/verifier-wasm && cargo test)                                      # wrapper, 15 tests
cargo test -p tracelane-audit-verifier --lib browser_fixtures                  # fixtures are current
node scripts/proofs/verifier-wasm-browser.mjs                                  # Chromium, 11 cases
```

The browser test needs Playwright with Chromium available to Node. It serves `web/` on a
loopback port, drops the fixture bundles on the page, reads the rendered verdict, and fails if
the page makes any request after load.

`fixtures/` holds a synthetic three-row bundle, a copy with one ledger byte changed, and the
matching public key. They are test inputs, not real evidence. Regenerate them with
`TRACELANE_WRITE_FIXTURES=1 cargo test -p tracelane-audit-verifier --lib browser_fixtures`.

## Limits

- Bundles over 64 MiB are refused (the command-line verifier's limit).
- Action ZIPs only. NDJSON ledgers are verified with the other verifiers in this directory.
- The `.wasm` build is not signed and has no reproducible-build attestation. To trust a hosted
  copy, build it yourself and compare, or use the command-line verifier.
