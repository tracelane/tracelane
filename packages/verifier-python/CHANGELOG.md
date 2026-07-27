# Changelog

All notable changes to `tracelane-audit-verifier` are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/); this package
is versioned in lockstep with the Rust and TypeScript reference verifiers.

## [0.2.1] - 2026-07-25

### Fixed
- **Windowed verify (ADR-070).** A retention-windowed ledger — one whose genesis
  (seq 0) has aged out of the loaded window — now verifies **GREEN** when it is
  rooted at a publicly-included Rekor anchor batch inside the window, instead of
  reporting a false **RED** (`seq_out_of_order`). `_verify_anchors_offline` now
  runs before `_verify_chain` and returns the per-tenant included-anchor starts;
  `_verify_chain` keys on the minimum loaded seq (`0` → full genesis verify,
  unchanged; `> 0` → windowed, rooted at the earliest resolved anchor). A windowed
  ledger with **no** resolved in-window anchor stays RED (`unrooted_window`) —
  never falsely green. `VerifyReport` gains `verified_from_seq` and
  `trust_established`. Restores byte-parity with the Rust and TypeScript verifiers.
