# Changelog

All notable changes to `tracelane-audit-verifier` (Rust reference verifier) are
documented here. Versioned in lockstep with the TypeScript and Python verifiers.

## [0.2.1] - 2026-07-25

### Fixed
- **Windowed verify (ADR-070).** A retention-windowed ledger — one whose genesis
  (seq 0) has aged out of the loaded window — now verifies **GREEN** when rooted
  at a publicly-included Rekor anchor batch inside the window, instead of a false
  **RED** (`seq_out_of_order`). `verify_chain` keys on the minimum loaded seq
  (`0` → full genesis verify, unchanged; `> 0` → windowed, rooted at the earliest
  resolved anchor). `verified_from_seq` is the report-level LATEST per-tenant
  anchor batch-start; a windowed ledger with no resolved in-window anchor stays
  RED (`unrooted_window`). `VerifyReport` gains `verified_from_seq` and
  `trust_established`.
