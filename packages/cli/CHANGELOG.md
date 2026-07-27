# Changelog

All notable changes to `@tracelanedev/cli` (`tlane`) are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.1] - 2026-07-25

### Fixed
- **`tlane verify` inherits the ADR-070 windowed-verify fix.** The CLI embeds
  `@tracelanedev/audit-verifier` (`workspace:*` → pinned at publish time), so
  0.2.1 ships the 0.2.1 verifier: a retention-windowed ledger whose genesis has
  aged out now verifies **GREEN** when rooted at a public Rekor anchor inside the
  window, instead of the prior false **RED** (`seq_out_of_order`). A windowed
  ledger with no in-window anchor still exits non-zero (`unrooted_window`). No
  CLI-surface changes; the dependency refresh is the whole of this release.
