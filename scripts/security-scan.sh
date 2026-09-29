#!/usr/bin/env bash
# scripts/security-scan.sh
#
# Local security-scan gate: runs every dependency / supply-chain scanner the
# nightly .github/workflows/security-scan.yml runs, with the same config files
# (deny.toml, .cargo/audit.toml, osv-scanner.toml, .grype.yaml),
# so a contributor can reproduce the scheduled scan before pushing.
#
# Usage: scripts/security-scan.sh          (from anywhere; cds to repo root)
# Exit:  0 iff every scanner is clean at its threshold.

set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

FAIL=0
say()  { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }
need() { command -v "$1" >/dev/null 2>&1 && return 0
         echo "MISSING: $1 — install: $2"; FAIL=1; return 1; }

say "cargo audit (RustSec advisories)"
need cargo-audit "cargo install cargo-audit --locked" && { cargo audit || FAIL=1; }

say "cargo deny (bans + licenses + advisories)"
need cargo-deny "cargo install cargo-deny --locked" && { cargo deny check || FAIL=1; }

say "cargo machete (unused Rust deps)"
need cargo-machete "cargo install cargo-machete --locked" && { cargo machete || FAIL=1; }

say "pnpm audit (high+)"
pnpm audit --audit-level=high || FAIL=1

say "osv-scanner (every lockfile, osv-scanner.toml ignores)"
need osv-scanner "curl -sL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o ~/.local/bin/osv-scanner && chmod +x ~/.local/bin/osv-scanner" \
  && { osv-scanner scan --recursive --config osv-scanner.toml ./ || FAIL=1; }

say "grype (filesystem, .grype.yaml, fail on High+)"
need grype "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin" \
  && { grype dir:. --fail-on high --config .grype.yaml \
         --exclude './**/node_modules/**' --exclude './.claude/**' || FAIL=1; }

say "no-openssl (Rust dependency tree)"
if cargo tree -i openssl 2>/dev/null | grep -q .; then
  echo "FAIL: openssl in the Rust dep tree (banned — rustls/aws-lc-rs only)"
  FAIL=1
else
  echo "clean"
fi

echo
if [[ "$FAIL" -eq 1 ]]; then
  echo "security-scan: FAILURES PRESENT ✗"
  exit 1
fi
echo "security-scan: ALL GREEN ✔"
