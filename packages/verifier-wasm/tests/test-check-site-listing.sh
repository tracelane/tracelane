#!/usr/bin/env bash
# Run: bash packages/verifier-wasm/tests/test-check-site-listing.sh
set -uo pipefail
chk="$(cd "$(dirname "$0")/.." && pwd)/check-site-listing.sh"
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT; fails=0
mk() { rm -rf "$t/d"; mkdir -p "$t/d/pkg"; echo a > "$t/d/verify.js"; echo b > "$t/d/pkg/x.js"; }
expect() { local want=$1 name=$2; shift 2; "$chk" "$t/d" verify.js pkg/x.js >/dev/null 2>&1; got=$?
  if { [ "$want" = ok ] && [ $got = 0 ]; } || { [ "$want" = no ] && [ $got != 0 ]; }; then echo "ok   $name"; else echo "FAIL $name (exit $got)"; fails=$((fails+1)); fi; }
mk; expect ok "exactly the listed files"
mk; echo s > "$t/d/evil.js"; expect no "an extra file"
mk; echo s > "$t/d/pkg/evil.js"; expect no "an extra file in a subdirectory"
mk; ln -s /etc/passwd "$t/d/link.js"; expect no "an extra symlink"
mk; rm "$t/d/verify.js"; ln -s pkg/x.js "$t/d/verify.js"; expect no "a listed path that is a symlink"
mk; rm "$t/d/pkg/x.js"; expect no "a listed file missing"
mk; mkfifo "$t/d/pipe"; expect no "an extra named pipe"
mk; mkdir "$t/real"; echo s > "$t/real/evil.js"; ln -s "$t/real" "$t/d/linkdir"; expect no "a symlinked directory"
mk; mkdir "$t/d/empty-dir"; expect ok "an empty directory is not a served file"
[ $fails = 0 ] && echo "check-site-listing: all pass" || { echo "check-site-listing: $fails FAILED"; exit 1; }
