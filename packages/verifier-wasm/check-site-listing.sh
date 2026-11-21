#!/usr/bin/env bash
# check-site-listing.sh DIR FILE...: DIR must hold exactly the listed files, each a regular file
# (not a symlink), and nothing else (no extra file, symlink, socket or directory entry).
# Used by publish-site.sh --check; a stray script served from the site origin must not slip in.
set -uo pipefail
dir="$1"; shift
for f in "$@"; do
  { [ -f "$dir/$f" ] && [ ! -L "$dir/$f" ]; } || { echo "MISSING or not a regular file: $dir/$f" >&2; exit 1; }
done
found=$(cd "$dir" && find . ! -type d | sed 's|^\./||' | sort) || { echo "cannot list $dir" >&2; exit 1; }
listing=$(mktemp) || { echo "cannot create a temp file" >&2; exit 1; }
trap 'rm -f "$listing"' EXIT
printf '%s\n' "$@" | sort > "$listing"
extra=$(printf '%s\n' "$found" | grep -vxF -f "$listing"); rc=$?
[ "$rc" -le 1 ] || { echo "grep failed ($rc) while checking $dir" >&2; exit 1; }
[ -z "$extra" ] || { echo "UNEXPECTED entry in $dir: $extra" >&2; exit 1; }
