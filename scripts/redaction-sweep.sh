#!/usr/bin/env bash
#
# Purpose : Block lab-specific identifiers from reaching a public commit.
# Inputs  : Every git-tracked file (layout-agnostic — no directory assumptions).
# Output  : Exit 0 when clean. Exit 1 with file:line for every match found.
#
# This is a mechanical backstop, not a substitute for reading the draft. It
# catches the identifiers that leak by accident — pasted command output,
# copied portal URLs, an un-scrubbed terminal capture. Judgement calls (is this
# detail too identifying?) stay with the author.

set -euo pipefail

# This script contains the patterns as literal strings and would match itself.
SELF="scripts/redaction-sweep.sh"

failed=0

indent() {
  while IFS= read -r line; do
    printf '  %s\n' "$line"
  done
}

# Each rule is "name|regex". Extended regex.
rules=(
  "GUID (tenant/subscription/object ID)|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
  "JWT or bearer token|(eyJ[A-Za-z0-9_-]{10,}|bearer[[:space:]]+[A-Za-z0-9._-]{20,})"
  "Azure storage/SAS credential|(AccountKey=|sig=[A-Za-z0-9%]{20,}|sv=20[0-9]{2}-[0-9]{2}-[0-9]{2})"
  "Private key block|-----BEGIN[[:space:]]+[A-Z ]*PRIVATE KEY-----"
  "Local workspace path|/media/ben/data"
  # Trailing character class keeps filenames such as CLAUDE.local.md from
  # reading as a hostname — a real one is not followed by another label.
  "Internal hostname|[A-Za-z0-9-]+\.(internal|local|lan|corp)([^.A-Za-z0-9]|$)"
)

# Addresses that are safe to publish: RFC 5737 documentation ranges, loopback
# and the unspecified address.
IP_ALLOW='(127\.0\.0\.1|0\.0\.0\.0|192\.0\.2\.[0-9]{1,3}|198\.51\.100\.[0-9]{1,3}|203\.0\.113\.[0-9]{1,3})'

# Tracked files only. Untracked scratch is not going anywhere public, and this
# keeps the sweep correct whatever the layout turns out to be.
mapfile -t files < <(git ls-files | grep -vFx "$SELF")

if [ ${#files[@]} -eq 0 ]; then
  echo "No tracked files to sweep."
  exit 0
fi

echo "Redaction sweep over ${#files[@]} tracked files."

for rule in "${rules[@]}"; do
  name="${rule%%|*}"
  pattern="${rule#*|}"
  if hits=$(grep -InE --binary-files=without-match "$pattern" "${files[@]}" 2>/dev/null); then
    echo "FAIL: $name"
    echo "$hits" | indent
    failed=1
  fi
done

# IPv4 handled separately so the documentation ranges can be filtered out.
if hits=$(grep -InE --binary-files=without-match \
            '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${files[@]}" 2>/dev/null \
          | grep -vE "$IP_ALLOW"); then
  echo "FAIL: IPv4 address outside the documentation ranges"
  echo "$hits" | indent
  failed=1
fi

if [ "$failed" -eq 0 ]; then
  echo "Clean — no lab-specific identifiers found."
else
  echo
  echo "Redact the matches above, or add a documented exception to this script."
fi

exit "$failed"
