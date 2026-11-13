#!/usr/bin/env sh
set -eu

DIR="${1:?release folder}"
PUBKEY="$(dirname "$0")/../minisign.pub"

cd "$DIR"
if [ -f "$PUBKEY" ]; then
  minisign -V -p "$PUBKEY" -m SHA256SUMS
else
  echo "warning: minisign.pub is missing, signature not verified" >&2
fi
sha256sum --ignore-missing -c SHA256SUMS
if command -v gh >/dev/null 2>&1; then
  for f in lyctacrypt*; do
    [ -f "$f" ] && gh attestation verify "$f" --repo "${LYCTA_REPO:?set LYCTA_REPO=owner/repo}"
  done
fi
echo "verification complete"
