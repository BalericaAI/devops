# You need JQ!!!

#!/usr/bin/env bash
set -euo pipefail

# Inputs
COMBINED_JSON="${COMBINED_JSON:-gate_result.json}"
G1="${G1:-gate_secrets_and_role.json}"
G2="${G2:-gate_network_db.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for roll-up." >&2
  exit 1
fi

if [[ ! -f "$COMBINED_JSON" || ! -f "$G1" || ! -f "$G2" ]]; then
  echo "ERROR: missing required json files (combined + two child gates)." >&2
  exit 1
fi

tmp="$(mktemp)"

jq \
  --slurpfile g1 "$G1" \
  --slurpfile g2 "$G2" \
  '
  .rollup = {
    failures:  (($g1[0].failures // []) + ($g2[0].failures // [])),
    warnings:  (($g1[0].warnings // []) + ($g2[0].warnings // [])),
    details:   (($g1[0].details  // []) + ($g2[0].details  // []))
  }
  ' "$COMBINED_JSON" > "$tmp"

mv "$tmp" "$COMBINED_JSON"
echo "Updated roll-up in: $COMBINED_JSON"
