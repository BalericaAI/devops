#!/usr/bin/env bash
set -euo pipefail

COMBINED_JSON="${COMBINED_JSON:-gate_result.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq not installed. Install jq or run without summary." >&2
  exit 1
fi

if [[ ! -f "$COMBINED_JSON" ]]; then
  echo "Missing: $COMBINED_JSON" >&2
  exit 1
fi

jq -r '
  "SEIR Gate Summary",
  "-----------------",
  ("Badge:   " + (.badge // "UNKNOWN")),
  ("Status:  " + (.status // "UNKNOWN")),
  ("Region:  " + (.region // "")),
  ("EC2:     " + (.inputs.instance_id // "")),
  ("RDS:     " + (.inputs.db_id // "")),
  ("Secret:  " + (.inputs.secret_id // "")),
  "",
  "SLA",
  ("  target_hours: " + ((.sla.target_hours // 0)|tostring)),
  ("  first_seen:   " + (.clocks.first_seen_utc // "")),
  ("  due:          " + (.sla.due_utc // "")),
  ("  breached:     " + ((.sla.breached // false)|tostring)),
  "",
  "Failures (fix in order)",
  (if (.rollup.failures|length) == 0 then "  (none)" else (.rollup.failures[] | "  - " + .) end),
  "",
  "Warnings",
  (if (.rollup.warnings|length) == 0 then "  (none)" else (.rollup.warnings[] | "  - " + .) end)
' "$COMBINED_JSON"
