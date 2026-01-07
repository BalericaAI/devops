#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# run_all_gates.sh (v2)
#
# Adds:
#  - badge.txt output (GREEN|YELLOW|RED)
#  - SLA clocks (first_seen/last_seen + due time)
#  - pr_comment.md output (copy/paste feedback)
#
# Exit codes:
#   0 = PASS
#   2 = FAIL
#   1 = ERROR
# ============================================================

REGION="${REGION:-us-east-1}"
INSTANCE_ID="${INSTANCE_ID:-}"
SECRET_ID="${SECRET_ID:-}"
DB_ID="${DB_ID:-}"

REQUIRE_ROTATION="${REQUIRE_ROTATION:-false}"
CHECK_SECRET_POLICY_WILDCARD="${CHECK_SECRET_POLICY_WILDCARD:-true}"
CHECK_SECRET_VALUE_READ="${CHECK_SECRET_VALUE_READ:-false}"
EXPECTED_ROLE_NAME="${EXPECTED_ROLE_NAME:-}"

CHECK_PRIVATE_SUBNETS="${CHECK_PRIVATE_SUBNETS:-false}"

OUT_JSON="${OUT_JSON:-gate_result.json}"
BADGE_TXT="${BADGE_TXT:-badge.txt}"
PR_COMMENT_MD="${PR_COMMENT_MD:-pr_comment.md}"

# SLA settings
SLA_HOURS="${SLA_HOURS:-24}"                 # target time to fix after first fail
STATE_DIR="${STATE_DIR:-.gate_state}"        # local persistence
STATE_FILE="${STATE_FILE:-.gate_state/all_gates_first_seen_utc.txt}"

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

json_escape() {
  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}

have_file() { [[ -f "$1" ]]; }

badge_color() {
  local overall_status="$1"   # PASS/FAIL
  local warning_flag="$2"     # 0/1
  if [[ "$overall_status" == "FAIL" ]]; then echo "RED"; return; fi
  if [[ "$warning_flag" -eq 1 ]]; then echo "YELLOW"; return; fi
  echo "GREEN"
}

iso_to_epoch() {
  # portable-ish: GNU date preferred. (Jenkins linux agents typically have it.)
  date -u -d "$1" +%s 2>/dev/null || echo ""
}

epoch_to_iso() {
  date -u -d "@$1" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo ""
}

ensure_state_dir() {
  mkdir -p "$STATE_DIR"
}

# Preconditions
if [[ -z "$INSTANCE_ID" || -z "$SECRET_ID" || -z "$DB_ID" ]]; then
  echo "ERROR: INSTANCE_ID, SECRET_ID, DB_ID required." >&2
  echo "Example:" >&2
  echo "  REGION=us-east-1 INSTANCE_ID=i-... SECRET_ID=my-secret DB_ID=mydb01 ./run_all_gates.sh" >&2
  exit 1
fi

if ! have_file "./gate_secrets_and_role.sh" || ! have_file "./gate_network_db.sh"; then
  echo "ERROR: Missing gate scripts in current directory." >&2
  echo "Need: ./gate_secrets_and_role.sh and ./gate_network_db.sh" >&2
  exit 1
fi

chmod +x ./gate_secrets_and_role.sh ./gate_network_db.sh || true

# Run Gate 1
echo "=== Running Gate 1/2: secrets_and_role ==="
set +e
OUT_JSON_1="gate_secrets_and_role.json" \
REGION="$REGION" INSTANCE_ID="$INSTANCE_ID" SECRET_ID="$SECRET_ID" \
REQUIRE_ROTATION="$REQUIRE_ROTATION" \
CHECK_SECRET_POLICY_WILDCARD="$CHECK_SECRET_POLICY_WILDCARD" \
CHECK_SECRET_VALUE_READ="$CHECK_SECRET_VALUE_READ" \
EXPECTED_ROLE_NAME="$EXPECTED_ROLE_NAME" \
./gate_secrets_and_role.sh
rc1=$?
set -e

# Run Gate 2
echo "=== Running Gate 2/2: network_db ==="
set +e
OUT_JSON_2="gate_network_db.json" \
REGION="$REGION" INSTANCE_ID="$INSTANCE_ID" DB_ID="$DB_ID" \
CHECK_PRIVATE_SUBNETS="$CHECK_PRIVATE_SUBNETS" \
./gate_network_db.sh
rc2=$?
set -e

# Determine overall status/exit
overall_status="PASS"
overall_exit=0
if [[ "$rc1" -ne 0 || "$rc2" -ne 0 ]]; then
  overall_status="FAIL"
  overall_exit=2
fi

# Warning heuristic: if warnings array exists and isn't empty
warning_flag=0
if grep -q '"warnings": \[' gate_secrets_and_role.json 2>/dev/null; then
  if ! grep -q '"warnings": \[\]' gate_secrets_and_role.json 2>/dev/null; then warning_flag=1; fi
fi
if grep -q '"warnings": \[' gate_network_db.json 2>/dev/null; then
  if ! grep -q '"warnings": \[\]' gate_network_db.json 2>/dev/null; then warning_flag=1; fi
fi

badge="$(badge_color "$overall_status" "$warning_flag")"
echo "$badge" > "$BADGE_TXT"

# SLA clocks (persist first_seen when first FAIL occurs; clear when PASS)
ts_now="$(now_utc)"
ensure_state_dir

first_seen_utc=""
last_seen_utc="$ts_now"

if [[ "$overall_status" == "FAIL" ]]; then
  if [[ -f "$STATE_FILE" ]]; then
    first_seen_utc="$(cat "$STATE_FILE" | tr -d '\n' || true)"
  fi
  if [[ -z "$first_seen_utc" ]]; then
    first_seen_utc="$ts_now"
    echo "$first_seen_utc" > "$STATE_FILE"
  fi
else
  # PASS clears the SLA timer
  rm -f "$STATE_FILE" >/dev/null 2>&1 || true
fi

# Compute SLA due + breach (best-effort)
breach=false
due_utc=""
age_seconds=""
remaining_seconds=""

if [[ -n "$first_seen_utc" ]]; then
  first_epoch="$(iso_to_epoch "$first_seen_utc")"
  now_epoch="$(iso_to_epoch "$ts_now")"
  if [[ -n "$first_epoch" && -n "$now_epoch" ]]; then
    age_seconds="$(( now_epoch - first_epoch ))"
    sla_seconds="$(( SLA_HOURS * 3600 ))"
    due_epoch="$(( first_epoch + sla_seconds ))"
    due_utc="$(epoch_to_iso "$due_epoch")"
    if (( now_epoch > due_epoch )); then
      breach=true
      remaining_seconds=0
    else
      remaining_seconds="$(( due_epoch - now_epoch ))"
    fi
  fi
fi

# Write combined JSON
cat > "$OUT_JSON" <<EOF
{
  "schema_version": "2.0",
  "gate": "all_gates",
  "timestamp_utc": "$ts_now",
  "region": "$(echo "$REGION" | json_escape)",
  "inputs": {
    "instance_id": "$(echo "$INSTANCE_ID" | json_escape)",
    "secret_id": "$(echo "$SECRET_ID" | json_escape)",
    "db_id": "$(echo "$DB_ID" | json_escape)"
  },
  "child_gates": [
    { "name": "secrets_and_role", "result_file": "gate_secrets_and_role.json", "exit_code": $rc1 },
    { "name": "network_db",       "result_file": "gate_network_db.json",       "exit_code": $rc2 }
  ],
  "badge": "$badge",
  "status": "$overall_status",
  "exit_code": $overall_exit,
  "clocks": {
    "first_seen_utc": "$(echo "${first_seen_utc:-}" | json_escape)",
    "last_seen_utc": "$(echo "$last_seen_utc" | json_escape)"
  },
  "sla": {
    "target_hours": $SLA_HOURS,
    "due_utc": "$(echo "${due_utc:-}" | json_escape)",
    "breached": $breach,
    "age_seconds": "$(echo "${age_seconds:-}" | json_escape)",
    "remaining_seconds": "$(echo "${remaining_seconds:-}" | json_escape)"
  },
  "artifacts": {
    "badge_txt": "$(echo "$BADGE_TXT" | json_escape)",
    "pr_comment_md": "$(echo "$PR_COMMENT_MD" | json_escape)"
  }
}
EOF

# PR comment output (simple & brutal)
cat > "$PR_COMMENT_MD" <<EOF
### SEIR Gate Result: **$badge** ($overall_status)

**Region:** \`$REGION\`  
**EC2:** \`$INSTANCE_ID\`  
**RDS:** \`$DB_ID\`  
**Secret:** \`$SECRET_ID\`  

**Child gates**
- secrets_and_role: exit \`$rc1\` (see \`gate_secrets_and_role.json\`)
- network_db: exit \`$rc2\` (see \`gate_network_db.json\`)

**SLA**
- target: \`${SLA_HOURS}h\`
- first_seen: \`${first_seen_utc:-}\`
- due: \`${due_utc:-}\`
- breached: \`$breach\`

**Next action**
- If **RED**: fix the failures listed inside each gate JSON and rerun the pipeline.
- If **YELLOW**: it passes, but warnings indicate “works by accident.” Stabilize it.
- If **GREEN**: merge with confidence.
EOF

# Console summary
echo ""
echo "===== SEIR Combined Gate Summary (v2) ====="
echo "Gate 1 exit: $rc1 -> gate_secrets_and_role.json"
echo "Gate 2 exit: $rc2 -> gate_network_db.json"
echo "------------------------------------------"
echo "BADGE:  $badge   (written to $BADGE_TXT)"
echo "RESULT: $overall_status"
echo "JSON:   $OUT_JSON"
echo "PR:     $PR_COMMENT_MD"
echo "=========================================="
echo ""

exit "$overall_exit"
