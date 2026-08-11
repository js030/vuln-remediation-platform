#!/usr/bin/env bash
set -u

INTERVAL_SECONDS=600
LOG_DIR="logs"
LOG_FILE="${LOG_DIR}/scheduled_remediation.log"
LOCK_FILE="/tmp/vuln-remediation-scheduler.lock"

mkdir -p "$LOG_DIR"

# Prevent two scheduler instances from running at the same time.
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[SCHEDULER] Another scheduler instance is already running. Exiting."
  exit 1
fi

echo "[SCHEDULER] Started at $(date -Iseconds)" | tee -a "$LOG_FILE"
echo "[SCHEDULER] Interval: ${INTERVAL_SECONDS}s" | tee -a "$LOG_FILE"

while true; do
  echo "" | tee -a "$LOG_FILE"
  echo "[SCHEDULER] Starting scan at $(date -Iseconds)" | tee -a "$LOG_FILE"

  # Do not run while local, uncommitted changes are present.
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "[SCHEDULER] Local Git changes detected; scan skipped." | tee -a "$LOG_FILE"
  else
    PYTHONPATH=. SCAN_LIVE_CLUSTER=true python scripts/mvp.py 2>&1 | tee -a "$LOG_FILE"
    EXIT_CODE=${PIPESTATUS[0]}
    echo "[SCHEDULER] Scan finished with exit code ${EXIT_CODE} at $(date -Iseconds)" \
      | tee -a "$LOG_FILE"
  fi

  echo "[SCHEDULER] Waiting 10 minutes for next run..." | tee -a "$LOG_FILE"
  sleep "$INTERVAL_SECONDS"
done
