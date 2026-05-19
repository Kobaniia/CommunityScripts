#!/usr/bin/env bash
# =============================================================================
# Script : rds_slow_query_report.sh
# Purpose: Download RDS slow-query logs and summarize the top offenders
# Usage  : ./rds_slow_query_report.sh <db-instance-id> [region]
# Requires: AWS CLI v2
# =============================================================================
set -euo pipefail

DB_ID="${1:?Usage: $0 <db-instance-id> [region]}"
REGION="${2:-us-east-1}"
OUTDIR="/tmp/rds_logs_${DB_ID}"
mkdir -p "$OUTDIR"

echo "=== RDS Slow Query Report: $DB_ID ==="

echo "[+] Fetching log file list..."
LOG_FILES=$(aws rds describe-db-log-files --db-instance-identifier "$DB_ID" \
  --region "$REGION" --filename-contains "slowquery" \
  --query 'DescribeDBLogFiles[*].LogFileName' --output text)

if [[ -z "$LOG_FILES" ]]; then
  echo "No slow query logs found. Ensure slow_query_log=1 in the parameter group."
  exit 0
fi

for LOG in $LOG_FILES; do
  echo "[+] Downloading $LOG..."
  SAFE=$(echo "$LOG" | tr '/' '_')
  aws rds download-db-log-file-portion --db-instance-identifier "$DB_ID" \
    --region "$REGION" --log-file-name "$LOG" --starting-token 0 \
    --query LogFileData --output text > "$OUTDIR/$SAFE" 2>/dev/null || true
done

echo ""
echo "[Summary] Top 10 slowest queries (by Query_time):"
grep -h "Query_time" "$OUTDIR"/* 2>/dev/null | sort -t: -k2 -rn | head -10 \
  || echo "  Could not parse log entries."

echo ""
echo "Full logs saved to: $OUTDIR"
