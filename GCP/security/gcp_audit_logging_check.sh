#!/usr/bin/env bash
# =============================================================================
# Script : gcp_audit_logging_check.sh
# Purpose: Verify that Cloud Audit Logs (Admin Activity, Data Access) are
#          enabled for all services in a GCP project and flag any gaps.
# Usage  : ./gcp_audit_logging_check.sh [project]
# Requires: gcloud CLI, python3
# =============================================================================
set -euo pipefail

PROJECT="${1:-$(gcloud config get-value project)}"
echo "=== GCP Audit Logging Check (project: $PROJECT) ==="

# Pull the IAM policy (which includes auditConfigs)
POLICY=$(gcloud projects get-iam-policy "$PROJECT" --format=json 2>/dev/null)

echo "$POLICY" | python3 << 'PYEOF'
import sys, json

policy = json.load(sys.stdin)
audit_configs = policy.get("auditConfigs", [])

# Expected minimum: allServices should have ADMIN_READ + DATA_READ + DATA_WRITE
REQUIRED_LOG_TYPES = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}

findings = []

# Check allServices catch-all
all_svc_config = next(
    (c for c in audit_configs if c.get("service") == "allServices"), None
)

if not all_svc_config:
    findings.append("CRITICAL: No 'allServices' audit config found — some services may have no audit logging.")
else:
    enabled_types = {lt["logType"] for lt in all_svc_config.get("auditLogConfigs", [])}
    missing = REQUIRED_LOG_TYPES - enabled_types
    if missing:
        findings.append(f"allServices audit config is missing log types: {', '.join(missing)}")
    else:
        print("  [OK] allServices audit config covers: " + ", ".join(sorted(enabled_types)))

# Check for exempted principals (these users bypass logging)
for cfg in audit_configs:
    svc = cfg.get("service", "?")
    for lt in cfg.get("auditLogConfigs", []):
        exempted = lt.get("exemptedMembers", [])
        if exempted:
            findings.append(
                f"Service '{svc}' log type '{lt['logType']}' has EXEMPTED members: {', '.join(exempted)}"
            )

# Log sink check (ensure logs are exported somewhere)
print("\n  Audit configs found:")
for cfg in audit_configs:
    types = [lt["logType"] for lt in cfg.get("auditLogConfigs", [])]
    print(f"    Service: {cfg.get('service','?'):<50} Types: {', '.join(types)}")

print("\n── Findings ──────────────────────────────────────────")
if findings:
    for f in findings:
        print(f"  [!] {f}")
else:
    print("  [OK] No audit logging gaps detected.")
print("──────────────────────────────────────────────────────")
PYEOF

# Check if a log sink is configured (logs exported to GCS/BigQuery/Pub/Sub)
echo ""
echo "[+] Log Sinks (export destinations):"
gcloud logging sinks list --project="$PROJECT" \
  --format="table(name, destination, filter)" 2>/dev/null \
  || echo "  (no sinks configured — logs are not being exported)"

echo "=== Done ==="
