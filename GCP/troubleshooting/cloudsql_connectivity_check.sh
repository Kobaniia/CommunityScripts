#!/usr/bin/env bash
# =============================================================================
# Script : cloudsql_connectivity_check.sh
# Purpose: Verify Cloud SQL instance connectivity, authorized networks,
#          SSL requirements, and recent error logs.
# Usage  : ./cloudsql_connectivity_check.sh <instance-name> [project]
# Requires: gcloud CLI
# =============================================================================
set -euo pipefail

INSTANCE="${1:?Usage: $0 <instance-name> [project]}"
PROJECT="${2:-$(gcloud config get-value project)}"

echo "=== Cloud SQL Connectivity Check: $INSTANCE ==="

# 1. Instance state & IP
echo "[+] Instance info:"
gcloud sql instances describe "$INSTANCE" --project="$PROJECT" \
  --format="table(state, databaseVersion, settings.tier, ipAddresses[0].ipAddress, region)"

# 2. Authorized networks
echo "[+] Authorized networks (IP allowlist):"
AUTH_NETS=$(gcloud sql instances describe "$INSTANCE" --project="$PROJECT" \
  --format="json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
nets = d.get('settings',{}).get('ipConfiguration',{}).get('authorizedNetworks',[])
if not nets:
    print('  (no authorized networks — public access may be restricted or disabled)')
for n in nets:
    print(f\"  {n.get('value','?')} — {n.get('name','unnamed')}\")
")
echo "$AUTH_NETS"

# 3. SSL requirement
echo "[+] SSL/TLS enforcement:"
gcloud sql instances describe "$INSTANCE" --project="$PROJECT" \
  --format="value(settings.ipConfiguration.requireSsl)"

# 4. Private IP / VPC peering
echo "[+] Private IP / PSC config:"
gcloud sql instances describe "$INSTANCE" --project="$PROJECT" \
  --format="table(settings.ipConfiguration.privateNetwork,settings.ipConfiguration.enablePrivatePathForGoogleCloudServices)"

# 5. Recent error logs (last 50 lines)
echo "[+] Recent DB error logs:"
gcloud logging read \
  "resource.type=cloudsql_database AND resource.labels.database_id=$PROJECT:$INSTANCE AND severity>=ERROR" \
  --project="$PROJECT" --limit=10 \
  --format="table(timestamp, severity, textPayload)" 2>/dev/null \
  || echo "  (no recent errors or Cloud Logging not accessible)"

echo "=== Done ==="
