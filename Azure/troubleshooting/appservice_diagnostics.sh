#!/usr/bin/env bash
# =============================================================================
# Script : appservice_diagnostics.sh
# Purpose: Gather App Service configuration, slot info, and recent error logs
# Usage  : ./appservice_diagnostics.sh <resource-group> <app-name> [slot]
# Requires: Azure CLI (az)
# =============================================================================
set -euo pipefail

RG="${1:?Usage: $0 <resource-group> <app-name> [slot]}"
APP="${2:?Usage: $0 <resource-group> <app-name> [slot]}"
SLOT="${3:-production}"

echo "=== App Service Diagnostics: $APP/$SLOT ==="

# 1. App settings (keys only — values may be secrets)
echo "[+] App setting keys:"
az webapp config appsettings list --resource-group "$RG" --name "$APP" \
  --query '[*].name' --output tsv 2>/dev/null || echo "  (no settings or insufficient access)"

# 2. Runtime stack
echo "[+] Runtime:"
az webapp show --resource-group "$RG" --name "$APP" \
  --query '{LinuxFx:siteConfig.linuxFxVersion,NetFx:siteConfig.netFrameworkVersion,NodeVer:siteConfig.nodeVersion}' \
  --output table 2>/dev/null

# 3. HTTPS & TLS
echo "[+] HTTPS / TLS settings:"
az webapp show --resource-group "$RG" --name "$APP" \
  --query '{HttpsOnly:httpsOnly,MinTlsVersion:siteConfig.minTlsVersion,Http20:siteConfig.http20Enabled}' \
  --output table

# 4. Deployment slots
echo "[+] Deployment slots:"
az webapp deployment slot list --resource-group "$RG" --name "$APP" \
  --query '[*].{Slot:name,State:state}' --output table 2>/dev/null \
  || echo "  No deployment slots."

# 5. Recent activity log errors (last 1 hour)
echo "[+] Recent error/warning events (last 1h):"
az monitor activity-log list \
  --resource-group "$RG" \
  --start-time "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)" \
  --query '[?level==`Error` || level==`Warning`].{Time:eventTimestamp,Op:operationName.localizedValue,Status:status.localizedValue}' \
  --output table 2>/dev/null || echo "  (no recent errors or az monitor unavailable)"

echo "=== Done ==="
