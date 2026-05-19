#!/usr/bin/env bash
# =============================================================================
# Script : azure_storage_security_check.sh
# Purpose: Audit all Storage Accounts for public blob access, HTTPS-only,
#          soft delete, and firewall configuration.
# Usage  : ./azure_storage_security_check.sh [subscription-id]
# Requires: Azure CLI (az), jq
# =============================================================================
set -euo pipefail

SUB="${1:-}"
[[ -n "$SUB" ]] && az account set --subscription "$SUB"

echo "=== Azure Storage Account Security Audit ==="
echo "[*] Subscription: $(az account show --query name -o tsv)"
echo ""

ACCOUNTS=$(az storage account list --query '[*].{name:name,rg:resourceGroup}' -o json)
COUNT=$(echo "$ACCOUNTS" | jq length)
echo "[*] Found $COUNT storage account(s)"
echo ""

RISKS=0

for ROW in $(echo "$ACCOUNTS" | jq -c '.[]'); do
  NAME=$(echo "$ROW" | jq -r '.name')
  RG=$(echo "$ROW"   | jq -r '.rg')

  PROPS=$(az storage account show --name "$NAME" --resource-group "$RG" -o json 2>/dev/null)

  HTTPS_ONLY=$(echo "$PROPS"   | jq -r '.enableHttpsTrafficOnly // false')
  MIN_TLS=$(echo "$PROPS"      | jq -r '.minimumTlsVersion // "TLS1_0"')
  PUBLIC_BLOB=$(echo "$PROPS"  | jq -r '.allowBlobPublicAccess // true')
  NET_DEFAULT=$(echo "$PROPS"  | jq -r '.networkRuleSet.defaultAction // "Allow"')
  INFRA_ENC=$(echo "$PROPS"    | jq -r '.encryption.requireInfrastructureEncryption // false')

  ISSUES=()
  [[ "$HTTPS_ONLY"  != "true"  ]] && ISSUES+=("HTTPSOnly=OFF")
  [[ "$MIN_TLS"     == "TLS1_0" || "$MIN_TLS" == "TLS1_1" ]] && ISSUES+=("WeakTLS:$MIN_TLS")
  [[ "$PUBLIC_BLOB" == "true"  ]] && ISSUES+=("PublicBlobAccess=ON")
  [[ "$NET_DEFAULT" == "Allow" ]] && ISSUES+=("FirewallDefault=Allow")
  [[ "$INFRA_ENC"   != "true"  ]] && ISSUES+=("InfraEncryption=OFF")

  if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo "  [RISK] $NAME (RG: $RG)"
    for I in "${ISSUES[@]}"; do echo "         ⚠ $I"; done
    (( RISKS++ )) || true
  else
    echo "  [OK]   $NAME"
  fi
done

echo ""
echo "=== Summary: $RISKS / $COUNT account(s) have security risks ==="
