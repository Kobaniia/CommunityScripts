#!/usr/bin/env bash
# =============================================================================
# Script : azure_nsg_audit.sh
# Purpose: Audit all NSGs in a subscription for dangerous inbound rules
#          (SSH/RDP/all-ports open to internet, priority < 200 wide-open rules)
# Usage  : ./azure_nsg_audit.sh [subscription-id]
# Requires: Azure CLI (az), python3, jq
# =============================================================================
set -euo pipefail

SUB="${1:-}"
[[ -n "$SUB" ]] && az account set --subscription "$SUB"

echo "=== Azure NSG Security Audit ==="
echo "[*] Subscription: $(az account show --query name -o tsv)"
echo ""

NSGS=$(az network nsg list --query '[*].{name:name,rg:resourceGroup}' -o json)
COUNT=$(echo "$NSGS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
echo "[*] Found $COUNT NSG(s)"

RISKY=0

for ROW in $(echo "$NSGS" | python3 -c "
import sys, json
for nsg in json.load(sys.stdin):
    print(nsg['name'] + '|' + nsg['rg'])
"); do
  NSG_NAME=$(echo "$ROW" | cut -d'|' -f1)
  RG=$(echo "$ROW"       | cut -d'|' -f2)

  RULES=$(az network nsg rule list \
    --resource-group "$RG" \
    --nsg-name "$NSG_NAME" \
    --query '[?direction==`Inbound` && access==`Allow`]' \
    -o json 2>/dev/null)

  ISSUES=$(echo "$RULES" | python3 << 'PYEOF'
import sys, json

rules = json.load(sys.stdin)
issues = []
DANGEROUS_PORTS = {"22": "SSH", "3389": "RDP", "23": "Telnet",
                   "3306": "MySQL", "5432": "PostgreSQL", "1433": "MSSQL"}

for r in rules:
    name     = r.get("name", "?")
    src      = r.get("sourceAddressPrefix", "")
    port     = r.get("destinationPortRange", "")
    prio     = r.get("priority", 4096)

    if src not in ("Internet", "*", "0.0.0.0/0", "::/0"):
        continue

    if port == "*":
        issues.append(f"Rule '{name}' (prio {prio}): ALL ports open to Internet")

    if port in DANGEROUS_PORTS:
        issues.append(f"Rule '{name}' (prio {prio}): {DANGEROUS_PORTS[port]} (port {port}) open to Internet")

    if prio < 200 and src in ("Internet", "*"):
        issues.append(f"Rule '{name}' (prio {prio}): Very low priority + wildcard source = likely catch-all ALLOW")

for i in issues:
    print(i)
PYEOF
  )

  if [[ -n "$ISSUES" ]]; then
    echo "  [RISK] $NSG_NAME (RG: $RG)"
    echo "$ISSUES" | while read -r line; do echo "         ⚠ $line"; done
    (( RISKY++ )) || true
  else
    echo "  [OK]   $NSG_NAME"
  fi
done

echo ""
echo "=== Summary: $RISKY / $COUNT NSG(s) have risky inbound rules ==="
