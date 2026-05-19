#!/usr/bin/env bash
# =============================================================================
# Script : azure_vm_health_check.sh
# Purpose: Check Azure VM health, NSG rules, boot diagnostics, and disk status
# Usage  : ./azure_vm_health_check.sh <resource-group> <vm-name>
# Requires: Azure CLI (az), jq
# =============================================================================
set -euo pipefail

RG="${1:?Usage: $0 <resource-group> <vm-name>}"
VM="${2:?Usage: $0 <resource-group> <vm-name>}"

echo "=== Azure VM Health Check: $VM (RG: $RG) ==="

# 1. Power state
echo "[+] Power state:"
az vm get-instance-view --resource-group "$RG" --name "$VM" \
  --query 'instanceView.statuses[?starts_with(code,`PowerState`)].displayStatus' \
  --output tsv

# 2. OS disk status
echo "[+] OS disk:"
az vm show --resource-group "$RG" --name "$VM" \
  --query '{DiskName:storageProfile.osDisk.name, Caching:storageProfile.osDisk.caching}' \
  --output table

# 3. Data disks
echo "[+] Data disks:"
az vm show --resource-group "$RG" --name "$VM" \
  --query 'storageProfile.dataDisks[*].{Name:name,SizeGB:diskSizeGb,Lun:lun}' \
  --output table

# 4. NIC & NSG
echo "[+] Network interfaces:"
NIC_IDS=$(az vm show --resource-group "$RG" --name "$VM" \
  --query 'networkProfile.networkInterfaces[*].id' --output tsv)

for NIC_ID in $NIC_IDS; do
  NIC_NAME=$(basename "$NIC_ID")
  NIC_RG=$(echo "$NIC_ID" | cut -d'/' -f5)
  echo "  NIC: $NIC_NAME"

  NSG_ID=$(az network nic show --ids "$NIC_ID" \
    --query 'networkSecurityGroup.id' --output tsv 2>/dev/null || echo "")
  if [[ -n "$NSG_ID" ]]; then
    NSG_NAME=$(basename "$NSG_ID")
    NSG_RG=$(echo "$NSG_ID" | cut -d'/' -f5)
    echo "  NSG: $NSG_NAME — Security Rules:"
    az network nsg rule list --resource-group "$NSG_RG" --nsg-name "$NSG_NAME" \
      --query '[*].{Name:name,Priority:priority,Access:access,Direction:direction,Port:destinationPortRange,Src:sourceAddressPrefix}' \
      --output table 2>/dev/null || true
  else
    echo "  NSG: None attached"
  fi
done

# 5. Boot diagnostics
echo "[+] Boot diagnostics:"
az vm boot-diagnostics get-boot-log --resource-group "$RG" --name "$VM" 2>/dev/null \
  | tail -30 || echo "  Boot diagnostics not enabled or unavailable."

echo "=== Done ==="
