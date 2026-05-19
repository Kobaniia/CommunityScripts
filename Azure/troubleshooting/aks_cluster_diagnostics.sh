#!/usr/bin/env bash
# =============================================================================
# Script : aks_cluster_diagnostics.sh
# Purpose: Diagnose AKS cluster issues — node pool health, pod failures,
#          resource pressure, and recent upgrade history.
# Usage  : ./aks_cluster_diagnostics.sh <resource-group> <cluster-name>
# Requires: Azure CLI (az), kubectl configured for the cluster
# =============================================================================
set -euo pipefail

RG="${1:?Usage: $0 <resource-group> <cluster-name>}"
CLUSTER="${2:?Usage: $0 <resource-group> <cluster-name>}"

echo "=== AKS Cluster Diagnostics: $CLUSTER ===" 

# Get credentials
az aks get-credentials --resource-group "$RG" --name "$CLUSTER" --overwrite-existing 2>/dev/null

# 1. Cluster overview
echo "[+] Cluster info:"
az aks show --resource-group "$RG" --name "$CLUSTER" \
  --query '{Version:kubernetesVersion, ProvisionState:provisioningState, FQDN:fqdn, SKU:sku.tier}' \
  --output table

# 2. Node pool status
echo "[+] Node pools:"
az aks nodepool list --resource-group "$RG" --cluster-name "$CLUSTER" \
  --query '[*].{Name:name,Mode:mode,State:provisioningState,Count:count,VMSize:vmSize,K8sVersion:orchestratorVersion}' \
  --output table

# 3. Nodes not Ready
echo "[+] Nodes not Ready:"
kubectl get nodes --no-headers | grep -v " Ready" || echo "  All nodes are Ready."

# 4. Node resource pressure
echo "[+] Node resource usage (top nodes — requires metrics-server):"
kubectl top nodes 2>/dev/null || echo "  Metrics server unavailable."

# 5. Unhealthy pods
echo "[+] Unhealthy pods:"
kubectl get pods --all-namespaces --no-headers \
  | grep -Ev "\s(Running|Completed)\s" \
  | awk '{printf "  %-30s %-40s %-15s Restarts:%s\n", $1, $2, $4, $5}' \
  || echo "  All pods healthy."

# 6. OOMKilled containers in last 30 mins
echo "[+] Recent OOMKilled events:"
kubectl get events --all-namespaces --field-selector reason=OOMKilling \
  --sort-by='.lastTimestamp' 2>/dev/null | tail -10 \
  || echo "  No OOMKill events."

# 7. Pending PVCs
echo "[+] Pending PersistentVolumeClaims:"
kubectl get pvc --all-namespaces --no-headers | grep -v "Bound" \
  || echo "  All PVCs bound."

# 8. Cluster upgrade history
echo "[+] Available upgrades:"
az aks get-upgrades --resource-group "$RG" --name "$CLUSTER" \
  --query 'agentPoolProfiles[0].upgrades[*].kubernetesVersion' \
  --output tsv 2>/dev/null || echo "  (none available)"

echo "=== Done ==="
