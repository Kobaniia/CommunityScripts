#!/usr/bin/env bash
# =============================================================================
# Script : gke_cluster_troubleshoot.sh
# Purpose: Diagnose GKE cluster issues — node health, pod failures, quotas
# Usage  : ./gke_cluster_troubleshoot.sh <cluster-name> <zone-or-region> [project]
# Requires: gcloud CLI, kubectl configured for the cluster
# =============================================================================
set -euo pipefail

CLUSTER="${1:?Usage: $0 <cluster-name> <zone-or-region> [project]}"
LOCATION="${2:?Usage: $0 <cluster-name> <zone-or-region> [project]}"
PROJECT="${3:-$(gcloud config get-value project)}"

echo "=== GKE Cluster Diagnostics: $CLUSTER ($LOCATION) ==="

# Configure kubectl credentials
gcloud container clusters get-credentials "$CLUSTER" \
  --zone "$LOCATION" --project "$PROJECT" 2>/dev/null

# 1. Cluster status
echo "[+] Cluster status:"
gcloud container clusters describe "$CLUSTER" \
  --zone "$LOCATION" --project "$PROJECT" \
  --format="table(status, currentMasterVersion, currentNodeVersion, nodeConfig.machineType)"

# 2. Node pool health
echo "[+] Node pools:"
gcloud container node-pools list --cluster "$CLUSTER" \
  --zone "$LOCATION" --project "$PROJECT" \
  --format="table(name, status, autoscaling.enabled, initialNodeCount)"

# 3. Nodes not Ready
echo "[+] Nodes not in Ready state:"
kubectl get nodes --no-headers | grep -v " Ready" || echo "  All nodes are Ready."

# 4. Pods in non-Running/Completed state
echo "[+] Unhealthy pods (all namespaces):"
kubectl get pods --all-namespaces --no-headers \
  | grep -Ev "\s(Running|Completed)\s" \
  | awk '{print "  NS:"$1, "Pod:"$2, "Status:"$4, "Restarts:"$5}' \
  || echo "  All pods healthy."

# 5. Recent pod events (warnings)
echo "[+] Recent Warning events:"
kubectl get events --all-namespaces --field-selector type=Warning \
  --sort-by='.lastTimestamp' 2>/dev/null | tail -20 || echo "  No warning events."

# 6. Resource quota usage
echo "[+] Resource quotas:"
kubectl describe resourcequota --all-namespaces 2>/dev/null \
  | grep -A4 "Resource\|Used\|Hard" || echo "  No resource quotas defined."

echo "=== Done ==="
