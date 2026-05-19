#!/usr/bin/env bash
# =============================================================================
# Script : gcs_public_bucket_scanner.sh
# Purpose: Find GCS buckets in a project that allow public (allUsers / allAuthenticatedUsers) access.
# Usage  : ./gcs_public_bucket_scanner.sh [project]
# Requires: gcloud CLI, gsutil (or gcloud storage)
# =============================================================================
set -euo pipefail

PROJECT="${1:-$(gcloud config get-value project)}"
RISKY=()

echo "=== GCS Public Bucket Scanner (project: $PROJECT) ==="

BUCKETS=$(gcloud storage buckets list --project="$PROJECT" --format="value(name)" 2>/dev/null)

if [[ -z "$BUCKETS" ]]; then
  echo "No buckets found in project $PROJECT."
  exit 0
fi

for BUCKET in $BUCKETS; do
  # Get IAM policy and check for public members
  POLICY=$(gcloud storage buckets get-iam-policy "gs://$BUCKET" \
    --format=json 2>/dev/null || echo '{"bindings":[]}')

  PUBLIC=$(echo "$POLICY" | python3 -c "
import sys, json
policy = json.load(sys.stdin)
hits = []
for b in policy.get('bindings', []):
    for m in b.get('members', []):
        if m in ('allUsers', 'allAuthenticatedUsers'):
            hits.append(f\"{m}=>{b['role']}\")
print(', '.join(hits))
")

  if [[ -n "$PUBLIC" ]]; then
    echo "  [RISK] gs://$BUCKET — $PUBLIC"
    RISKY+=("$BUCKET")
  else
    # Also check uniform bucket-level access (good practice)
    UBLA=$(gcloud storage buckets describe "gs://$BUCKET" \
      --format="value(iamConfiguration.uniformBucketLevelAccess.enabled)" 2>/dev/null || echo "false")
    if [[ "$UBLA" != "True" && "$UBLA" != "true" ]]; then
      echo "  [WARN] gs://$BUCKET — Uniform Bucket-Level Access DISABLED (ACLs possible)"
    else
      echo "  [OK]   gs://$BUCKET"
    fi
  fi
done

echo ""
echo "=== Summary: ${#RISKY[@]} publicly accessible bucket(s) ==="
for B in "${RISKY[@]}"; do echo "  gs://$B"; done
