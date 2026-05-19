#!/usr/bin/env bash
# =============================================================================
# Script : s3_public_bucket_scanner.sh
# Purpose: Find S3 buckets with public ACLs or missing Block Public Access
# Usage  : ./s3_public_bucket_scanner.sh [--region us-east-1]
# Requires: AWS CLI v2, jq
# =============================================================================
set -euo pipefail

REGION="${1:-us-east-1}"
RISKY=()

echo "=== S3 Public Exposure Scanner ==="
echo "[*] Enumerating buckets …"

BUCKETS=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text)

for BUCKET in $BUCKETS; do
  ISSUES=()

  # Check Block Public Access settings
  BPA=$(aws s3api get-public-access-block --bucket "$BUCKET" 2>/dev/null \
    || echo '{"PublicAccessBlockConfiguration":{}}')

  BLOCK_ACL=$(echo "$BPA"   | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls // false')
  IGNORE_ACL=$(echo "$BPA"  | jq -r '.PublicAccessBlockConfiguration.IgnorePublicAcls // false')
  BLOCK_POL=$(echo "$BPA"   | jq -r '.PublicAccessBlockConfiguration.BlockPublicPolicy // false')
  RESTRICT_POL=$(echo "$BPA"| jq -r '.PublicAccessBlockConfiguration.RestrictPublicBuckets // false')

  [[ "$BLOCK_ACL"    != "true" ]] && ISSUES+=("BlockPublicAcls=OFF")
  [[ "$IGNORE_ACL"   != "true" ]] && ISSUES+=("IgnorePublicAcls=OFF")
  [[ "$BLOCK_POL"    != "true" ]] && ISSUES+=("BlockPublicPolicy=OFF")
  [[ "$RESTRICT_POL" != "true" ]] && ISSUES+=("RestrictPublicBuckets=OFF")

  # Check bucket ACL
  ACL_GRANTS=$(aws s3api get-bucket-acl --bucket "$BUCKET" 2>/dev/null \
    | jq -r '.Grants[] | select(.Grantee.URI? == "http://acs.amazonaws.com/groups/global/AllUsers") | .Permission' 2>/dev/null || true)
  [[ -n "$ACL_GRANTS" ]] && ISSUES+=("PUBLIC_ACL:$ACL_GRANTS")

  if [[ ${#ISSUES[@]} -gt 0 ]]; then
    RISKY+=("$BUCKET")
    echo "  [RISK] $BUCKET — ${ISSUES[*]}"
  else
    echo "  [OK]   $BUCKET"
  fi
done

echo ""
echo "=== Summary: ${#RISKY[@]} bucket(s) with public exposure risks ==="
for B in "${RISKY[@]}"; do echo "  $B"; done
