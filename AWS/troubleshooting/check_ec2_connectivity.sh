#!/usr/bin/env bash
# =============================================================================
# Script : check_ec2_connectivity.sh
# Purpose: Diagnose common EC2 connectivity issues (SG, NACL, route tables)
# Usage  : ./check_ec2_connectivity.sh <instance-id> [region]
# Requires: AWS CLI v2, jq
# =============================================================================
set -euo pipefail

INSTANCE_ID="${1:?Usage: $0 <instance-id> [region]}"
REGION="${2:-us-east-1}"

echo "=== EC2 Connectivity Diagnostics: $INSTANCE_ID ==="

# 1. Instance state
STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --region "$REGION" --query 'Reservations[0].Instances[0].State.Name' --output text)
echo "[Instance State] $STATE"

# 2. Public / Private IP
IPS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].{Public:PublicIpAddress,Private:PrivateIpAddress}' \
  --output json)
echo "[IPs] $IPS"

# 3. Security Groups — inbound rules
SG_IDS=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].SecurityGroups[*].GroupId' --output text)
echo "[Security Groups] $SG_IDS"

for SG in $SG_IDS; do
  echo "  --- Inbound rules for $SG ---"
  aws ec2 describe-security-groups --group-ids "$SG" --region "$REGION" \
    --query 'SecurityGroups[0].IpPermissions' --output table 2>/dev/null || true
done

# 4. Subnet & NACL
SUBNET_ID=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'Reservations[0].Instances[0].SubnetId' --output text)
echo "[Subnet] $SUBNET_ID"

NACL=$(aws ec2 describe-network-acls --region "$REGION" \
  --filters "Name=association.subnet-id,Values=$SUBNET_ID" \
  --query 'NetworkAcls[0].NetworkAclId' --output text)
echo "[NACL] $NACL"

# 5. System / Instance status checks
echo "[Status Checks]"
aws ec2 describe-instance-status --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --query 'InstanceStatuses[0].{System:SystemStatus.Status,Instance:InstanceStatus.Status}' \
  --output table 2>/dev/null || echo "  No status data (instance may be stopped)"

echo "=== Done ==="
