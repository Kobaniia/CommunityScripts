#!/usr/bin/env bash
# =============================================================================
# Script : gcp_firewall_audit.sh
# Purpose: Find overly permissive GCP VPC firewall rules (0.0.0.0/0 ingress,
#          all-ports, default-allow rules) across a project.
# Usage  : ./gcp_firewall_audit.sh [project]
# Requires: gcloud CLI, python3
# =============================================================================
set -euo pipefail

PROJECT="${1:-$(gcloud config get-value project)}"
echo "=== GCP Firewall Rule Audit (project: $PROJECT) ==="

gcloud compute firewall-rules list --project="$PROJECT" \
  --format=json 2>/dev/null | python3 - << 'PYEOF'
import sys, json

rules = json.load(sys.stdin)
findings = []
ok_count = 0

for r in rules:
    name        = r.get("name", "unknown")
    direction   = r.get("direction", "INGRESS")
    priority    = r.get("priority", 1000)
    disabled    = r.get("disabled", False)
    src_ranges  = r.get("sourceRanges", [])
    allowed     = r.get("allowed", [])
    target_tags = r.get("targetTags", [])
    action      = "ALLOW" if "allowed" in r else "DENY"

    if disabled or direction != "INGRESS" or action != "ALLOW":
        ok_count += 1
        continue

    issues = []

    # Wide-open source
    if "0.0.0.0/0" in src_ranges or "::/0" in src_ranges:
        issues.append("Source: 0.0.0.0/0 (internet)")

    # All ports / all protocols
    for a in allowed:
        proto = a.get("IPProtocol", "")
        ports = a.get("ports", [])
        if proto == "all":
            issues.append("Protocol: ALL (no port restriction)")
        elif not ports or "0-65535" in ports:
            issues.append(f"Protocol: {proto} — all ports open")

    # High-risk ports open to internet
    RISKY_PORTS = {"22": "SSH", "3389": "RDP", "23": "Telnet", "3306": "MySQL",
                   "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB"}
    if "0.0.0.0/0" in src_ranges:
        for a in allowed:
            for port in a.get("ports", []):
                if port in RISKY_PORTS:
                    issues.append(f"Port {port} ({RISKY_PORTS[port]}) open to internet")

    # Default (low-priority) allow rules
    if name.startswith("default-allow") and priority >= 65534:
        issues.append("Default network allow rule (consider removing)")

    if issues:
        findings.append((name, priority, src_ranges, target_tags, issues))
    else:
        ok_count += 1

print(f"  Rules with issues : {len(findings)}")
print(f"  Rules OK          : {ok_count}\n")

for name, prio, src, tags, issues in sorted(findings, key=lambda x: x[1]):
    print(f"  [RISK] {name}  (priority={prio})")
    print(f"         Src    : {', '.join(src)}")
    print(f"         Targets: {', '.join(tags) if tags else 'ALL instances'}")
    for i in issues:
        print(f"         ⚠  {i}")
    print()

PYEOF

echo "=== Done ==="
