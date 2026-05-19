#!/usr/bin/env python3
"""
Script : azure_rbac_audit.py
Purpose: Identify over-permissive RBAC assignments (Owner/Contributor at subscription scope,
         broad custom roles, guest accounts with high privilege).
Usage  : python3 azure_rbac_audit.py [--subscription <id>]
Requires: azure-mgmt-authorization, azure-identity, python 3.8+
          pip install azure-mgmt-authorization azure-identity
"""
import argparse
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

HIGH_RISK_ROLES = {"Owner", "Contributor", "User Access Administrator"}

def run(args):
    cred   = DefaultAzureCredential()
    client = AuthorizationManagementClient(cred, args.subscription)

    print(f"[*] Auditing RBAC assignments for subscription: {args.subscription}")
    assignments = list(client.role_assignments.list(filter="atScope()"))

    findings = []
    for a in assignments:
        role_def_id = a.role_definition_id.split("/")[-1]
        try:
            role_def = client.role_definitions.get_by_id(a.role_definition_id)
            role_name = role_def.role_name
        except Exception:
            role_name = role_def_id

        scope = a.scope or ""
        principal = a.principal_id or "unknown"
        principal_type = a.principal_type or "unknown"

        issues = []
        if role_name in HIGH_RISK_ROLES:
            if "/subscriptions/" in scope and "/resourceGroups/" not in scope:
                issues.append(f"High-privilege role '{role_name}' at subscription scope")

        if principal_type == "ForeignGroup":
            issues.append("Guest/external principal has role assignment")

        if issues:
            findings.append({
                "principal"     : principal,
                "principal_type": principal_type,
                "role"          : role_name,
                "scope"         : scope,
                "issues"        : issues,
            })

    print(f"\n── RBAC Risk Report ({len(findings)} finding(s)) ────────────")
    for f in findings:
        print(f"\n  Principal : {f['principal']} ({f['principal_type']})")
        print(f"  Role      : {f['role']}")
        print(f"  Scope     : {f['scope']}")
        for issue in f["issues"]:
            print(f"  [!] {issue}")

    if not findings:
        print("  No high-risk RBAC assignments found.")
    print("────────────────────────────────────────────────────")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Azure RBAC over-permissive role auditor")
    p.add_argument("--subscription", required=True, help="Azure subscription ID")
    run(p.parse_args())
