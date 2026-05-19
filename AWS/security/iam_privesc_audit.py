#!/usr/bin/env python3
"""
Script : iam_privesc_audit.py
Purpose: Detect IAM users/roles with privilege-escalation risk paths
         (e.g. iam:CreatePolicyVersion, iam:AttachUserPolicy, sts:AssumeRole combos)
Usage  : python3 iam_privesc_audit.py [--region us-east-1] [--output report.json]
Requires: boto3, python 3.8+
"""
import argparse, boto3, json
from collections import defaultdict

RISKY_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "iam:PassRole",
    "cloudformation:CreateStack",
    "glue:CreateDevEndpoint",
}


def get_all_entities(iam):
    """Return all users and roles with their attached / inline policies."""
    entities = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page["Users"]:
            entities.append({"type": "user", "name": u["UserName"], "arn": u["Arn"]})

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            entities.append({"type": "role", "name": r["RoleName"], "arn": r["Arn"]})

    return entities


def effective_actions(iam, entity):
    """Collect all Allow actions for an entity across attached + inline policies."""
    actions = set()
    etype = entity["type"]
    name  = entity["name"]

    # Attached policies
    list_fn = iam.list_attached_user_policies if etype == "user" else iam.list_attached_role_policies
    kw = {"UserName": name} if etype == "user" else {"RoleName": name}
    for policy in list_fn(**kw).get("AttachedPolicies", []):
        pv = iam.get_policy_version(
            PolicyArn=policy["PolicyArn"],
            VersionId=iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"],
        )
        for stmt in pv["PolicyVersion"]["Document"].get("Statement", []):
            if stmt.get("Effect") == "Allow":
                acts = stmt.get("Action", [])
                if isinstance(acts, str):
                    acts = [acts]
                actions.update(acts)

    # Inline policies
    inline_fn = iam.list_user_policies if etype == "user" else iam.list_role_policies
    get_fn    = iam.get_user_policy    if etype == "user" else iam.get_role_policy
    gkw_key   = "UserName"             if etype == "user" else "RoleName"
    for pname in inline_fn(**kw).get("PolicyNames", []):
        doc = get_fn(**{gkw_key: name, "PolicyName": pname})["PolicyDocument"]
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                acts = stmt.get("Action", [])
                if isinstance(acts, str):
                    acts = [acts]
                actions.update(acts)

    return actions


def run(args):
    iam     = boto3.client("iam", region_name=args.region)
    results = []

    entities = get_all_entities(iam)
    print(f"[*] Scanning {len(entities)} entities for privilege-escalation risks …")

    for entity in entities:
        try:
            actions = effective_actions(iam, entity)
        except Exception as e:
            print(f"  [!] Could not evaluate {entity['name']}: {e}")
            continue

        # Wildcard admin check
        if "*" in actions or "iam:*" in actions:
            risky = list(RISKY_ACTIONS)
        else:
            risky = sorted(RISKY_ACTIONS & actions)

        if risky:
            results.append({
                "type"         : entity["type"],
                "name"         : entity["name"],
                "arn"          : entity["arn"],
                "risky_actions": risky,
                "risk_count"   : len(risky),
            })

    results.sort(key=lambda x: x["risk_count"], reverse=True)

    print(f"\n── Privilege Escalation Risk Report ──────────────")
    print(f"  Entities scanned : {len(entities)}")
    print(f"  At-risk entities : {len(results)}")
    for r in results:
        print(f"\n  [{r['type'].upper()}] {r['name']}  ({r['risk_count']} risky actions)")
        for a in r["risky_actions"]:
            print(f"    - {a}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Full report saved to {args.output}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="IAM privilege-escalation auditor")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--output", help="Optional path to save JSON report")
    run(p.parse_args())
