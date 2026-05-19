#!/usr/bin/env python3
"""
Script : gcp_iam_overpermissive_audit.py
Purpose: Find GCP project IAM bindings with primitive roles (owner/editor/viewer)
         or allUsers / allAuthenticatedUsers granted on sensitive roles.
Usage  : python3 gcp_iam_overpermissive_audit.py [--project <id>]
Requires: google-cloud-resource-manager, google-auth, python 3.8+
          pip install google-cloud-resource-manager google-auth
"""
import argparse
from google.cloud import resourcemanager_v3
from google.oauth2 import google_auth_httplib2
import subprocess, json

PRIMITIVE_ROLES   = {"roles/owner", "roles/editor", "roles/viewer"}
PUBLIC_MEMBERS    = {"allUsers", "allAuthenticatedUsers"}
SENSITIVE_ROLES   = {
    "roles/owner", "roles/editor",
    "roles/iam.securityAdmin", "roles/iam.serviceAccountTokenCreator",
    "roles/storage.admin", "roles/compute.admin",
}


def get_iam_policy(project):
    result = subprocess.run(
        ["gcloud", "projects", "get-iam-policy", project, "--format=json"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def run(args):
    project = args.project or subprocess.run(
        ["gcloud", "config", "get-value", "project"],
        capture_output=True, text=True,
    ).stdout.strip()

    print(f"[*] Auditing IAM policy for project: {project}")
    policy = get_iam_policy(project)
    bindings = policy.get("bindings", [])
    findings = []

    for binding in bindings:
        role    = binding.get("role", "")
        members = binding.get("members", [])

        for member in members:
            issues = []
            member_type = member.split(":")[0] if ":" in member else member

            # Primitive roles at project level
            if role in PRIMITIVE_ROLES:
                issues.append(f"Primitive role '{role}' assigned at project level")

            # Public access on sensitive roles
            if member in PUBLIC_MEMBERS and role in SENSITIVE_ROLES:
                issues.append(f"PUBLIC member '{member}' has sensitive role '{role}'")

            # Any public access
            if member in PUBLIC_MEMBERS:
                issues.append(f"PUBLIC member '{member}' has role '{role}'")

            # Service account with owner
            if member_type == "serviceAccount" and role == "roles/owner":
                issues.append("Service account has Owner role")

            if issues:
                findings.append({
                    "member": member,
                    "role"  : role,
                    "issues": issues,
                })

    print(f"\n── GCP IAM Risk Report ({len(findings)} finding(s)) ──────────")
    for f in findings:
        print(f"\n  Member : {f['member']}")
        print(f"  Role   : {f['role']}")
        for i in f["issues"]:
            print(f"  [!] {i}")

    if not findings:
        print("  No high-risk IAM bindings found.")
    print("──────────────────────────────────────────────────────")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="GCP IAM over-permissive binding auditor")
    p.add_argument("--project", help="GCP project ID (defaults to active gcloud project)")
    run(p.parse_args())
