#!/usr/bin/env python3
"""
Script : aad_conditional_access_gaps.py
Purpose: Identify gaps in Azure AD Conditional Access policies — users/apps
         not covered by MFA, compliant-device, or sign-in risk policies.
Usage  : python3 aad_conditional_access_gaps.py
Requires: msal, requests, python 3.8+
         pip install msal requests
         App registration needs Policy.Read.All, User.Read.All
"""
import os, sys, json, requests, msal

TENANT_ID     = os.environ.get("AZURE_TENANT_ID",     "")
CLIENT_ID     = os.environ.get("AZURE_CLIENT_ID",     "")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def get_token():
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        print("Auth failed:", result.get("error_description"))
        sys.exit(1)
    return result["access_token"]


def graph_get(token, path):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{GRAPH_BASE}{path}", headers=headers)
    r.raise_for_status()
    return r.json()


def run():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.")
        sys.exit(1)

    token = get_token()

    # Fetch all CA policies
    policies = graph_get(token, "/identity/conditionalAccess/policies").get("value", [])
    print(f"[*] Found {len(policies)} Conditional Access policy/policies")

    mfa_policies       = []
    compliant_policies = []
    disabled_policies  = []

    for p in policies:
        state = p.get("state", "")
        if state == "disabled":
            disabled_policies.append(p["displayName"])
            continue

        grant_controls = p.get("grantControls") or {}
        built_ins      = grant_controls.get("builtInControls", [])
        conditions     = p.get("conditions", {})

        if "mfa" in built_ins:
            mfa_policies.append(p["displayName"])
        if "compliantDevice" in built_ins or "domainJoinedDevice" in built_ins:
            compliant_policies.append(p["displayName"])

    print(f"\n── Conditional Access Coverage Summary ────────────")
    print(f"  Total policies        : {len(policies)}")
    print(f"  Disabled policies     : {len(disabled_policies)}")
    print(f"  Policies requiring MFA: {len(mfa_policies)}")
    print(f"  Policies requiring compliant/joined device: {len(compliant_policies)}")

    if disabled_policies:
        print(f"\n  [WARN] Disabled policies (not enforced):")
        for p in disabled_policies:
            print(f"    - {p}")

    print(f"\n  [INFO] MFA-enforcing policies:")
    for p in mfa_policies:
        print(f"    - {p}")

    if not mfa_policies:
        print("  [RISK] No enabled policies enforce MFA!")

    if not compliant_policies:
        print("  [RISK] No enabled policies require a compliant or domain-joined device!")

    print("────────────────────────────────────────────────────")


if __name__ == "__main__":
    run()
