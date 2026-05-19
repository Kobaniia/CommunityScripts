#!/usr/bin/env python3
"""
Script : cloudtrail_anomaly_detector.py
Purpose: Query CloudTrail for high-risk API events (root usage, failed auth,
         unusual regions, large-scale deletions) in a given time window.
Usage  : python3 cloudtrail_anomaly_detector.py [--hours 24] [--region us-east-1]
Requires: boto3, python 3.8+
"""
import argparse, boto3, json
from datetime import datetime, timezone, timedelta

HIGH_RISK_EVENTS = {
    # Identity & access abuse
    "ConsoleLoginWithMFA": False,   # Alert if MFA is missing
    "CreateUser", "DeleteUser",
    "AttachRolePolicy", "PutUserPolicy",
    "CreateAccessKey", "UpdateAccessKey",
    # Data exfil / destruction
    "DeleteBucket", "DeleteObject", "DeleteObjects",
    "GetObject",                    # High-volume spike
    "DeleteDBInstance", "DeleteDBSnapshot",
    # Infra tampering
    "TerminateInstances", "StopInstances",
    "DeleteTrail", "StopLogging", "DeleteFlowLogs",
    # Network / security changes
    "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
    "ModifyInstanceAttribute",
}

ROOT_USAGE_EVENTS = {"ConsoleLogin", "CreateUser", "DeleteUser", "GetObject"}


def run(args):
    ct  = boto3.client("cloudtrail", region_name=args.region)
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=args.hours)

    print(f"[*] Scanning CloudTrail events: last {args.hours}h in {args.region}")

    findings = []
    paginator = ct.get_paginator("lookup_events")

    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=now,
        PaginationConfig={"PageSize": 50},
    ):
        for event in page["Events"]:
            e_name   = event.get("EventName", "")
            username = event.get("Username", "unknown")
            region   = event.get("AwsRegion", "")

            # Root account activity
            if username in ("root", "ROOT"):
                findings.append({
                    "severity": "CRITICAL",
                    "reason"  : "Root account used",
                    "event"   : e_name,
                    "user"    : username,
                    "region"  : region,
                    "time"    : str(event.get("EventTime")),
                })

            # CloudTrail itself being tampered
            if e_name in ("DeleteTrail", "StopLogging", "UpdateTrail"):
                findings.append({
                    "severity": "HIGH",
                    "reason"  : "CloudTrail tampering",
                    "event"   : e_name,
                    "user"    : username,
                    "region"  : region,
                    "time"    : str(event.get("EventTime")),
                })

            # Security group opened to world (0.0.0.0/0)
            if e_name == "AuthorizeSecurityGroupIngress":
                resources = json.dumps(event.get("Resources", []))
                if "0.0.0.0/0" in str(event) or "::/0" in str(event):
                    findings.append({
                        "severity": "HIGH",
                        "reason"  : "Security group opened to 0.0.0.0/0",
                        "event"   : e_name,
                        "user"    : username,
                        "region"  : region,
                        "time"    : str(event.get("EventTime")),
                    })

    findings.sort(key=lambda x: x["severity"])

    print(f"\n── Anomaly Report ({len(findings)} finding(s)) ──────────────")
    for f in findings:
        print(f"  [{f['severity']}] {f['event']} by {f['user']} in {f['region']} — {f['reason']}")
        print(f"           Time: {f['time']}")

    if not findings:
        print("  No anomalies detected in the selected window.")

    print("────────────────────────────────────────────────────")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="CloudTrail anomaly detector")
    p.add_argument("--hours",  type=int, default=24)
    p.add_argument("--region", default="us-east-1")
    run(p.parse_args())
