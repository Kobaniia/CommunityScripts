#!/usr/bin/env python3
"""
Script : vpc_flowlog_rejection_analyzer.py
Purpose: Query VPC Flow Logs via CloudWatch Logs Insights for top REJECT traffic
         to identify misconfigured SGs/NACLs or potential port-scan activity.
Usage  : python3 vpc_flowlog_rejection_analyzer.py --log-group /aws/vpc/flowlogs [--hours 6] [--top 20]
Requires: boto3, python 3.8+
"""
import argparse, boto3, time
from datetime import datetime, timezone, timedelta


def run(args):
    cw    = boto3.client("logs", region_name=args.region)
    end   = int(datetime.now(timezone.utc).timestamp())
    start = int((datetime.now(timezone.utc) - timedelta(hours=args.hours)).timestamp())

    query = f"""
        filter action = "REJECT"
        | stats
            count()                    as rejections,
            sum(bytes)                 as total_bytes
          by srcAddr, dstAddr, dstPort, protocol
        | sort rejections desc
        | limit {args.top}
    """

    print(f"[*] Querying {args.log_group} for REJECT events — last {args.hours}h …")
    resp = cw.start_query(
        logGroupName=args.log_group,
        startTime=start,
        endTime=end,
        queryString=query,
    )
    qid = resp["queryId"]

    while True:
        result = cw.get_query_results(queryId=qid)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(1)

    if result["status"] != "Complete" or not result["results"]:
        print("No REJECT events found in this window.")
        return

    print(f"\n── Top {args.top} Rejected Flows ──────────────────────────────")
    print(f"  {'SrcAddr':<20} {'DstAddr':<20} {'DstPort':<8} {'Proto':<8} {'Rejects':>8} {'Bytes':>12}")
    print(f"  {'-'*20} {'-'*20} {'-'*8} {'-'*8} {'-'*8} {'-'*12}")

    PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}
    for row in result["results"]:
        r = {f["field"]: f["value"] for f in row}
        proto = PROTO_MAP.get(r.get("protocol", "?"), r.get("protocol", "?"))
        print(
            f"  {r.get('srcAddr','?'):<20} {r.get('dstAddr','?'):<20} "
            f"{r.get('dstPort','?'):<8} {proto:<8} "
            f"{int(float(r.get('rejections',0))):>8,} "
            f"{int(float(r.get('total_bytes',0))):>12,}"
        )

    print("────────────────────────────────────────────────────────────────")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="VPC Flow Log rejection analyzer")
    p.add_argument("--log-group", required=True, help="CloudWatch Log Group name")
    p.add_argument("--hours",     type=int, default=6,    help="Lookback window in hours")
    p.add_argument("--top",       type=int, default=20,   help="Number of top flows to display")
    p.add_argument("--region",    default="us-east-1")
    run(p.parse_args())
