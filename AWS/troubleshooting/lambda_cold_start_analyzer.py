#!/usr/bin/env python3
"""
Script : lambda_cold_start_analyzer.py
Purpose: Analyze Lambda cold starts via CloudWatch Logs Insights
Usage  : python3 lambda_cold_start_analyzer.py --function <name> [--hours 24] [--region us-east-1]
Requires: boto3, python 3.8+
"""
import argparse, boto3, time
from datetime import datetime, timezone, timedelta


def run(args):
    cw = boto3.client("logs", region_name=args.region)
    log_group = f"/aws/lambda/{args.function}"
    end   = int(datetime.now(timezone.utc).timestamp())
    start = int((datetime.now(timezone.utc) - timedelta(hours=args.hours)).timestamp())

    query = """
        filter @message like /Init Duration/
        | parse @message "Init Duration: * ms" as init_ms
        | stats
            count()        as cold_starts,
            avg(init_ms)   as avg_init_ms,
            max(init_ms)   as max_init_ms,
            min(init_ms)   as min_init_ms
    """
    print(f"[*] Querying {log_group} for the last {args.hours}h …")
    resp = cw.start_query(
        logGroupName=log_group, startTime=start, endTime=end, queryString=query
    )
    qid = resp["queryId"]

    while True:
        result = cw.get_query_results(queryId=qid)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(1)

    if result["status"] != "Complete" or not result["results"]:
        print("No cold start events found in the selected time window.")
        return

    row = {f["field"]: f["value"] for f in result["results"][0]}
    print("\n── Cold Start Summary ───────────────────────────")
    print(f"  Cold starts : {row.get('cold_starts', 0)}")
    print(f"  Avg init    : {float(row.get('avg_init_ms', 0)):.1f} ms")
    print(f"  Max init    : {float(row.get('max_init_ms', 0)):.1f} ms")
    print(f"  Min init    : {float(row.get('min_init_ms', 0)):.1f} ms")
    print("─────────────────────────────────────────────────")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Lambda cold-start analyzer")
    p.add_argument("--function", required=True, help="Lambda function name")
    p.add_argument("--hours",    type=int, default=24, help="Lookback window in hours")
    p.add_argument("--region",   default="us-east-1")
    run(p.parse_args())
