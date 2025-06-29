#!/usr/bin/env python3
"""
OWASP ZAP Baseline Scan
https://www.zaproxy.org/

This script runs ZAP in baseline mode, which performs a passive scan of the given target URL.

Requires ZAP to be running in daemon mode or via GUI with the API enabled.
"""

import argparse
import json
import os
import sys
import time
from urllib.parse import urlparse

from zapv2 import ZAPv2


def passive_scan(zap, target):
    zap.urlopen(target)
    print(f"Accessing target: {target}")
    time.sleep(2)
    while int(zap.pscan.records_to_scan) > 0:
        print(f"Records to scan: {zap.pscan.records_to_scan}")
        time.sleep(1)
    print("Passive scan complete")


def save_report(zap, json_output):
    alerts = zap.core.alerts()
    with open(json_output, "w") as f:
        json.dump({"alerts": alerts}, f, indent=2)
    print(f"Report saved to {json_output}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument(
        "-J", "--json", default="zap-report.json", help="Output report in JSON"
    )
    parser.add_argument(
        "-z",
        "--zap-url",
        default="http://localhost:8080",
        help="ZAP address (default: http://localhost:8080)",
    )
    args = parser.parse_args()

    target = args.target
    json_output = args.json
    zap_url = args.zap_url

    parsed_url = urlparse(zap_url)
    zap = ZAPv2(proxies={"http": zap_url, "https": zap_url})

    try:
        zap.urlopen(target)
        time.sleep(1)
        passive_scan(zap, target)
        save_report(zap, json_output)
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
