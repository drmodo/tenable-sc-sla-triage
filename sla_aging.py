#!/usr/bin/env python3
"""
Tenable.sc SLA & remediation aging.

Pulls CUMULATIVE (open) findings from Tenable Security Center, ages each one from
its Vulnerability Discovered date (firstSeen), tiers by VPR, flags CISA KEV
membership, and writes a prioritized CSV plus a printed summary.

Read-only: this script never launches scans or modifies the instance.

Usage:
    pip install pytenable
    export TSC_URL="https://your-sc-host"
    export TSC_ACCESS_KEY="..."
    export TSC_SECRET_KEY="..."
    python sla_aging.py [--repo <id>] [--out report.csv]

Never hard-code credentials in this file. Use environment variables.
"""

import argparse
import csv
import os
import sys
import time
from datetime import datetime, timezone

try:
    from tenable.sc import TenableSC
except ImportError:
    sys.exit("pyTenable not installed. Run: pip install pytenable")

# SLA targets in days, measured from Vulnerability Discovered. Edit to match the
# program's policy, or override interactively before running.
SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}

# Days-before-deadline that counts as "approaching breach".
APPROACHING_WINDOW = 7


def vpr_tier(vpr):
    """Map a VPR score to a severity tier."""
    try:
        v = float(vpr)
    except (TypeError, ValueError):
        return "Low"
    if v >= 9.0:
        return "Critical"
    if v >= 7.0:
        return "High"
    if v >= 4.0:
        return "Medium"
    return "Low"


def days_open(first_seen_epoch):
    try:
        first = datetime.fromtimestamp(int(first_seen_epoch), tz=timezone.utc)
    except (TypeError, ValueError):
        return None
    return (datetime.now(timezone.utc) - first).days


def connect():
    url = os.environ.get("TSC_URL")
    ak = os.environ.get("TSC_ACCESS_KEY")
    sk = os.environ.get("TSC_SECRET_KEY")
    if not all([url, ak, sk]):
        sys.exit("Set TSC_URL, TSC_ACCESS_KEY, and TSC_SECRET_KEY.")
    return TenableSC(url=url.replace("https://", "").replace("http://", ""),
                     access_key=ak, secret_key=sk)


def fetch_kev_plugins(sc, repo=None):
    """Return the set of pluginIDs that are on the CISA KEV catalog."""
    filters = [("crossRef", "=", "CISA-KNOWN-EXPLOITED|*")]
    if repo:
        filters.append(("repository", "=", str(repo)))
    kev = set()
    for v in sc.analysis.vulns(*filters, tool="sumid", source="cumulative"):
        kev.add(str(v.get("pluginID")))
    return kev


def fetch_findings(sc, repo=None):
    filters = []
    if repo:
        filters.append(("repository", "=", str(repo)))
    # vulndetails gives us vprScore + firstSeen per finding.
    return sc.analysis.vulns(*filters, tool="vulndetails", source="cumulative")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="Repository ID to scope to", default=None)
    ap.add_argument("--out", help="Output CSV path", default="tsc_sla_report.csv")
    args = ap.parse_args()

    sc = connect()
    print("Fetching CISA KEV plugins ...")
    kev = fetch_kev_plugins(sc, args.repo)
    print(f"  {len(kev)} KEV-listed plugins present.")

    print("Fetching cumulative (open) findings ...")
    rows = []
    tier_stats = {t: {"open": 0, "breach": 0} for t in SLA_DAYS}
    approaching = 0
    kev_open = 0

    for f in fetch_findings(sc, args.repo):
        plugin = str(f.get("pluginID"))
        vpr = f.get("vprScore")
        tier = vpr_tier(vpr)
        age = days_open(f.get("firstSeen"))
        if age is None:
            continue
        sla = SLA_DAYS[tier]
        is_kev = plugin in kev
        # KEV findings are aged against the Critical SLA regardless of VPR.
        effective_sla = SLA_DAYS["Critical"] if is_kev else sla
        over = age - effective_sla
        if is_kev:
            kev_open += 1
        status = "BREACH" if over > 0 else "ok"
        if over > 0:
            tier_stats[tier]["breach"] += 1
        elif -APPROACHING_WINDOW <= over <= 0:
            approaching += 1
            status = "approaching"
        tier_stats[tier]["open"] += 1

        rows.append({
            "pluginID": plugin,
            "name": f.get("name", ""),
            "vpr": vpr,
            "tier": tier,
            "kev": "YES" if is_kev else "",
            "ip": f.get("ip", ""),
            "dnsName": f.get("dnsName", ""),
            "discovered": datetime.fromtimestamp(
                int(f.get("firstSeen")), tz=timezone.utc).strftime("%Y-%m-%d"),
            "days_open": age,
            "sla_days": effective_sla,
            "days_over_sla": over,
            "status": status,
        })

    # Sort: KEV first, then VPR desc, then days-over-SLA desc.
    def sort_key(r):
        return (r["kev"] != "YES", -(float(r["vpr"] or 0)), -(r["days_over_sla"]))
    rows.sort(key=sort_key)

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else [])
        w.writeheader()
        w.writerows(rows)

    # Printed summary.
    total = len(rows)
    total_breach = sum(t["breach"] for t in tier_stats.values())
    print("\n=== SLA SUMMARY ===")
    print(f"Open findings:        {total}")
    print(f"In breach:            {total_breach}")
    print(f"Approaching (<= {APPROACHING_WINDOW}d): {approaching}")
    print(f"KEV-listed open:      {kev_open}  <-- highest urgency")
    print("\nTier        open   breach   %compliant")
    for t in ["Critical", "High", "Medium", "Low"]:
        o = tier_stats[t]["open"]
        b = tier_stats[t]["breach"]
        pct = f"{100*(o-b)/o:.0f}%" if o else "n/a"
        print(f"{t:<10} {o:>6} {b:>8}   {pct:>8}")
    print(f"\nFull ranked queue written to: {args.out}")


if __name__ == "__main__":
    main()
