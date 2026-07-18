---
name: tenable-sc-sla-triage
description: Analyze a Tenable Security Center (Tenable.sc) instance for remediation SLA compliance and produce a risk-prioritized remediation queue. Pulls cumulative vulnerability data via the Tenable.sc API, buckets findings by age against SLA targets using the Vulnerability Discovered date as the SLA clock, prioritizes with VPR (not raw CVSS), and cross-references CISA KEV. Use this skill whenever the user mentions Tenable.sc, Security Center, vulnerability SLA, SLA aging, remediation aging, VPR prioritization, KEV cross-reference, or wants to know which findings are breaching or about to breach SLA — even if they don't say "SLA" explicitly and just ask "which vulns should we fix first" against a Tenable.sc instance.
---

# Tenable Security Center — SLA & Remediation Triage

## What this skill does

Given credentials to a Tenable Security Center (Tenable.sc) instance, this skill
produces an SLA compliance and remediation-prioritization report:

1. Pulls **cumulative** (not mitigated) vulnerability findings via the API.
2. Ages each finding against configurable SLA targets, measured from the
   **Vulnerability Discovered** date — the correct SLA clock, not "last seen".
3. Prioritizes using **VPR** (Vulnerability Priority Rating), not raw CVSS.
4. Flags findings on the **CISA KEV** list, which should jump the queue.
5. Emits a breach summary, an "approaching breach" watchlist, and a ranked
   remediation queue.

## Why the details matter (read before running)

These choices are the difference between a report that reflects reality and one
that quietly lies to leadership:

- **Cumulative vs. Mitigated database.** Tenable.sc keeps two analysis views.
  The *cumulative* view is the current open state; the *mitigated* view is
  findings confirmed remediated. SLA aging must run against **cumulative** —
  querying the wrong database is the single most common reporting error.
- **SLA clock = Vulnerability Discovered.** Age from the date the vuln was first
  discovered on the asset, not "last observed". Using last-observed resets the
  clock on every scan and makes chronic findings look fresh.
- **VPR over CVSS.** CVSS is static severity. VPR is Tenable's dynamic score that
  factors in real-world threat activity, so a CVSS-7 with active exploitation can
  outrank a CVSS-9 that nobody is exploiting. Prioritize the queue by VPR.
- **KEV overrides everything.** Anything on the CISA Known Exploited
  Vulnerabilities catalog is being exploited in the wild right now and belongs at
  the top regardless of VPR or age.

## Default SLA targets

Ask the user for their program's targets; if they don't have any, use these
common defaults (measured from Vulnerability Discovered):

| Severity tier (by VPR) | SLA to remediate |
|------------------------|------------------|
| Critical (VPR 9.0–10)  | 15 days          |
| High (VPR 7.0–8.9)     | 30 days          |
| Medium (VPR 4.0–6.9)   | 90 days          |
| Low (VPR 0.1–3.9)      | 180 days         |

KEV-listed findings: treat as Critical regardless of VPR.

## How to run it

1. **Get connection details** from the user: Tenable.sc host/URL, and API
   **access key + secret key** (preferred over username/password). Never ask the
   user to paste keys into anything but their own environment — if you are running
   in a context where you cannot securely hold secrets, instead hand the user the
   script in `scripts/sla_aging.py` to run themselves.
2. **Confirm the SLA targets** (above) or take the user's.
3. **Run** `scripts/sla_aging.py`. It uses the pyTenable library
   (`pip install pytenable`). It queries the cumulative database, computes aging,
   and writes a CSV plus a printed summary.
4. **Report** using the structure below.

If you need the exact API filter names, tool types, or field syntax, read
`references/sc-query-cookbook.md`.

## Report structure

Always produce the report in this order:

```
# Tenable.sc SLA & Remediation Report — <date>

## Executive summary
- Total open findings, count in breach, count approaching breach (7-day window)
- KEV-listed open findings (call out separately — highest urgency)

## SLA breaches by tier
Table: tier | open | in breach | % compliant

## Approaching-breach watchlist
Findings within 7 days of their SLA deadline, so teams can act before they breach

## Top remediation queue
Ranked list. Sort: KEV first, then VPR desc, then days-over-SLA desc.
Columns: plugin ID | name | asset count | VPR | KEV? | discovered | days open | SLA status
```

Keep the executive summary free of jargon — it is written for leadership. Put
plugin IDs and filter detail lower down.

## Safety and scope notes

- This skill is **read-only**. It never launches scans, changes policies, or
  writes to Tenable.sc.
- Do not embed credentials in the report or in any file you save.
- If the instance has multiple repositories or organizations, ask which to scope
  to rather than silently querying all of them.
