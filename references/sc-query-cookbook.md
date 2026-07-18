
Tenable.sc Analysis Query Cookbook
Reference for the filter names, tool types, and field syntax used when querying
the Tenable.sc `analysis` endpoint (via pyTenable's `sc.analysis`). Read this when
you need to adjust the queries in `scripts/sla_aging.py` or build new ones.
Table of contents
Choosing the source database
Useful tool types
Common filters
Severity vs. VPR
The SLA clock field
CISA KEV cross-reference
Authentication / scan-health plugins
Choosing the source database
`sc.analysis` accepts a `source` argument:
`source='cumulative'` — current open findings. Use this for SLA aging.
`source='patched'` (mitigated) — findings confirmed remediated. Use only for
remediation-velocity / trend reporting, never for open-state aging.
Useful tool types
Passed as the `tool` argument to `sc.analysis.vulns(...)`:
`vulndetails` — one row per finding with full detail (VPR, discovered date,
plugin text). Used by the aging script.
`sumip` — summary counts grouped by asset/IP.
`sumid` — summary grouped by plugin ID (good for "top plugins" rollups).
`listvuln` — flat list, lighter weight than vulndetails.
Common filters
Filters are `(name, operator, value)` tuples. Frequently used:
`('severity', '=', '4,3')` — restrict to Critical(4)/High(3). Severity IDs:
0=Info, 1=Low, 2=Medium, 3=High, 4=Critical.
`('repository', '=', '<id>')` — scope to a repository.
`('pluginID', '=', '19506')` — a specific plugin.
`('exploitAvailable', '=', 'true')` — findings with a known public exploit.
`('lastSeen', '=', '0:30')` — observed in the last 30 days (day range syntax).
Severity vs. VPR
`severity` is the static, CVSS-derived tier (the IDs above).
VPR is the dynamic priority score. In `vulndetails` output it comes back on
the `vprScore` field. Prioritize remediation by `vprScore`, not `severity`.
VPR-to-tier mapping used by this skill: Critical 9.0–10, High 7.0–8.9,
Medium 4.0–6.9, Low 0.1–3.9.
The SLA clock field
In `vulndetails` output, the discovery date is `firstSeen` at the finding level.
This is the Vulnerability Discovered value — the correct SLA start. Do not
age from `lastSeen` (that resets every scan). Both come back as Unix epoch
seconds; convert before computing age in days.
CISA KEV cross-reference
Tenable.sc exposes KEV membership through the cross-reference field. Filter syntax:
```
('crossRef', '=', 'CISA-KNOWN-EXPLOITED|*')
```
The `|*` wildcard matches any KEV identifier. Findings returned by this filter are
on the CISA Known Exploited Vulnerabilities catalog and should be treated as top
priority regardless of VPR or age.
Authentication / scan-health plugins
SLA numbers are only trustworthy if scans are actually authenticating. Before
trusting an aging report, sanity-check credentialed-scan health with these
plugins (query by `pluginID`):
`19506` — Nessus Scan Information (shows whether credentialed checks ran)
`10180` — Ping the remote host (basic reachability)
`104410`, `110385`, `110095`, `110723`, `141118` — authentication status /
failure plugins across platforms. A spike here means findings may be
under-reported and SLA compliance is overstated.
If a meaningful share of in-scope assets show failed authentication, note this as
a caveat in the report — the SLA picture is only as good as the scan coverage
underneath it.
