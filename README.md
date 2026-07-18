# tenable-sc-sla-triage

An Agent Skill for analyzing a **Tenable Security Center (Tenable.sc)** instance
for remediation **SLA compliance** and producing a **VPR-prioritized remediation
queue**, with **CISA KEV** cross-referencing.

Compatible with any SKILL.md-based agent (Claude Code, Cowork, and others).

## What it does

- Pulls **cumulative** (open) findings from Tenable.sc via the API.
- Ages each finding from its **Vulnerability Discovered** date (the correct SLA
  clock — not "last seen").
- Tiers and ranks by **VPR** rather than static CVSS.
- Flags findings on the **CISA Known Exploited Vulnerabilities** catalog.
- Outputs an executive summary, an approaching-breach watchlist, and a ranked
  remediation queue (CSV).

Read-only — it never launches scans or modifies the instance.

## Layout

```
tenable-sc-sla-triage/
├── SKILL.md                        # skill instructions + report format
├── references/
│   └── sc-query-cookbook.md        # Tenable.sc query syntax reference
└── scripts/
    └── sla_aging.py                # pyTenable script (the engine)
```

## Standalone use (without an agent)

```bash
pip install pytenable
export TSC_URL="https://your-sc-host"
export TSC_ACCESS_KEY="..."
export TSC_SECRET_KEY="..."
python scripts/sla_aging.py --out report.csv
```

Edit the `SLA_DAYS` targets at the top of `scripts/sla_aging.py` to match your
program's policy.

## License

MIT — see [LICENSE](LICENSE).
