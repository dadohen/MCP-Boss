# MCP Boss Benchmark Scorecard

- last_run: 2026-04-22T22:43:27.843684+00:00
- model: gemini-2.5-flash
- scenarios_run: 6

## Headline numbers

- correct_verdict_pct: 83.3
- correct_containment_pct: 13.9
- destructive_fp_rate_pct: 0.0
- median_alert_to_containment_s: 60.87

## Per-scenario detail

| scenario | verdict | containment | destructive FP | a2c (s) |
|----------|---------|-------------|----------------|---------|
| s001-aws-key-exposure | OK | 0.00 | no | 102.89642715454102 |
| s002-phish-okta-compromise | OK | 0.00 | no | 58.15893363952637 |
| s003-bigquery-exfil | OK | 0.50 | no | 41.69841551780701 |
| s004-ransomware-mass-encrypt | OK | 0.33 | no | 60.87396550178528 |
| s005-apt-lateral-sa-impersonation | MISS | 0.00 | no | - |
| s006-bec-inbox-rule | OK | 0.00 | no | 77.6879551410675 |
