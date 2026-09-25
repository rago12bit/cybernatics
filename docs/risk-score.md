# Risk score and "Fix these first"

Every finding gets `scoring.risk_score` (0-100) and `scoring.risk_factors`, a list of the reasons in
plain words. The UI's **Fix these first** panel is the ten highest scores; the API equivalent is
`GET /scans/{id}/findings?sort=risk&limit=10`.

## Inputs

| Signal | Source | Used for |
|---|---|---|
| CVSS v3.1 base score, else normalized severity | Trivy, OSV-Scanner / severity matrix | impact |
| **EPSS**: probability a CVE is exploited in the next 30 days | FIRST.org, daily file | likelihood |
| **KEV**: CVE is known to be exploited in the wild | CISA Known Exploited Vulnerabilities catalog | likelihood, and a floor |
| Scanner agreement (merged confidence) | correlation | likelihood, for findings with no CVE |

## Formula

```
impact     = CVSS / 10                       if known
           = {CRITICAL .95, HIGH .75, MEDIUM .5, LOW .25, INFO .05}   otherwise
likelihood = 1.0                             CVE is in KEV
           = min(1, sqrt(EPSS / 0.5))        EPSS known (full weight at 50%)
           = 0.3                             dependency finding, exploit data unknown
           = merged confidence               code, secrets and IaC findings (no CVE exists)
risk       = round(100 * impact * (0.5 + 0.5 * likelihood))
risk       = max(risk, 90)                   if in KEV
```

Impact sets the ceiling; exploit evidence decides where between 50% and 100% of it a score lands. EPSS values are heavily skewed (most CVEs sit below 1%), which is why the square-root
curve is used instead of a linear one. A finding can list several CVE ids; the highest EPSS and any KEV
hit count.

## Behaviour you can rely on

- **Feeds missing or stale never fail a scan.** Scores fall back to "unknown exploit data" and the factor
  list says so (`Exploit feeds not loaded`).
- **Scoring is a pure function** of the finding and the two files; no network at scoring time.
- **Downloads are validated** before they replace the cache: https only, size-capped, header and
  minimum-row checks; a bad file leaves the previous good copy in place.
- **Secrets and code findings** are scored from severity and confidence only; nothing in EPSS or KEV
  applies to them.

## Feeds

`bulwark update-feeds` downloads both files into `<workdir>/feeds` (about 4 MB). The worker also refreshes
them daily (Celery beat) and before a scan when the cache is missing or over 48 hours old.
`GET /risk/feeds` (authenticated) reports the dates, sizes and last errors. Only the API/worker side needs
the network; scanner containers still have none.

Sources: <https://www.first.org/epss/> (score files) and
<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>.

## Limits

- **A heuristic for ordering work, not a probability and not validated against real outcomes.** The
  weights and the KEV floor are judgment calls, kept in one place (`core/risk/score.py`) for review.
- **No reachability yet.** A vulnerable library the code never calls scores the same as one it does.
- A dependency advisory without a CVE id (GitHub-only advisories) cannot be looked up, so it scores as
  "unknown".
- EPSS and KEV describe the whole internet, not your environment.
