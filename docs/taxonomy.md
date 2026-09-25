# CWE and OWASP Top 10 mapping

Every finding carries `taxonomy.cwe` (weakness ids) and `taxonomy.owasp_top_10_2021` (categories such as
`A03:2021`). Scanners fill these unevenly, so Bulwark completes them from one table after correlation
(`core/taxonomy`, applied in `core/scan.py`).

## Source and licence

`core/taxonomy/owasp_top10_2021.json` is transcribed by script from the OWASP Top 10:2021 project
(<https://github.com/OWASP/Top10>, `2021/docs/en`), which is licensed CC BY-SA 4.0. It holds, per
category, the CWE ids OWASP lists for it and their names. Categories with count: A01 34, A02 30, A03 33,
A04 40, A05 20, A06 3, A07 22, A08 10, A09 4, A10 1. A unit test pins these counts so a truncated file
fails CI. Some CWEs belong to two categories (for example CWE-259 is in A02 and A07); both are kept.

## Rules

1. **Normalize.** `79`, `"cwe_79"` and `CWE-79` all become `CWE-79`; unparseable values are dropped
   (scanner output is untrusted).
2. **Map.** Each CWE adds the OWASP categories the table lists for it.
3. **Keep the scanner's own tags.** An OWASP tag a scanner reported (Semgrep does this) is normalized and
   kept, never overwritten.
4. **Defaults for CWE-less findings** (the only inference in the system):
   a vulnerable dependency (`sca`) is **A06** Vulnerable and Outdated Components; an infrastructure
   misconfiguration (`iac`) is **A05** Security Misconfiguration.
   Code (`sast`) and container findings with no CWE stay unmapped rather than guessed.

Secrets map through CWE-798 (hard-coded credentials) to **A07**.

## Measured on the sample scan

Of 38 merged findings, 3 had an OWASP category before; 35 have one now. The 3 still unmapped are container
findings that carry no CWE.

## Limits

- The table covers only CWEs OWASP lists. A CWE outside the Top 10 mapping gets no category and no name.
- OWASP's own mapping is many-to-many and coarse; treat the category as a grouping aid, not a verdict.
- Refreshing for a new Top 10 edition means a new JSON file and a new field; the 2021 field name is
  deliberate.
