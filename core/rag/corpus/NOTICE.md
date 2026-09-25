# Corpus notice

This directory holds reference text used to give remediation prompts factual grounding. It is **not** scanner
output and contains no user data. It is rebuilt by `scripts/build-corpus.py`; exact versions are in
`SOURCES.json`.

- **`cwe.jsonl`**: descriptions, consequences and mitigations from the MITRE **Common Weakness Enumeration**
  (<https://cwe.mitre.org/>). CWE is a trademark of The MITRE Corporation; this text is used under the CWE
  Terms of Use (<https://cwe.mitre.org/about/termsofuse.html>), which allow use with attribution to MITRE.
  Bulwark is not endorsed by or affiliated with MITRE.
- **`cheatsheets.jsonl`**: sections of the **OWASP Cheat Sheet Series**
  (<https://github.com/OWASP/CheatSheetSeries>), split into chunks. Licensed **CC BY-SA 4.0**
  (<https://creativecommons.org/licenses/by-sa/4.0/>). Chunks are adapted (split, links and images removed,
  tagged with CWE/OWASP categories). **Share-alike applies to these files**: redistribute them under CC BY-SA
  4.0 with this attribution. Each chunk records the URL of the sheet it came from. The rest of Bulwark stays
  Apache-2.0.
- The mapping from sheets to OWASP categories and CWE ids is our own curation (`SHEETS` in the build
  script), not something OWASP asserts.
