"""DAST tool adapters (Week 49 task 3, plan §22.4): each runs a real scanner container against a
live, ownership-verified URL and parses its report into the same canonical `Finding` shape every
SAST/SCA adapter already produces, so the rest of the pipeline (correlation, scoring, the Issues
table, the Week 49 task 4 SAST/DAST correlator) needs no DAST-specific special case to consume them.

Deliberately NOT `core.adapters.ToolAdapter`: that interface's `applies_to(RepoContext)` and
`parse(raw_bytes)` shape assumes a checked-out source tree to scan, which a web target has none of.
`core.dast.campaign` orchestrates these directly instead of going through `core.scan.ADAPTERS`.
"""
