"""Connectors (plan §42.5, ADR-0045): scheduled, pull-based ingestion from GitHub code scanning and
Dependabot, GitLab vulnerability reports and DefectDojo, plus an export to DefectDojo -- every pull
applied through the same ingest path as an upload (ADR-0040), with a health state that notices the
quiet failure: a connection that authenticates and fetches nothing."""
