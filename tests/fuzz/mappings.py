"""Fixed mappings the universal mapper is fuzzed through (Week 59, plan §42.4/§22.3). A saved
mapping is a parser like any other, so it is fuzzed like one: `ingest-universal-json` and friends
are fuzz targets next to the built-in parsers, and their crashes replay in
tests/unit/test_fuzz_regressions.py. Kept free of `atheris` so that replay test can import it."""

from __future__ import annotations

from typing import Any

FUZZ_MAPPINGS: dict[str, dict[str, Any]] = {
    "universal-json": {
        "format": "json", "source": "fuzz", "records": "$.issues[*]",
        "fields": {"title": "$.name", "severity": "$.risk", "path": "$.at.file",
                   "line": "$.at.line", "rule": "$.id", "cwe": "$.cwe[*]", "cve": "$.cve",
                   "references": "$.refs[*]", "description": '$["long text"]'},
        "severity_map": {"p1": "CRITICAL"},
    },
    "universal-csv": {
        "format": "csv", "source": "fuzz", "category": "sca",
        "fields": {"title": "title", "severity": "severity", "package": "package",
                   "version": "version", "cve": "cve"},
    },
    "universal-xml": {
        "format": "xml", "source": "fuzz", "category": "dast", "records": "issues/issue",
        "fields": {"title": "name", "severity": "@sev", "url": "where/@url", "cwe": "cwe",
                   "references": "refs/ref"},
    },
}  # fmt: skip

SEEDS = {
    "universal-json": "tests/fuzz/seeds/universal.json",
    "universal-csv": "tests/fuzz/seeds/universal.csv",
    "universal-xml": "tests/fuzz/seeds/universal.xml",
    "analyze": "tests/fuzz/seeds/universal.json",
}
