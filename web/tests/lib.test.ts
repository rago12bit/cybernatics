import { describe, expect, it } from "vitest";
import { agreementLabel, dedupSummary, defaultQuery, findingsQueryString, formatDuration, locationLabel, pageCount } from "../lib/format";
import { cveUrl, cweUrl, owaspUrl, safeHttpsUrl } from "../lib/safe";
import type { Finding, ScanView } from "../lib/types";

const scan = (over: Partial<ScanView> = {}): ScanView => ({
  id: "1", status: "completed", source_type: "git", source_label: "x", tools: [],
  created_at: "", started_at: null, finished_at: null, error: null,
  tool_status: {
    bandit: { status: "ok", findings: 1, exit_code: 1, duration_seconds: 1, error: null, raw_artifact: null },
    semgrep: { status: "ok", findings: 1, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
    trivy: { status: "skipped", findings: 0, exit_code: null, duration_seconds: null, error: null, raw_artifact: null },
  },
  severity_counts: {}, raw_findings: 10, unique_findings: 6, dedup_rate: 0.4, ...over,
});

const finding = (agreement: number): Finding => ({
  id: "f", fingerprint: "fp", title: "t", description: "d",
  location: { path: "a.py", start_line: 3, end_line: 5, snippet: "" },
  taxonomy: { category: "sast", cwe: [], owasp_top_10_2021: [], cve: [], aliases: [] },
  scoring: { native_severity: { bandit: "MEDIUM", semgrep: "ERROR" }, normalized_severity: "HIGH", cvss_v3_1: null, risk_score: null, confidence: 0.5 },
  evidence: { reported_by: [], agreement_count: agreement, rule_ids: {} },
  remediation: { summary: "", references: [], generated_by: "static" }, package: null,
});

describe("safe links (untrusted scanner data must never become a dangerous href)", () => {
  it("only allows plain https URLs", () => {
    expect(safeHttpsUrl("https://example.com/a")).toBe("https://example.com/a");
    for (const bad of ["javascript:alert(1)", "http://example.com", "data:text/html,<script>", "//evil.com", "https://user:pw@evil.com", "ftp://x", "", "not a url"]) {
      expect(safeHttpsUrl(bad)).toBeNull();
    }
  });
  it("builds CWE/CVE/OWASP links only from well-formed ids", () => {
    expect(cweUrl("CWE-89")).toBe("https://cwe.mitre.org/data/definitions/89.html");
    expect(cveUrl("cve-2021-23337")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-23337");
    expect(owaspUrl("A03:2021")).toBe("https://owasp.org/Top10/A03_2021/");
    for (const bad of ["CWE-89/../x", "CWE-", "javascript:CWE-1", "CWE-999999"]) expect(cweUrl(bad)).toBeNull();
    for (const bad of ["CVE-2021-1", "GHSA-xxxx", 'CVE-2021-23337"><script>']) expect(cveUrl(bad)).toBeNull();
    for (const bad of ["A11:2021", "A03:2017", "A03"]) expect(owaspUrl(bad)).toBeNull();
  });
});

describe("findings query", () => {
  it("omits empty filters and encodes values", () => {
    expect(findingsQueryString(defaultQuery())).toBe("sort=severity&limit=50&offset=0");
    const q = { ...defaultQuery(), severity: ["HIGH", "CRITICAL"] as Finding["scoring"]["normalized_severity"][], category: "sca", path: " src/a b&c ", page: 2, sort: "path" as const };
    const s = new URLSearchParams(findingsQueryString(q));
    expect(s.getAll("severity")).toEqual(["HIGH", "CRITICAL"]);
    expect(s.get("path")).toBe("src/a b&c");
    expect(s.get("offset")).toBe("100");
    expect(s.get("sort")).toBe("path");
  });
  it("pageCount never drops below 1", () => {
    expect([0, 1, 50, 51, 120].map(pageCount)).toEqual([1, 1, 1, 2, 3]);
  });
});

describe("labels", () => {
  it("agreement denominator counts only scanners that ran AND cover the finding's category", () => {
    const sc = scan({
      tool_status: {
        bandit: { status: "ok", findings: 1, exit_code: 1, duration_seconds: 1, error: null, raw_artifact: null },
        semgrep: { status: "ok", findings: 1, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
        trivy: { status: "ok", findings: 0, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
        gitleaks: { status: "ok", findings: 0, exit_code: 0, duration_seconds: 1, error: null, raw_artifact: null },
      },
    });
    // Trivy and Gitleaks ran but cannot find a SQL injection, so they are not counted against it.
    expect(agreementLabel(finding(2), sc)).toBe("Flagged by 2 of 2 code scanners");
    expect(agreementLabel(finding(1), sc)).toBe("Flagged by 1 of 2 code scanners");
    expect(agreementLabel(finding(1), null)).toBe("Flagged by 1 scanner");
    expect(agreementLabel(finding(3), sc)).toBe("Flagged by 3 scanners"); // never "3 of 2"
    const semgrepDown = scan({ tool_status: { ...sc.tool_status, semgrep: { ...sc.tool_status.semgrep!, status: "timeout" } } });
    expect(agreementLabel(finding(1), semgrepDown)).toBe("Flagged by 1 of 1 code scanners"); // a dead scanner is not a miss
  });
  it("dedup summary", () => {
    expect(dedupSummary(scan())).toContain("10 raw findings became 6");
    expect(dedupSummary(scan({ raw_findings: 0, unique_findings: 0, dedup_rate: 0 }))).toContain("No findings");
    expect(dedupSummary(scan({ raw_findings: 4, unique_findings: 4, dedup_rate: 0 }))).toContain("no duplicates");
  });
  it("durations and locations", () => {
    expect([0.2, 5.4, 75, null].map(formatDuration)).toEqual(["<1s", "5s", "1m 15s", ""]);
    expect(locationLabel(finding(1))).toBe("a.py:3-5");
  });
});
