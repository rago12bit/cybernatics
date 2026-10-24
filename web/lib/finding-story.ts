import data from "./demo-data.json";

// "Follow one finding" on /how-it-works: the SQL injection in tests/fixtures/vuln-py/src/users.py, from
// the real scan of that fixture in demo-data.json (the same data the home page's merge diagram shows).
// Every value is read from that scan rather than retyped, so the page cannot drift from it.

// The fields used here; the JSON's inferred type is a union per finding, too narrow to search.
type StoryFinding = {
  title: string;
  location: { path: string; start_line: number };
  taxonomy: { cwe: string[]; owasp_top_10_2021: string[] };
  scoring: { native_severity: Record<string, string>; normalized_severity: string; risk_score: number; risk_factors: string[] };
  evidence: { reported_by: string[]; agreement_count: number; rule_ids: Record<string, string[]> };
  fingerprint: string;
};

const SQLI = (data.findings as unknown as StoryFinding[]).find((f) => f.taxonomy.cwe.includes("CWE-89") && f.evidence.reported_by.length > 1);
if (!SQLI) throw new Error("demo-data.json no longer holds a merged SQL injection finding");

/** The fixture's lines 5-7 (tests/fixtures/vuln-py/src/users.py), as scanned. */
export const SOURCE = [
  [5, "def get_user(conn, user_id):"],
  [6, '    query = "SELECT * FROM users WHERE id=" + user_id'],
  [7, "    return conn.execute(query).fetchall()"],
] as const;

const rules = SQLI.evidence.rule_ids;
const native = SQLI.scoring.native_severity;

export const STORY = {
  path: SQLI.location.path,
  line: SQLI.location.start_line,
  title: SQLI.title,
  reports: [
    // Bandit reports B608 on the line that builds the string (6), Semgrep on the call that runs it (7).
    { tool: "bandit", rule: rules.bandit?.[0] ?? "", line: 6, severity: native.bandit ?? "" },
    { tool: "semgrep", rule: rules.semgrep?.[0] ?? "", line: SQLI.location.start_line, severity: native.semgrep ?? "" },
  ],
  cwe: SQLI.taxonomy.cwe,
  owasp: SQLI.taxonomy.owasp_top_10_2021,
  severity: SQLI.scoring.normalized_severity,
  reportedBy: SQLI.evidence.reported_by,
  agreement: SQLI.evidence.agreement_count,
  fingerprint: SQLI.fingerprint,
  riskScore: SQLI.scoring.risk_score,
  riskFactors: SQLI.scoring.risk_factors,
  scannedOn: data.scan.created_at.slice(0, 10),
};

/** The fingerprint shortened for display: "sha256:f2a299fd6401…". */
export const shortPrint = (fp: string) => `${fp.slice(0, 19)}…`;
