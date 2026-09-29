/** The subset of `bulwark scan --format json` this extension reads. Everything is validated at runtime. */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface BulwarkFinding {
  id: string;
  /** Stable defect identity (core.correlation.fingerprint) -- what "new since the base branch"
   * (plan §36) matches on, since a finding's `id` alone isn't guaranteed stable across scans. */
  fingerprint: string;
  title: string;
  path: string;
  startLine: number;
  endLine: number;
  severity: Severity;
  category: string;
  riskScore: number | null;
  rule: string;
  cwe: string[];
  owasp: string[];
  tools: string[];
  description: string;
  riskFactors: string[];
  references: string[]; // https only
  remediationSummary: string;
  suggestedPatch: string | null;
  patchSource: string; // "static" (a scanner's own fix) or "llm"
  reachable: boolean | null;
}

export interface ScanOutput {
  findings: BulwarkFinding[];
  toolStatus: Record<string, string>;
  skipped: number; // findings in the output that could not be read
}
