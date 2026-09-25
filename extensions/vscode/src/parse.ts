import type { BulwarkFinding, ScanOutput, Severity } from "./types";

const SEVERITIES: readonly string[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function str(v: unknown, max = 500): string {
  return typeof v === "string" ? v.slice(0, max) : "";
}

function int(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : fallback;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, 20) : [];
}

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/** A finding whose shape we do not trust is dropped (and counted), never guessed at. */
export function parseFinding(raw: unknown): BulwarkFinding | null {
  const f = obj(raw);
  const loc = obj(f.location);
  const scoring = obj(f.scoring);
  const rem = obj(f.remediation);
  const path = str(loc.path, 1000);
  const sev = str(scoring.normalized_severity);
  const start = int(loc.start_line, 0);
  if (!path || start < 1 || !SEVERITIES.includes(sev)) return null;
  const rules = Object.values(obj(obj(f.evidence).rule_ids)).flatMap(strings);
  const risk = scoring.risk_score;
  return {
    id: str(f.id, 300),
    title: str(f.title) || "Security finding",
    path,
    startLine: start,
    endLine: Math.max(int(loc.end_line, start), start),
    severity: sev as Severity,
    category: str(obj(f.taxonomy).category),
    riskScore: typeof risk === "number" ? risk : null,
    rule: rules[0] ?? "",
    cwe: strings(obj(f.taxonomy).cwe),
    owasp: strings(obj(f.taxonomy).owasp_top_10_2021),
    tools: strings(obj(f.evidence).reported_by),
    description: str(f.description, 2000),
    riskFactors: strings(scoring.risk_factors),
    references: strings(rem.references).filter((u) => /^https:\/\//.test(u)).slice(0, 5),
    remediationSummary: str(rem.summary, 1000),
    suggestedPatch: typeof rem.suggested_patch === "string" && rem.suggested_patch.length <= 20_000 ? rem.suggested_patch : null,
    patchSource: str(rem.generated_by, 20) || "static",
    reachable: typeof scoring.reachable === "boolean" ? scoring.reachable : null,
  };
}

export function parseScanOutput(text: string): ScanOutput {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Error("The Bulwark CLI did not return valid JSON.");
  }
  const d = obj(doc);
  if (!Array.isArray(d.findings)) throw new Error("The Bulwark CLI output has no findings list.");
  const findings: BulwarkFinding[] = [];
  let skipped = 0;
  for (const raw of d.findings) {
    const f = parseFinding(raw);
    if (f) findings.push(f);
    else skipped++;
  }
  const toolStatus: Record<string, string> = {};
  for (const [tool, v] of Object.entries(obj(d.tool_status))) toolStatus[tool] = str(obj(v).status) || "unknown";
  return { findings, toolStatus, skipped };
}
