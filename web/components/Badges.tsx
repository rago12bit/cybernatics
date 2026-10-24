import type { IssueRef, ScanStatus, Severity, ToolState } from "@/lib/types";
import { formatDateTime } from "@/lib/format";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`tag sev-${severity.toLowerCase()}`}>{severity}</span>;
}

export function StatusBadge({ status }: { status: ScanStatus | ToolState | "pending" }) {
  return <span className={`tag st-${status}`}>{status}</span>;
}

export function SeverityCounts({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const shown = order.filter((s) => (counts[s] ?? 0) > 0);
  if (shown.length === 0) return <span className="muted">none</span>;
  return (
    <span className="counts">
      {shown.map((s) => (
        <span key={s} className={`tag sev-${s.toLowerCase()}`}>{counts[s]} {s}</span>
      ))}
    </span>
  );
}

/** Whether this finding is new, or came back after being fixed (ADR-0012). Silent for "open" —
 * the steady state of most findings shouldn't compete for attention with what actually changed. */
export function IssueBadge({ issue }: { issue?: IssueRef | null }) {
  if (!issue || issue.state === "open") return null;
  const label = issue.state === "new" ? "New" : "Reintroduced";
  return (
    <span
      className={`tag issue-${issue.state}`}
      title={
        issue.state === "new"
          ? "First time this issue has been seen on this project"
          : "This issue was fixed in an earlier scan and has come back"
      }
    >
      {label}
    </span>
  );
}

/** Set once a DAST campaign's own finding matched this Issue on the same route+CWE (plan §22.4,
 * Week 49 task 4) -- a static finding a real HTTP request actually reached, not just a tool's
 * guess. Silent when absent: most Issues have no DAST campaign to confirm them against at all. */
export function ConfirmedAtRuntimeBadge({ issue }: { issue?: IssueRef | null }) {
  if (!issue?.confirmed_at_runtime_at) return null;
  return (
    <span
      className="tag issue-confirmed-runtime"
      title={`A DAST campaign confirmed this at runtime on ${formatDateTime(issue.confirmed_at_runtime_at)}`}
    >
      Confirmed at runtime
    </span>
  );
}

/** Risk 0-100 plus the two exploit signals that matter most. */
export function RiskSignals({ score, kev, epss }: { score: number | null; kev?: boolean; epss?: number | null }) {
  return (
    <span className="signals">
      {score !== null && <span className="risk" title="Risk score, 0 to 100">{score}</span>}
      {kev && <span className="tag kev" title="Listed in CISA's Known Exploited Vulnerabilities catalog">KEV</span>}
      {!kev && typeof epss === "number" && epss >= 0.1 && <span className="tag epss" title="EPSS: chance of exploitation in the next 30 days">EPSS {Math.round(epss * 100)}%</span>}
    </span>
  );
}
