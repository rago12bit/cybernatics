import type { ScanStatus, Severity, ToolState } from "@/lib/types";

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
