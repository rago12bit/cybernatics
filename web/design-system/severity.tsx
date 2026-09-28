/* Severity scale (plan §29.2): shape + label + color, never color alone — about one in twelve men
   has some red-green color vision deficiency. Calm by default: only a critical finding that is also
   reachable gets the filled treatment; an unreachable critical keeps its "Critical" label but draws
   outline, with a "Not reachable" tag next to it. */
import type { CSSProperties, ReactElement } from "react";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

// CSS custom property per severity, defined in tokens.css.
const SEVERITY_VAR: Record<Severity, string> = {
  critical: "var(--ds-sev-critical)",
  high: "var(--ds-sev-high)",
  medium: "var(--ds-sev-medium)",
  low: "var(--ds-sev-low)",
  info: "var(--ds-sev-info)",
};

type ShapeProps = { size: number; filled: boolean };

function Octagon({ size, filled }: ShapeProps): ReactElement {
  // Regular octagon inscribed in a 24x24 box.
  const points = "8,2 16,2 22,8 22,16 16,22 8,22 2,16 2,8";
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <polygon points={points} fill={filled ? "currentColor" : "none"} stroke="currentColor" strokeWidth={filled ? 0 : 2} />
    </svg>
  );
}

function Triangle({ size, filled }: ShapeProps): ReactElement {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <polygon points="12,2 22,21 2,21" fill={filled ? "currentColor" : "none"} stroke="currentColor" strokeWidth={filled ? 0 : 2} strokeLinejoin="round" />
    </svg>
  );
}

function Diamond({ size, filled }: ShapeProps): ReactElement {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <polygon points="12,2 22,12 12,22 2,12" fill={filled ? "currentColor" : "none"} stroke="currentColor" strokeWidth={filled ? 0 : 2} strokeLinejoin="round" />
    </svg>
  );
}

function Circle({ size, filled }: ShapeProps): ReactElement {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="10" fill={filled ? "currentColor" : "none"} stroke="currentColor" strokeWidth={filled ? 0 : 2} />
    </svg>
  );
}

function Ring({ size }: ShapeProps): ReactElement {
  // Info is always a ring, filled or not — it never carries the "filled = urgent" meaning.
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth={3} />
    </svg>
  );
}

const SHAPE: Record<Severity, (p: ShapeProps) => ReactElement> = {
  critical: Octagon,
  high: Triangle,
  medium: Diamond,
  low: Circle,
  info: Ring,
};

export function SeverityIcon({ severity, size = 16, filled = true }: { severity: Severity; size?: number; filled?: boolean }): ReactElement {
  const Shape = SHAPE[severity];
  const style: CSSProperties = { color: SEVERITY_VAR[severity], flex: "none", display: "inline-block" };
  return (
    <span style={style}>
      <Shape size={size} filled={severity === "info" ? true : filled} />
    </span>
  );
}

/**
 * The one severity component product code should render. `reachable` only affects `critical`
 * (29.2's calm-by-default rule); it's ignored for other levels since the plan only carves out this
 * exception for critical findings.
 */
export function SeverityBadge({ severity, reachable = true }: { severity: Severity; reachable?: boolean }): ReactElement {
  const showOutline = severity === "critical" && !reachable;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem", fontFamily: "var(--ds-font-sans)", fontSize: "var(--ds-text-2)", color: "var(--ds-ink)" }}>
      <SeverityIcon severity={severity} filled={!showOutline} />
      <span>{SEVERITY_LABEL[severity]}</span>
      {showOutline && (
        <span style={{ fontSize: "var(--ds-text-1)", color: "var(--ds-muted)", border: "1px solid var(--ds-rule)", borderRadius: "var(--ds-radius-input)", padding: "0.1rem 0.35rem" }}>
          Not reachable
        </span>
      )}
    </span>
  );
}
