/* "Explain every rank" (plan C8): "the UI shows why an issue is ranked where it is: 'reachable from
   POST /login, in CISA KEV, flagged by 3 scanners'. A score without a reason does not get trusted."
   `Finding.scoring.risk_factors` already carries this text (core/risk/score.py) -- this is the one
   place it gets rendered, in two shapes so it can appear "everywhere a rank appears" (§32) without
   every list blowing up its own row height: a compact tooltip-style trigger for list rows (the
   fix-first queue, a future issues table), and a full panel for a single issue's own detail view. */
import type { ReactElement } from "react";
import { Tooltip } from "./primitives/Tooltip";

export function WhyRankedPanel({ factors, riskScore }: { factors: string[]; riskScore?: number | null }): ReactElement | null {
  if (factors.length === 0) return null;
  return (
    <div
      role="group"
      aria-label="Why this is ranked here"
      style={{
        border: "1px solid var(--ds-rule)",
        borderRadius: "var(--ds-radius-panel)",
        background: "color-mix(in srgb, var(--ds-brand) 6%, var(--ds-raised))",
        padding: "0.9rem 1rem",
        display: "grid",
        gap: "0.5rem",
        fontFamily: "var(--ds-font-sans)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.75rem" }}>
        <span style={{ fontSize: "var(--ds-text-1)", color: "var(--ds-muted)", textTransform: "none" }}>Why it&apos;s ranked here</span>
        {riskScore != null && (
          <span style={{ fontFamily: "var(--ds-font-mono)", fontSize: "var(--ds-text-2)", fontWeight: 600, color: "var(--ds-brand)" }}>
            {riskScore}
            <span style={{ color: "var(--ds-muted)", fontWeight: 400 }}>/100</span>
          </span>
        )}
      </div>
      <ul style={{ margin: 0, paddingLeft: "1.1rem", color: "var(--ds-ink)", fontSize: "var(--ds-text-2)", display: "grid", gap: "0.25rem" }}>
        {factors.map((f) => (
          <li key={f}>{f}</li>
        ))}
      </ul>
    </div>
  );
}

/** A compact version for a list row: the reasons live behind a tooltip rather than expanding every
 * row's height, but the same real `risk_factors` text — never a different, shortened explanation. */
export function WhyRankedTrigger({ factors, children }: { factors: string[]; children: ReactElement }): ReactElement {
  if (factors.length === 0) return children;
  return <Tooltip label={factors.join(" · ")}>{children}</Tooltip>;
}
