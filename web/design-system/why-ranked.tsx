/* "Explain every rank" (plan C8): "the UI shows why an issue is ranked where it is: 'reachable from
   POST /login, in CISA KEV, flagged by 3 scanners'. A score without a reason does not get trusted."
   `Finding.scoring.risk_factors` already carries this text (core/risk/score.py) -- this is the one
   place it gets rendered, in two shapes so it can appear "everywhere a rank appears" (§32) without
   every list blowing up its own row height: a compact tooltip-style trigger for list rows (the
   fix-first queue, a future issues table), and a full panel for a single issue's own detail view. */
import type { ReactElement } from "react";
import { Tooltip } from "./primitives/Tooltip";

/** A factor with the weight its project gave it (the priority engine, plan §44.3, Week 63). */
export interface WeightedFactor {
  text: string;
  factor?: string;
  weight?: number;
  effect?: number;
}

/** "weight 1.5 · ×1.15": the multiplier the factor applied after its weight. Known exploitation is a
 * floor, not a multiplier, so only its weight is shown (its text already says "at least 90"). */
function weightNote(f: WeightedFactor): string | null {
  if (f.weight == null) return null;
  return f.factor === "kev" ? `weight ${f.weight}` : `weight ${f.weight} · ×${(f.effect ?? 1).toFixed(2)}`;
}

export function WhyRankedPanel({
  factors,
  riskScore,
  weighted,
  band,
}: {
  factors: string[];
  riskScore?: number | null;
  /** When the project has priority weights: each factor with its weight, shown instead of `factors`. */
  weighted?: WeightedFactor[];
  band?: string | null;
}): ReactElement | null {
  const rows: WeightedFactor[] = weighted && weighted.length > 0 ? weighted : factors.map((text) => ({ text }));
  if (rows.length === 0) return null;
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
            {band ? `${band} · ` : ""}
            {riskScore}
            <span style={{ color: "var(--ds-muted)", fontWeight: 400 }}>/100</span>
          </span>
        )}
      </div>
      <ul style={{ margin: 0, paddingLeft: "1.1rem", color: "var(--ds-ink)", fontSize: "var(--ds-text-2)", display: "grid", gap: "0.25rem" }}>
        {rows.map((f, i) => (
          <li key={`${f.text}-${i}`}>
            {f.text}
            {weightNote(f) && <span style={{ color: "var(--ds-muted)", fontFamily: "var(--ds-font-mono)", fontSize: "var(--ds-text-1)" }}> ({weightNote(f)})</span>}
          </li>
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
