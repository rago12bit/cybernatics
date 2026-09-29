/* The taint-path stepper (plan §28.3, §20.3). Week 37/38 built the real taint engine
 * (core/taint/) that traces source→sink through the call graph; `IssueDetail.tsx` now feeds this
 * component the real, multi-hop path when one was found, falling back to the finding's own
 * location as the one real step when it wasn't (never invented intermediate hops either way).
 * Steps are clickable and move the code view to that line, per the plan's own wording. */
import type { ReactElement } from "react";

export type TaintStep = { path: string; line: number; label: string; isSink?: boolean };

export function TaintStepper({
  steps,
  activeIndex,
  onStepClick,
}: {
  steps: TaintStep[];
  activeIndex: number;
  onStepClick: (index: number) => void;
}): ReactElement | null {
  if (steps.length === 0) return null;
  return (
    <ol
      aria-label={steps.length > 1 ? "How the input gets there" : "Where this happens"}
      style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: "0.3rem", fontFamily: "var(--ds-font-sans)" }}
    >
      {steps.map((s, i) => (
        <li key={`${s.path}:${s.line}:${i}`}>
          <button
            type="button"
            onClick={() => onStepClick(i)}
            aria-current={i === activeIndex ? "step" : undefined}
            style={{
              display: "flex",
              width: "100%",
              alignItems: "baseline",
              gap: "0.6rem",
              padding: "0.4rem 0.5rem",
              borderRadius: "var(--ds-radius-input)",
              border: "none",
              background: i === activeIndex ? "color-mix(in srgb, var(--ds-brand) 10%, var(--ds-raised))" : "transparent",
              color: i === activeIndex ? "var(--ds-brand)" : "var(--ds-ink)",
              cursor: "pointer",
              textAlign: "left",
              fontSize: "var(--ds-text-2)",
            }}
          >
            <span aria-hidden="true" style={{ fontFamily: "var(--ds-font-mono)", color: "var(--ds-muted)" }}>
              {i + 1}
            </span>
            <code style={{ fontFamily: "var(--ds-font-mono)", fontSize: "var(--ds-text-1)" }}>
              {s.path}:{s.line}
            </code>
            <span>{s.label}</span>
            {s.isSink && steps.length > 1 && (
              <span aria-hidden="true" title="Sink" style={{ marginLeft: "auto" }}>
                ◄
              </span>
            )}
          </button>
        </li>
      ))}
    </ol>
  );
}
