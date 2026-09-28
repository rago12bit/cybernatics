/* The taint-path stepper (plan §28.3, §20.3): "static until Phase 9 supplies real paths" (Week
 * 34's own line item) — Phase 9 (Weeks 36-40) is where a real taint engine tracing source→sink
 * through the call graph gets built. Until then, this component is real and reusable, but the data
 * it's fed is honest about what exists today: a finding's own location is the one real step (the
 * sink), never invented intermediate hops. Steps are clickable and move the code view to that
 * line, exactly as the plan asks, for whenever Phase 9 supplies more than one. */
import type { ReactElement } from "react";

export type TaintStep = { path: string; line: number; label: string };

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
            {i === activeIndex && steps.length > 1 && (
              <span aria-hidden="true" style={{ marginLeft: "auto" }}>
                ◄
              </span>
            )}
          </button>
        </li>
      ))}
    </ol>
  );
}
