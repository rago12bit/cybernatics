import type { ReactElement } from "react";
import "../primitives.css";

/**
 * While a screen or a panel waits for the API: placeholder lines in the shape of text, and the word
 * for screen readers. Replaces a bare "Loading…" line, which looked the same as a screen that had
 * nothing to show.
 */
export function Loading({ label = "Loading…", lines = 3 }: { label?: string; lines?: number }): ReactElement {
  return (
    <div className="ds-loading" role="status" aria-busy="true">
      <span className="sr-only">{label}</span>
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className="sk ds-loading-line" aria-hidden="true" />
      ))}
    </div>
  );
}
