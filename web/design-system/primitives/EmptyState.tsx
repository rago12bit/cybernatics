import type { ReactElement, ReactNode } from "react";
import "../primitives.css";

/**
 * What a screen shows when there is nothing on it yet: what would be here, why it is empty, and the
 * one thing to do next. Before this, empty screens were a single grey sentence on a blank page, so
 * "nothing yet" and "still loading" or "broken" looked the same.
 */
export function EmptyState({ title, children, actions, compact = false }: {
  title: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  compact?: boolean;
}): ReactElement {
  return (
    <div className={compact ? "ds-empty compact" : "ds-empty"}>
      <svg className="ds-empty-mark" viewBox="0 0 40 40" aria-hidden="true" focusable="false">
        <rect x="1" y="1" width="38" height="38" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 3" />
        <rect x="14" y="14" width="12" height="12" fill="currentColor" />
      </svg>
      <p className="ds-empty-title">{title}</p>
      {children && <div className="ds-empty-body">{children}</div>}
      {actions && <div className="ds-empty-actions">{actions}</div>}
    </div>
  );
}
