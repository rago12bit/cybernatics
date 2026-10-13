import { formatDuration } from "@/lib/format";
import type { ScanView, ToolState } from "@/lib/types";
import { StatusBadge } from "./Badges";

type RowState = ToolState | "running" | "pending";

/** One outlined bar per scanner while a scan runs, like the reference's stat rows; once it has
 * finished, one line each, so the results are not pushed below the fold by five full bars.
 * State is text + bar (or badge), never colour alone. */
export function ToolCards({ scan }: { scan: ScanView }) {
  const running = scan.status === "queued" || scan.status === "running";
  return (
    <div className={running ? "toolrows" : "toolrows done"} role="list" aria-label={running ? "Scanner progress" : "Scanners"}>
      {scan.tools.map((name) => {
        const t = scan.tool_status[name];
        const status: RowState = t ? t.status : running ? (scan.status === "running" ? "running" : "pending") : "skipped";
        const width = status === "pending" ? "w-4" : status === "skipped" ? "w-4" : "w-100";
        const detail = t
          ? t.status === "skipped" ? (t.error ?? "no relevant files") : `${t.findings} finding${t.findings === 1 ? "" : "s"}`
          : running ? (status === "running" ? "scanning…" : "waiting…") : "";
        const duration = t && t.status !== "skipped" ? formatDuration(t.duration_seconds) : "";
        const label = (
          <span className="trow-name">
            <span className="pip" aria-hidden="true"><i /><i /><i /></span>
            {name}
          </span>
        );
        const error = t && (t.status === "error" || t.status === "timeout") && t.error && <div className="tmeta error-text">{t.error}</div>;
        if (!running) {
          return (
            <div key={name} className="trow" role="listitem">
              {label}
              <span className="tmeta">{detail}</span>
              <span className="tmeta">{duration}</span>
              <StatusBadge status={status} />
              {error}
            </div>
          );
        }
        return (
          <div key={name} className="trow" role="listitem">
            <div className="trow-head">
              {label}
              <StatusBadge status={status} />
            </div>
            <div className={`tbar ${status}`} aria-hidden="true"><b className={width} /></div>
            <div className="tmeta">
              <span>{detail}</span>
              <span>{duration}</span>
            </div>
            {error}
          </div>
        );
      })}
    </div>
  );
}
