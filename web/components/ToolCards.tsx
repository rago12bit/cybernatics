import { formatDuration } from "@/lib/format";
import type { ScanView } from "@/lib/types";
import { StatusBadge } from "./Badges";

/** One outlined bar per scanner, like the reference's stat rows. State is text + bar, never colour alone. */
export function ToolCards({ scan }: { scan: ScanView }) {
  const running = scan.status === "queued" || scan.status === "running";
  return (
    <div className="toolrows" role="list" aria-label="Scanner progress">
      {scan.tools.map((name) => {
        const t = scan.tool_status[name];
        const status = t ? t.status : running ? (scan.status === "running" ? "running" : "pending") : "skipped";
        const badge = status;
        const width = status === "pending" ? "w-4" : status === "skipped" ? "w-4" : "w-100";
        return (
          <div key={name} className="trow" role="listitem">
            <div className="trow-head">
              <span className="trow-name">
                <span className="pip" aria-hidden="true"><i /><i /><i /></span>
                {name}
              </span>
              <StatusBadge status={badge as "running" | "pending" | "ok" | "skipped" | "timeout" | "error"} />
            </div>
            <div className={`tbar ${status}`} aria-hidden="true"><b className={width} /></div>
            <div className="tmeta">
              <span>
                {t && t.status !== "skipped" && `${t.findings} finding${t.findings === 1 ? "" : "s"}`}
                {t?.status === "skipped" && (t.error ?? "no relevant files")}
                {!t && running && (status === "running" ? "scanning…" : "waiting…")}
              </span>
              <span>{t && t.status !== "skipped" ? formatDuration(t.duration_seconds) : ""}</span>
            </div>
            {t && (t.status === "error" || t.status === "timeout") && t.error && <div className="tmeta error-text">{t.error}</div>}
          </div>
        );
      })}
    </div>
  );
}
