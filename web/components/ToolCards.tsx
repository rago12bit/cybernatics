import { formatDuration } from "@/lib/format";
import type { ScanView } from "@/lib/types";
import { StatusBadge } from "./Badges";

export function ToolCards({ scan }: { scan: ScanView }) {
  const running = scan.status === "queued" || scan.status === "running";
  return (
    <ul className="tools" aria-label="Scanner progress">
      {scan.tools.map((name) => {
        const t = scan.tool_status[name];
        const status = t ? t.status : running ? "pending" : "skipped";
        return (
          <li key={name} className={`tool tool-${status}`}>
            <div className="tool-head">
              <strong>{name}</strong>
              <StatusBadge status={status} />
            </div>
            <div className="muted small">
              {t && t.status !== "skipped" && <>{t.findings} finding{t.findings === 1 ? "" : "s"} · {formatDuration(t.duration_seconds)}</>}
              {t?.status === "skipped" && (t.error ?? "no relevant files")}
              {!t && running && "waiting…"}
            </div>
            {t && (t.status === "error" || t.status === "timeout") && t.error && <div className="small error-text">{t.error}</div>}
            {t?.raw_artifact === "withheld" && <div className="small muted">Raw output withheld: this scan contains secrets.</div>}
          </li>
        );
      })}
    </ul>
  );
}
