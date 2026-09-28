"use client";

import { liveGuidance } from "@/lib/api";
import { useScan } from "@/lib/useScan";
import { ScanReport } from "./ScanReport";

export function ScanPage({ id }: { id: string }) {
  const { scan, error, connection, version } = useScan(id);
  if (error && !scan) return <p className="cell error" role="alert">{error}</p>;
  if (!scan) {
    return (
      <div className="section skeleton-list" role="status" aria-busy="true">
        <span className="sr-only">Loading scan…</span>
        <span className="sk sk-l" style={{ height: "2rem" }} />
        <span className="sk sk-row" />
        <span className="sk sk-row" />
        <span className="sk sk-row" />
      </div>
    );
  }
  return <ScanReport scan={scan} connection={connection} version={version} downloads guidance={liveGuidance} />;
}
