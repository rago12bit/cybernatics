"use client";

import { liveGuidance } from "@/lib/api";
import { useScan } from "@/lib/useScan";
import { ScanReport } from "./ScanReport";

export function ScanPage({ id }: { id: string }) {
  const { scan, error, connection, version } = useScan(id);
  if (error && !scan) return <p className="cell error" role="alert">{error}</p>;
  if (!scan) return <p className="cell muted" role="status">Loading scan…</p>;
  return <ScanReport scan={scan} connection={connection} version={version} downloads guidance={liveGuidance} />;
}
