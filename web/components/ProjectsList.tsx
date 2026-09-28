"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, listAssets } from "@/lib/api";
import type { AssetSummary } from "@/lib/types";
import "./project-overview.css";

/** Plan §27's "Projects" screen: one row per distinct repository (ADR-0012), most recently
 * scanned first. The entry point into the new §29 design system's Project overview (Week 33). */
export function ProjectsList() {
  const [assets, setAssets] = useState<AssetSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listAssets().then(setAssets, (e) => setError(e instanceof ApiError ? e.message : "Failed to load projects"));
  }, []);

  if (error) return <div className="ds-ov-empty" role="alert">{error}</div>;
  if (!assets) return <div className="ds-ov-empty" role="status" aria-live="polite">Loading…</div>;
  if (assets.length === 0) {
    return (
      <div className="ds-ov-empty">
        <p>No projects scanned yet. Run a scan from the <Link href="/app">Scans</Link> page to see it here.</p>
      </div>
    );
  }

  return (
    <ol className="ds-ov-list" aria-label="Projects">
      {assets.map((a) => (
        <li key={a.id} className="ds-ov-item">
          <span className="ds-ov-rank" aria-hidden="true">•</span>
          <div className="ds-ov-item-main">
            <Link href={`/app/projects/${a.id}`} className="ds-ov-item-title">{a.label}</Link>
            <div className="ds-ov-item-meta">
              <span>{a.open_issue_count} open issue{a.open_issue_count === 1 ? "" : "s"}</span>
              <span>·</span>
              <span>{a.latest_scan_status ?? "no completed scan"}</span>
            </div>
          </div>
          <Link href={`/app/projects/${a.id}`} className="ds-ov-item-action">Open →</Link>
        </li>
      ))}
    </ol>
  );
}
