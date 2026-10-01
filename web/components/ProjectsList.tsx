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
  if (!assets) {
    return (
      <div role="status" aria-busy="true">
        <span className="sr-only">Loading projects…</span>
        <ol className="ds-ov-list" aria-label="Projects">
          {[0, 1, 2].map((i) => (
            <li key={i} className="ds-ov-item">
              <span className="ds-ov-rank" aria-hidden="true">•</span>
              <div className="ds-ov-item-main">
                <span className="sk sk-m" />
                <span className="sk sk-s" style={{ marginTop: "0.4rem" }} />
              </div>
            </li>
          ))}
        </ol>
      </div>
    );
  }
  if (assets.length === 0) {
    return (
      <div className="ds-ov-empty">
        {/* §30.3's own wording ("Connect a repository...") describes a GitHub-App connect flow this
            build doesn't have yet (no per-user GitHub sign-in exists -- see docs/v2-week33/34
            verification). The real first action today is the scan submission form. */}
        <p>Run your first scan to see it here. It takes about two minutes. <Link href="/app">Start a scan →</Link></p>
        <p><Link href="/app/projects/new-web">Add a web target for DAST scanning →</Link></p>
      </div>
    );
  }

  return (
    <>
      <p style={{ marginBottom: "1rem" }}>
        <Link href="/app/projects/new-web">+ Add a web target</Link>
      </p>
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
    </>
  );
}
