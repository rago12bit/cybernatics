"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, listDastCampaigns, startDastCampaign } from "@/lib/api";
import type { ScanSummary } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./campaigns-view.css";
import { formatDateTime } from "@/lib/format";

/** DAST campaign view (plan §22.4, Week 49 task 3): start a passive or active scan and see past
 * campaigns -- each one is a Scan under the hood, so "View results" goes straight to the existing
 * /scans/[id] report screen, with no DAST-specific rendering needed there. */
export function CampaignsView({ assetId }: { assetId: string }) {
  const [campaigns, setCampaigns] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState<"passive" | "active" | null>(null);

  function refresh() {
    listDastCampaigns(assetId).then(setCampaigns, (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to load campaigns"),
    );
  }

  useEffect(refresh, [assetId]);

  async function start(mode: "passive" | "active") {
    setStarting(mode);
    setError(null);
    try {
      await startDastCampaign(assetId, mode);
      refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the campaign");
    } finally {
      setStarting(null);
    }
  }

  return (
    <div>
      <p className="small muted ds-campaigns-intro">
        Passive scans (ZAP baseline) spider and observe only -- never an attack payload. Active
        scans add curated Nuclei templates and are limited to one per day per target.
      </p>
      {error && <p className="ds-campaigns-error" role="alert">{error}</p>}
      <div className="ds-campaigns-actions">
        <Button variant="primary" onClick={() => start("passive")} disabled={starting !== null}>
          {starting === "passive" ? "Starting…" : "Start passive scan"}
        </Button>
        <Button onClick={() => start("active")} disabled={starting !== null}>
          {starting === "active" ? "Starting…" : "Start active scan"}
        </Button>
      </div>

      {campaigns === null ? (
        <p className="small muted">Loading…</p>
      ) : campaigns.length === 0 ? (
        <p className="small muted">No campaigns yet.</p>
      ) : (
        <table className="ds-campaigns-table">
          <thead>
            <tr>
              <th>Started</th>
              <th>Status</th>
              <th>Findings</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {campaigns.map((c) => (
              <tr key={c.id}>
                <td>{formatDateTime(c.created_at)}</td>
                <td>{c.status}</td>
                <td>{c.unique_findings}</td>
                <td>
                  <Link href={`/scans/${c.id}`}>View results →</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
