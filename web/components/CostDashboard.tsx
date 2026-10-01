"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, getCostSummary } from "@/lib/api";
import type { CostSummary } from "@/lib/types";
import { formatDuration } from "@/lib/format";
import "./cost-dashboard.css";

function formatUsd(n: number): string {
  if (n < 0.01 && n > 0) return `$${n.toFixed(4)}`;
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(n);
}

const WINDOWS = [7, 30, 90];

/** Cost-per-scan dashboard (plan §23, Week 50): compute seconds plus LLM tokens, as an estimate --
 * not a bill. See core/observability/cost.py's own docstring for the pricing assumptions and their
 * disclosed imprecision, surfaced here too so this screen doesn't read as more authoritative than it
 * is. */
export function CostDashboard() {
  const [days, setDays] = useState(30);
  const [summary, setSummary] = useState<CostSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setSummary(null);
    getCostSummary(days).then(setSummary, (e) =>
      setError(e instanceof ApiError ? e.message : "Failed to load cost summary"),
    );
  }, [days]);

  return (
    <div>
      <p className="small muted ds-cost-intro">
        An estimate, not a bill: scanner compute time and LLM token usage, each priced with a
        placeholder/overridable rate. A changed <code>BULWARK_LLM_MODEL</code> reprices every past
        token at today&rsquo;s rate -- this is for relative visibility across scans and projects,
        not for reconciling an invoice.
      </p>

      <div className="ds-cost-window">
        {WINDOWS.map((w) => (
          <button
            key={w}
            className={w === days ? "ds-cost-window-active" : ""}
            onClick={() => setDays(w)}
          >
            Last {w}d
          </button>
        ))}
      </div>

      {error && <p className="ds-cost-error" role="alert">{error}</p>}

      {summary === null ? (
        <p className="small muted">Loading…</p>
      ) : (
        <>
          <div className="ds-cost-totals">
            <div className="ds-cost-tile">
              <div className="ds-cost-tile-label">Total estimated cost</div>
              <div className="ds-cost-tile-value">{formatUsd(summary.total_usd)}</div>
            </div>
            <div className="ds-cost-tile">
              <div className="ds-cost-tile-label">Scanner compute</div>
              <div className="ds-cost-tile-value">{formatUsd(summary.total_compute_usd)}</div>
              <div className="small muted">{formatDuration(summary.total_compute_seconds)}</div>
            </div>
            <div className="ds-cost-tile">
              <div className="ds-cost-tile-label">LLM tokens</div>
              <div className="ds-cost-tile-value">{formatUsd(summary.total_llm_usd)}</div>
              <div className="small muted">{summary.total_llm_tokens.toLocaleString()} tokens</div>
            </div>
            <div className="ds-cost-tile">
              <div className="ds-cost-tile-label">Scans</div>
              <div className="ds-cost-tile-value">{summary.scan_count}</div>
            </div>
          </div>

          {summary.scans.length === 0 ? (
            <p className="small muted">No scans in this window.</p>
          ) : (
            <table className="ds-cost-table">
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>When</th>
                  <th>Compute</th>
                  <th>LLM tokens</th>
                  <th>Estimated cost</th>
                </tr>
              </thead>
              <tbody>
                {summary.scans.map((row) => (
                  <tr key={row.scan_id}>
                    <td>
                      <Link href={`/scans/${row.scan_id}`}>{row.source_label}</Link>
                    </td>
                    <td>{new Date(row.created_at).toLocaleString()}</td>
                    <td>{formatDuration(row.compute_seconds)}</td>
                    <td>{row.llm_tokens.toLocaleString()}</td>
                    <td>{formatUsd(row.total_usd)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
