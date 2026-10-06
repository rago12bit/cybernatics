"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import { ApiError, decideVex, downloadVex, getProjectVex } from "@/lib/api";
import type { ProjectVex, VexStatement } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { justificationLabel } from "@/lib/vex";
import "./compliance.css";

/** A project's VEX (plan §46.3): what its exported documents say about each vulnerability in its
 * current SBOM, the statements people confirmed (with the evidence), and the downloads. Only
 * vulnerabilities the advisory engine knows are included. */

const STATUS: Record<VexStatement["status"], string> = {
  not_affected: "Not affected",
  affected: "Affected",
  fixed: "Fixed",
  under_investigation: "Under investigation",
};
const BASIS: Record<string, string> = {
  vex: "confirmed VEX statement",
  "vex-stale": "a confirmed statement the latest scan contradicts",
  issue: "Issue marked not a risk",
  uncertain: "version could not be compared",
  match: "advisory match",
};
const STATE: Record<VexStatement["state"], string> = {
  proposed: "Proposed", confirmed: "Confirmed", rejected: "Rejected", withdrawn: "Withdrawn",
};

export function ProjectVexScreen({ assetId }: { assetId: string }) {
  const fid = useId();
  const [v, setV] = useState<ProjectVex | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getProjectVex(assetId).then(setV, (e) => setError(e instanceof ApiError && e.status === 404 ? "Project not found." : "Could not load the project's VEX."));
  }, [assetId]);
  useEffect(load, [load]);

  async function act(fn: () => Promise<unknown>, failure: string) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : failure);
    } finally {
      setBusy(false);
    }
  }

  if (!v) return <div className="ds-cmp">{error ? <p role="alert" className="ds-cmp-error">{error}</p> : <p>Loading…</p>}</div>;
  const counts = Object.entries(v.counts).map(([k, n]) => `${n} ${STATUS[k as VexStatement["status"]].toLowerCase()}`);
  return (
    <div className="ds-cmp">
      <header>
        <h1 className="ds-cmp-title">VEX for {v.project}</h1>
        <p className="ds-cmp-lede">
          {v.exported.length
            ? `The project's VEX says, for each vulnerability in its current SBOM: ${counts.join(", ")}.`
            : "No vulnerability the advisory engine knows is in this project's current SBOM."}
        </p>
        <div className="ds-cmp-actions">
          <Button disabled={busy} onClick={() => act(() => downloadVex(assetId, "openvex"), "Could not download.")}>Download OpenVEX</Button>
          <Button disabled={busy} onClick={() => act(() => downloadVex(assetId, "cyclonedx"), "Could not download.")}>Download CycloneDX VEX</Button>
        </div>
        {error && <p role="alert" className="ds-cmp-error">{error}</p>}
      </header>

      {v.exported.length > 0 && (
        <section aria-labelledby={`${fid}-doc`} className="ds-cmp-box">
          <h2 id={`${fid}-doc`}>What the documents say</h2>
          <table className="ds-cmp-table">
            <thead>
              <tr><th scope="col">Vulnerability</th><th scope="col">Package</th><th scope="col">Status</th><th scope="col">Why</th></tr>
            </thead>
            <tbody>
              {v.exported.map((e) => (
                <tr key={`${e.vuln_key}-${e.purl}`}>
                  <th scope="row" data-label="Vulnerability"><Link href={`/app/advisories/${encodeURIComponent(e.vuln_key)}`}>{e.vuln_key}</Link></th>
                  <td data-label="Package"><span className="ds-cmp-wrap">{e.library}</span> <code>{e.version}</code></td>
                  <td data-label="Status" className={e.status === "not_affected" ? "ds-cmp-ok" : e.status === "affected" ? "ds-cmp-bad" : ""}>{STATUS[e.status]}</td>
                  <td data-label="Why">
                    <span className="ds-cmp-wrap">
                      {e.justification ? justificationLabel(e.justification) : e.action_statement || e.impact_statement || ""}
                    </span>
                    <span className="ds-cmp-meta"> · from {BASIS[e.basis] ?? e.basis}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section aria-labelledby={`${fid}-st`} className="ds-cmp-box">
        <h2 id={`${fid}-st`}>Statements</h2>
        {v.statements.length === 0 ? (
          <p className="ds-cmp-meta">None yet. Draft them from an advisory&apos;s page: Bulwark proposes them where the code shows it does not execute the vulnerability.</p>
        ) : (
          <ul className="ds-cmp-list">
            {v.statements.map((st) => (
              <li key={st.id} className="ds-cmp-item">
                <div>
                  <strong>{STATE[st.state]}</strong> · <Link href={`/app/advisories/${encodeURIComponent(st.vuln_key)}`}>{st.vuln_key}</Link> · {st.library} <code>{st.version}</code>
                </div>
                <p className="ds-cmp-wrap">{st.impact_statement}</p>
                {"caveats" in st.evidence && st.evidence.caveats.length > 0 && (
                  <ul className="ds-cmp-meta">{st.evidence.caveats.map((c) => <li key={c}>{c}</li>)}</ul>
                )}
                <p className="ds-cmp-meta">
                  Proposed {new Date(st.proposed_at).toLocaleDateString()}
                  {st.decided_by && ` · ${STATE[st.state].toLowerCase()} by ${st.decided_by}`}
                  {st.note && ` · ${st.note}`}
                </p>
                {st.state === "proposed" && (
                  <div className="ds-cmp-actions">
                    <Button variant="primary" disabled={busy} onClick={() => act(() => decideVex(st.id, "confirm"), "Could not confirm.")}>Confirm</Button>
                    <Button disabled={busy} onClick={() => act(() => decideVex(st.id, "reject"), "Could not reject.")}>Reject</Button>
                  </div>
                )}
                {st.state === "confirmed" && (
                  <div className="ds-cmp-actions">
                    <Button disabled={busy} onClick={() => act(() => decideVex(st.id, "withdraw"), "Could not withdraw.")}>Withdraw</Button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
