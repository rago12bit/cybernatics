"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, evidenceDownloadUrl, listManualFindings } from "@/lib/api";
import type { ManualFindingView } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";

/** What a person recorded about this Issue by hand (plan §43.2): the CVSS 4.0 vector beside its
 * score, the steps as written, and the evidence -- which is only ever downloaded, never displayed
 * here, whatever kind of file it is (threat T24). Renders nothing for an Issue nobody recorded. */

const sizeLabel = (n: number) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1048576).toFixed(1)} MB`);

export function ManualFindingPanel({ assetId, issueId }: { assetId: string; issueId: string }) {
  const [rows, setRows] = useState<ManualFindingView[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listManualFindings(assetId, issueId).then((r) => setRows(Array.isArray(r) ? r : []), () => setRows([]));
  }, [assetId, issueId]);

  async function download(id: string) {
    setError(null);
    try {
      window.location.assign(await evidenceDownloadUrl(id));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not prepare the download.");
    }
  }

  if (rows.length === 0) return null;
  return (
    <section className="ds-issue-section ds-manual" aria-label="Recorded by hand">
      {rows.map((m) => (
        <div key={m.id}>
          <div className="ds-issue-label">Recorded by hand</div>
          <p className="ds-issue-meta">
            {m.created_by ?? "Someone"} on <time dateTime={m.created_at}>{new Date(m.created_at).toLocaleDateString()}</time>
            {m.location_kind === "route" && m.route && <> · <code>{m.method ?? ""} {m.route}</code></>}
            {m.host && <> on <code>{m.host}</code></>}
          </p>
          {m.cvss_vector && (
            <p>
              <strong>{m.cvss_score}</strong> CVSS 4.0 · <code className="ds-manual-vector">{m.cvss_vector}</code>
            </p>
          )}
          {m.cwe && <p>{m.cwe}{m.cwe_name ? `: ${m.cwe_name}` : ""}</p>}
          {m.related_issue_id && (
            <p>
              Also found by <strong>{m.related_source}</strong>, whose taint path is shown above.{" "}
              <Link href={`/app/projects/${assetId}/issues/${m.related_issue_id}`}>Open that issue</Link>
            </p>
          )}
          {([["Steps to reproduce", m.steps], ["Impact", m.impact], ["Recommendation", m.recommendation]] as const)
            .filter(([, text]) => text.trim())
            .map(([label, text]) => (
              <div key={label}>
                <h3 className="ds-manual-h">{label}</h3>
                <p className="ds-manual-text">{text}</p>
              </div>
            ))}
          {m.references.length > 0 && (
            <ul>{m.references.map((r) => <li key={r}><a href={r} rel="noopener noreferrer nofollow" target="_blank">{r}</a></li>)}</ul>
          )}
          {m.attachments.length > 0 && (
            <>
              <h3 className="ds-manual-h">Evidence</h3>
              <ul className="ds-manual-files">
                {m.attachments.map((a) => (
                  <li key={a.id}>
                    <span>{a.file_name}</span>{" "}
                    <span className="ds-issue-meta">
                      {a.sniffed_type} · {sizeLabel(a.size_bytes)}
                      {a.encrypted ? " · encrypted at rest" : ""}
                      {a.active_content ? " · can contain script: opens only as a download" : ""}
                    </span>{" "}
                    <Button onClick={() => download(a.id)}>Download<span className="ds-manual-sr"> {a.file_name}</span></Button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      ))}
      {error && <p role="alert" className="ds-manual-error">{error}</p>}
    </section>
  );
}
