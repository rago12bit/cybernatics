"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import { ApiError, closeEngagement, downloadReport, getEngagement, updateEngagement } from "@/lib/api";
import type { Engagement, EngagementDetail, EngagementFinding, EngagementStatus } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { SeverityIcon } from "@/design-system/severity";
import { EngagementForm } from "./EngagementForm";
import "./engagement.css";

/** Plan §55.2: one assessment. Scope and people, checklist progress, its findings -- with what else
 * found them ("Also found by Opengrep taint", cross-source correlation where the tester works) and
 * where their retests stand -- its tests, and the way out: close it and write the report. */

export const STATUS_WORD: Record<EngagementStatus, string> = {
  planned: "Planned",
  in_progress: "In progress",
  reporting: "Reporting",
  closed: "Closed",
};

const NEXT: Record<EngagementStatus, [EngagementStatus, string][]> = {
  planned: [["in_progress", "Start testing"]],
  in_progress: [["reporting", "Move to reporting"], ["planned", "Back to planned"]],
  reporting: [["in_progress", "Back to testing"]],
  closed: [["in_progress", "Reopen"]],
};
const SHOWN = 8;

const fmt = (iso: string) => new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "long" });

export function dateRange(e: Pick<Engagement, "status" | "starts_at" | "ends_at" | "closed_at">): string {
  if (e.status === "closed" && e.closed_at) return `closed ${fmt(e.closed_at)}`;
  if (e.status === "planned" && e.starts_at) return `starts ${fmt(e.starts_at)}`;
  return e.ends_at ? `ends ${fmt(e.ends_at)}` : "no end date";
}

function findingNote(f: EngagementFinding, names: Record<string, string>): string | null {
  if (f.state === "fixed") return f.retest_status === "passed" ? "Fixed: retest passed" : "Fixed";
  if (f.retest_status === "requested") {
    const who = f.retest_requested_by ? names[f.retest_requested_by] ?? f.retest_requested_by : null;
    return who ? `Retest requested by ${who}` : "Retest requested";
  }
  if (f.retest_status === "failed") return "Retest failed: still reproduces";
  if (f.also_found_by.length) return `Also found by ${f.also_found_by.join(", ")}`;
  return null;
}

export function EngagementScreen({ id }: { id: string }) {
  const fid = useId();
  const [e, setE] = useState<EngagementDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [all, setAll] = useState(false);
  const [closing, setClosing] = useState(false);
  const [summary, setSummary] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getEngagement(id).then(setE, (err) => setError(err instanceof ApiError ? err.message : "Could not load the engagement."));
  }, [id]);
  useEffect(load, [load]);

  async function move(to: EngagementStatus) {
    setBusy(true);
    setError(null);
    try {
      await updateEngagement(id, { status: to });
      setNotice(`Now ${STATUS_WORD[to].toLowerCase()}.`);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not change the status.");
    } finally {
      setBusy(false);
    }
  }

  async function close() {
    setBusy(true);
    setError(null);
    try {
      await closeEngagement(id, summary.trim() || undefined);
      setClosing(false);
      setNotice("Closed. The report is written: download it below.");
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not close the engagement.");
    } finally {
      setBusy(false);
    }
  }

  async function report(format: "md" | "html") {
    try {
      await downloadReport(id, format);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not download the report.");
    }
  }

  if (!e) return error ? <p role="alert" className="ds-eng-error">{error}</p> : <p role="status">Loading the engagement…</p>;
  const closed = e.status === "closed";
  const shown = all ? e.findings : e.findings.slice(0, SHOWN);
  const project = `/app/projects/${e.project_id}`;

  return (
    <div className="ds-eng">
      <header className="ds-eng-head">
        <h1 className="ds-eng-title">{e.name}</h1>
        <p className="ds-eng-meta">
          <Link href={project}>{e.project}</Link> <span aria-hidden="true">·</span>{" "}
          <span className={`ds-eng-status ds-eng-status-${e.status}`}>{STATUS_WORD[e.status]}</span>, {dateRange(e)}
        </p>
      </header>
      {error && <p role="alert" className="ds-eng-error">{error}</p>}
      {notice && <p role="status" className="ds-eng-notice">{notice}</p>}

      {editing ? (
        <section className="ds-eng-panel" aria-label="Edit engagement">
          <EngagementForm
            initial={e}
            submitLabel="Save"
            onCancel={() => setEditing(false)}
            onSubmit={async (body) => {
              await updateEngagement(id, body);
              setEditing(false);
              setNotice("Saved.");
              load();
            }}
          />
        </section>
      ) : (
        <dl className="ds-eng-facts">
          <div>
            <dt>Scope</dt>
            <dd>{[...e.scope_targets, ...e.scope_routes].join(", ") || "Not recorded"}</dd>
          </div>
          <div>
            <dt>Out</dt>
            <dd>{e.out_of_scope || "Nothing recorded"}</dd>
          </div>
          <div>
            <dt>Lead</dt>
            <dd>{e.lead || "Not recorded"}</dd>
          </div>
          <div>
            <dt>Testers</dt>
            <dd>{e.testers.join(", ") || "Not recorded"}</dd>
          </div>
          <div>
            <dt>Checklist</dt>
            <dd>
              {e.checklist ? (
                <>
                  {e.checklist.name}: {e.checklist.done} of {e.checklist.total} tests done{" "}
                  <Link href={`/app/engagements/${id}/checklist`}>Open</Link>
                </>
              ) : (
                "None"
              )}
            </dd>
          </div>
        </dl>
      )}

      {!editing && (
        <div className="ds-eng-actions ds-eng-actions-start">
          {NEXT[e.status].map(([to, label]) => (
            <Button key={to} onClick={() => move(to)} disabled={busy}>{label}</Button>
          ))}
          {!closed && <Button onClick={() => setEditing(true)} disabled={busy}>Edit details</Button>}
        </div>
      )}

      <div className="ds-eng-columns">
        <section className="ds-eng-panel" aria-labelledby={`${fid}-f`}>
          <div className="ds-eng-panel-head">
            <h2 id={`${fid}-f`}>Findings</h2>
            {!closed && (
              <Link className="ds-eng-button-link" href={`${project}/findings/new?engagement=${id}`}>Add a finding</Link>
            )}
          </div>
          {e.findings.length === 0 ? (
            <p className="ds-eng-empty">No findings yet. Add one, or import a tool&apos;s results.</p>
          ) : (
            <ul className="ds-eng-findings">
              {shown.map((f) => {
                const note = findingNote(f, e.names);
                return (
                  <li key={f.issue_id} className={f.state === "fixed" ? "ds-eng-fixed" : undefined}>
                    <span className="ds-eng-sev">
                      <SeverityIcon severity={f.severity.toLowerCase() as "critical" | "high" | "medium" | "low" | "info"} size={14} />{" "}
                      {f.severity.charAt(0) + f.severity.slice(1).toLowerCase()}
                    </span>
                    <span className="ds-eng-finding">
                      <Link href={`${project}/issues/${f.issue_id}`}>{f.title}</Link>
                      {note && <span className="ds-eng-meta">{note}</span>}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
          {e.findings.length > SHOWN && (
            <p>
              <button type="button" className="ds-eng-link" onClick={() => setAll(!all)}>
                {all ? "Show fewer" : `${e.findings.length - SHOWN} more: view all`}
              </button>
            </p>
          )}
        </section>

        <section className="ds-eng-panel" aria-labelledby={`${fid}-t`}>
          <h2 id={`${fid}-t`}>Tests</h2>
          {e.tests.length === 0 ? (
            <p className="ds-eng-empty">Nothing recorded or imported yet.</p>
          ) : (
            <table className="ds-eng-tests">
              <tbody>
                {e.tests.map((t) => (
                  <tr key={t.id}>
                    <th scope="row">{t.name}</th>
                    <td>{t.findings} finding{t.findings === 1 ? "" : "s"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="ds-eng-stack">
            {!closed && <Link className="ds-eng-button-link" href={`${project}/import?engagement=${id}`}>Import results</Link>}
            {(e.status === "in_progress" || e.status === "reporting") && (
              <Button variant="primary" onClick={() => setClosing(true)}>Close and write the report</Button>
            )}
            {e.report_generated_at && (
              <div className="ds-eng-report" role="group" aria-label="Report">
                <span className="ds-eng-meta">Report written {fmt(e.report_generated_at)}</span>
                <Button onClick={() => report("md")}>Download Markdown</Button>
                <Button onClick={() => report("html")}>Download HTML</Button>
              </div>
            )}
          </div>
        </section>
      </div>

      <Dialog
        open={closing}
        onOpenChange={(o) => !o && setClosing(false)}
        title="Close and write the report"
        description="The report records the scope, people, checklist, findings and tests as they are now. Later changes to an issue do not rewrite it."
      >
        <label htmlFor={`${fid}-sum`} className="ds-eng-label">Summary (optional, opens the report)</label>
        <textarea id={`${fid}-sum`} rows={4} value={summary} onChange={(ev) => setSummary(ev.target.value)} className="ds-eng-textarea" />
        <p className="ds-eng-meta">
          {e.findings.length} finding{e.findings.length === 1 ? "" : "s"}
          {e.checklist && `, checklist ${e.checklist.done} of ${e.checklist.total} done`}.
        </p>
        <div className="ds-eng-actions">
          <Button onClick={() => setClosing(false)}>Cancel</Button>
          <Button variant="primary" onClick={close} disabled={busy}>{busy ? "Writing…" : "Close and write the report"}</Button>
        </div>
      </Dialog>
    </div>
  );
}
