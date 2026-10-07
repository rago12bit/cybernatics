"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useState } from "react";
import {
  API_URL, ApiError, createReportLink, deleteReport, downloadReportPdf, downloadReportSignature, draftReportSummary,
  generateReport, getReport, listAssets, listFrameworks, listPortfolios, listReportLinks, listReportRuns, reviewReportSummary,
  revokeReportLink, saveReport,
} from "@/lib/api";
import { CATALOGUE, describeFilters, type WidgetFilters } from "@/lib/dashboard";
import {
  ACCEPTANCE_STATES, BLOCK_LABEL, BLOCK_TYPES, ISSUE_KINDS, WEEKDAYS, idFrom, moveBlock, newBlock, scheduleWords,
  type Block, type BlockType, type NewLink, type Report, type ReportLink, type ReportRun, type Schedule,
} from "@/lib/reports";
import type { AssetSummary, ComplianceFramework, Portfolio } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { WidgetFiltersForm } from "../dashboard/WidgetFiltersForm";
import "../dashboard/dashboard.css";
import "./reports.css";

/* The report builder (plan §48.3): blocks in order (Move up / Move down, announced), each with its
 * settings; the executive summary, which a model may draft and a person must confirm; a schedule;
 * and the generated PDFs, each with its SHA-256, signature, and links that expire or are revoked. */

type FieldError = { field: string; message: string };
const PERIODS = [7, 14, 30, 90, 180, 365];
const LINK_DAYS = [1, 7, 14, 30, 90];

function errorOf(e: unknown, fallback: string): { message: string; field?: string } {
  if (e instanceof ApiError) {
    const d = e.data as Partial<FieldError> | undefined;
    return { message: d?.message ?? e.message, field: d?.field };
  }
  return { message: fallback };
}

function SummaryEditor({ report, block, onReport, onText, locked }: {
  report: Report; block: Block; onReport: (r: Report) => void; onText: (t: string) => void; locked: boolean;
}) {
  const id = useId();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const cfg = block.config as { text?: string; source?: string; drafted_by_model?: string; reviewed_by?: string | null; reviewed_at?: string | null };
  const ai = cfg.source === "ai";
  async function draft() {
    setBusy(true); setError(null);
    try {
      const r = await draftReportSummary(report.id);
      setNotes(r.notes ?? []);
      onReport(r);
    } catch (e) { setError(errorOf(e, "Could not draft the summary.").message); } finally { setBusy(false); }
  }
  async function confirm() {
    setBusy(true); setError(null);
    try { onReport(await reviewReportSummary(report.id, report.version, cfg.text ?? "")); }
    catch (e) { setError(errorOf(e, "Could not confirm the summary.").message); } finally { setBusy(false); }
  }
  return (
    <div>
      {ai && (
        <p className={report.summary_needs_review ? "rep-ai rep-warn" : "rep-ai"} id={`${id}-label`}>
          {report.summary_needs_review
            ? `AI draft (${cfg.drafted_by_model ?? "a model"}), not reviewed yet. Read it, edit it, then confirm it: the report can't be generated or sent until you do.`
            : `Drafted by AI (${cfg.drafted_by_model ?? "a model"}) from this report's data; reviewed. The PDF says so.`}
        </p>
      )}
      <label htmlFor={`${id}-text`} className="dash-label">Summary</label>
      <textarea id={`${id}-text`} rows={7} value={cfg.text ?? ""} maxLength={8000}
        aria-describedby={ai ? `${id}-label` : undefined} onChange={(e) => onText(e.target.value)} />
      {notes.map((n) => <p key={n} className="dash-muted dash-small">{n}</p>)}
      {error && <p role="alert" className="dash-error">{error}</p>}
      <div className="dash-row">
        <Button type="button" onClick={draft} disabled={busy || locked} aria-describedby={locked ? `${id}-locked` : undefined}>Draft with AI</Button>
        {ai && report.summary_needs_review && (
          <Button type="button" variant="primary" onClick={confirm} disabled={busy || locked || !(cfg.text ?? "").trim()}
            aria-describedby={locked ? `${id}-locked` : undefined}>
            Confirm this summary
          </Button>
        )}
      </div>
      {locked && <p id={`${id}-locked`} className="rep-warn dash-small">Save your other changes first.</p>}
      <p className="dash-muted dash-small">Drafting sends this report&apos;s numbers, and a few issue titles marked as untrusted, to the model.</p>
    </div>
  );
}

function BlockSettings({ block, onChange, frameworks, portfolios, projects, names }: {
  block: Block; onChange: (b: Block) => void; frameworks: ComplianceFramework[]; portfolios: Portfolio[];
  projects: AssetSummary[]; names: Record<string, string>;
}) {
  const id = useId();
  const [filtering, setFiltering] = useState(false);
  const c = block.config as Record<string, unknown>;
  const set = (patch: Record<string, unknown>) => onChange({ ...block, config: { ...block.config, ...patch } });
  const text = (key: string, label: string, max: number) => (
    <div className="rep-field">
      <label htmlFor={`${id}-${key}`} className="dash-label">{label}</label>
      <input id={`${id}-${key}`} value={String(c[key] ?? "")} maxLength={max} onChange={(e) => set({ [key]: e.target.value })} />
    </div>
  );
  const select = (key: string, label: string, options: [string, string][]) => (
    <div className="rep-field">
      <label htmlFor={`${id}-${key}`} className="dash-label">{label}</label>
      <select id={`${id}-${key}`} value={String(c[key] ?? "")} onChange={(e) => set({ [key]: e.target.value || null })}>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
    </div>
  );
  const pasted = (key: string, label: string, hint: string) => (
    <div className="rep-field">
      <label htmlFor={`${id}-${key}`} className="dash-label">{label}</label>
      <input id={`${id}-${key}`} defaultValue={String(c[key] ?? "")} aria-describedby={`${id}-${key}-hint`}
        onChange={(e) => set({ [key]: idFrom(e.target.value) ?? e.target.value.trim() })} />
      <p id={`${id}-${key}-hint`} className="dash-muted dash-small">{hint}</p>
    </div>
  );
  const filters = (
    <div className="rep-field">
      <span className="dash-label">Filters</span>
      <p className="dash-small">{describeFilters(c.filters as WidgetFilters, names) || "All projects; the report's period"}</p>
      <Button type="button" onClick={() => setFiltering(true)} aria-label={`Filters: ${BLOCK_LABEL[block.type]}`}>Filters</Button>
      <Dialog open={filtering} onOpenChange={setFiltering} title={`Filters: ${BLOCK_LABEL[block.type]}`}>
        <WidgetFiltersForm
          widget={{ id: block.id, metric: block.type === "metric" ? String(c.metric) : "open_issues", x: 0, y: 0, w: 6, h: 4, filters: c.filters as WidgetFilters }}
          portfolios={portfolios} projects={projects}
          onApply={(f) => { set({ filters: f }); setFiltering(false); }} onCancel={() => setFiltering(false)} />
      </Dialog>
    </div>
  );
  switch (block.type) {
    case "cover":
      return <div className="rep-fields">{text("title", "Title", 120)}{text("subtitle", "Subtitle", 200)}</div>;
    case "metric":
      return <div className="rep-fields">{select("metric", "Metric", CATALOGUE.map((m) => [m.metric, m.title]))}{filters}</div>;
    case "issues":
      return (
        <div className="rep-fields">
          {text("title", "Heading (optional)", 120)}
          {select("kind", "Which issues", ISSUE_KINDS)}
          {select("band", "Priority", [["", "Any"], ["P1", "P1"], ["P2", "P2"], ["P3", "P3"], ["P4", "P4"]])}
          <div className="rep-field">
            <label htmlFor={`${id}-limit`} className="dash-label">At most</label>
            <input id={`${id}-limit`} type="number" min={1} max={200} value={Number(c.limit ?? 50)}
              onChange={(e) => set({ limit: Number(e.target.value) })} />
          </div>
          {filters}
        </div>
      );
    case "issue":
      return <div className="rep-fields">{pasted("issue_id", "Issue", "Paste the issue's link from its page, or its id.")}</div>;
    case "engagement":
      return <div className="rep-fields">{pasted("engagement_id", "Engagement", "Paste the engagement's link from its page, or its id.")}</div>;
    case "acceptances":
      return <div className="rep-fields">{select("state", "Which", ACCEPTANCE_STATES)}</div>;
    case "compliance":
      return <div className="rep-fields">{select("framework", "Framework", frameworks.map((f) => [f.id, f.name]))}</div>;
    case "appendix":
      return <p className="dash-muted dash-small">Every metric's definition used above, and how to check the PDF's signature. Nothing to set.</p>;
    default:
      return null;
  }
}

function ScheduleEditor({ schedule, onChange }: { schedule: Schedule | null; onChange: (s: Schedule | null) => void }) {
  const id = useId();
  const s = schedule ?? { cadence: "weekly", weekday: 0, day: 1, hour: 8, recipients: [], link_days: 14 } as Schedule;
  const [recipients, setRecipients] = useState(s.recipients.join("\n"));
  const set = (patch: Partial<Schedule>) => onChange({ ...s, ...patch });
  return (
    <fieldset className="rep-panel">
      <legend><h2>Schedule</h2></legend>
      <label className="rep-check">
        <input type="checkbox" checked={schedule !== null} onChange={(e) => onChange(e.target.checked ? s : null)} />
        Generate this report on a schedule and email recipients a link to it
      </label>
      {schedule && (
        <div className="rep-fields">
          <div className="rep-field">
            <label htmlFor={`${id}-cad`} className="dash-label">How often</label>
            <select id={`${id}-cad`} value={s.cadence} onChange={(e) => set({ cadence: e.target.value as Schedule["cadence"] })}>
              <option value="weekly">Weekly</option><option value="monthly">Monthly</option>
            </select>
          </div>
          {s.cadence === "weekly" ? (
            <div className="rep-field">
              <label htmlFor={`${id}-wd`} className="dash-label">On</label>
              <select id={`${id}-wd`} value={s.weekday} onChange={(e) => set({ weekday: Number(e.target.value) })}>
                {WEEKDAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
              </select>
            </div>
          ) : (
            <div className="rep-field">
              <label htmlFor={`${id}-day`} className="dash-label">Day of the month</label>
              <input id={`${id}-day`} type="number" min={1} max={28} value={s.day} onChange={(e) => set({ day: Number(e.target.value) })} />
            </div>
          )}
          <div className="rep-field">
            <label htmlFor={`${id}-hr`} className="dash-label">Hour (UTC)</label>
            <input id={`${id}-hr`} type="number" min={0} max={23} value={s.hour} onChange={(e) => set({ hour: Number(e.target.value) })} />
          </div>
          <div className="rep-field">
            <label htmlFor={`${id}-ld`} className="dash-label">Links last</label>
            <select id={`${id}-ld`} value={s.link_days} onChange={(e) => set({ link_days: Number(e.target.value) })}>
              {LINK_DAYS.map((d) => <option key={d} value={d}>{d} day{d === 1 ? "" : "s"}</option>)}
            </select>
          </div>
          <div className="rep-field rep-wide">
            <label htmlFor={`${id}-to`} className="dash-label">Recipients, one email address per line</label>
            <textarea id={`${id}-to`} rows={3} value={recipients}
              onChange={(e) => { setRecipients(e.target.value); set({ recipients: e.target.value.split(/[\n,]/).map((x) => x.trim()).filter(Boolean) }); }} />
          </div>
          <p className="dash-muted dash-small rep-wide">Recipients get a link that needs no sign-in, never the PDF itself. A report with an AI summary nobody has confirmed is not sent.</p>
        </div>
      )}
    </fieldset>
  );
}

function RunRow({ run }: { run: ReportRun }) {
  const id = useId();
  const [links, setLinks] = useState<ReportLink[] | null>(null);
  const [fresh, setFresh] = useState<NewLink | null>(null);
  const [days, setDays] = useState(7);
  const [error, setError] = useState<string | null>(null);
  const loadLinks = useCallback(() => listReportLinks(run.id).then(setLinks, () => setLinks([])), [run.id]);
  useEffect(() => { if (run.status === "done") void loadLinks(); }, [loadLinks, run.status]);
  async function share() {
    setError(null);
    try { setFresh(await createReportLink(run.id, days)); await loadLinks(); }
    catch (e) { setError(errorOf(e, "Could not create the link.").message); }
  }
  async function revoke(l: ReportLink) {
    try { await revokeReportLink(l.id); await loadLinks(); if (fresh?.id === l.id) setFresh(null); }
    catch (e) { setError(errorOf(e, "Could not revoke the link.").message); }
  }
  const url = fresh ? fresh.url ?? `${API_URL}${fresh.path}` : null;
  if (run.status !== "done") {
    return (
      <li className="rep-run">
        <p><strong>{new Date(run.created_at).toLocaleString()}</strong> · {run.trigger === "schedule" ? "on its schedule" : `by ${run.created_by_name ?? run.created_by}`}</p>
        {run.status === "queued"
          ? <p role="status">Being made. This takes a few seconds.</p>
          : <p role="alert" className="dash-error">{run.error ?? "Could not make the PDF."}</p>}
      </li>
    );
  }
  return (
    <li className="rep-run">
      <p>
        <strong>{new Date(run.created_at).toLocaleString()}</strong> · {run.trigger === "schedule" ? "on its schedule" : `by ${run.created_by_name ?? run.created_by}`} ·
        covers {run.period[0]} to {run.period[1]} · {(run.size / 1024).toFixed(0)} KB · {run.signed ? "signed" : "not signed (no key set up)"}
        {run.ai_summary ? " · AI-drafted summary, reviewed" : ""}
      </p>
      <p className="dash-small">SHA-256 <code className="rep-hash">{run.sha256}</code></p>
      {run.delivery.length > 0 && (
        <p className="dash-small">Sent: {run.delivery.map((d) => `${d.to} (${d.status}${d.reason ? `: ${d.reason}` : ""})`).join(", ")}</p>
      )}
      <div className="dash-row">
        <Button type="button" onClick={() => void downloadReportPdf(run.id)}>Download PDF</Button>
        {run.signed && <Button type="button" onClick={() => void downloadReportSignature(run.id)}>Download signature</Button>}
        <label htmlFor={`${id}-days`} className="dash-label">Link lasts</label>
        <select id={`${id}-days`} value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {LINK_DAYS.map((d) => <option key={d} value={d}>{d} day{d === 1 ? "" : "s"}</option>)}
        </select>
        <Button type="button" onClick={share}>Create a link</Button>
      </div>
      {error && <p role="alert" className="dash-error">{error}</p>}
      {url && (
        <div role="status" className="rep-link">
          <p>Anyone with this link can open the PDF until {new Date(fresh!.expires_at).toLocaleDateString()}. It is shown only now:</p>
          <input readOnly value={url} aria-label="The new link" onFocus={(e) => e.currentTarget.select()} />
          <Button type="button" onClick={() => void navigator.clipboard?.writeText(url)}>Copy</Button>
        </div>
      )}
      {links && links.length > 0 && (
        <div className="dash-table-wrap">
        <table className="dash-table">
          <caption>Links to this PDF</caption>
          <thead><tr><th scope="col">Created</th><th scope="col">State</th><th scope="col">Expires</th><th scope="col">Opened</th><th scope="col"><span className="sr-only">Action</span></th></tr></thead>
          <tbody>
            {links.map((l) => (
              <tr key={l.id}>
                <th scope="row">{new Date(l.created_at).toLocaleString()} by {l.created_by_name ?? l.created_by}</th>
                <td>{l.state}</td>
                <td>{new Date(l.expires_at).toLocaleDateString()}</td>
                <td>{l.opens} time{l.opens === 1 ? "" : "s"}</td>
                <td>{l.state === "active" && <Button type="button" onClick={() => void revoke(l)} aria-label={`Revoke the link created ${new Date(l.created_at).toLocaleString()}`}>Revoke</Button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
    </li>
  );
}

export function ReportBuilder({ reportId }: { reportId: string }) {
  const id = useId();
  const router = useRouter();
  const [report, setReport] = useState<Report | null>(null);
  const [draft, setDraft] = useState<Report | null>(null);
  const [runs, setRuns] = useState<ReportRun[]>([]);
  const [error, setError] = useState<FieldError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [announce, setAnnounce] = useState({ text: "", n: 0 });
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState<BlockType>("metric");
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [portfolios, setPortfolios] = useState<Portfolio[]>([]);
  const [projects, setProjects] = useState<AssetSummary[]>([]);
  const say = (text: string) => setAnnounce((a) => ({ text, n: a.n + 1 }));

  const show = useCallback((r: Report) => { setReport(r); setDraft(r); }, []);
  useEffect(() => {
    getReport(reportId).then(show, (e) => setError({ field: "", message: errorOf(e, "Could not load the report.").message }));
    listReportRuns(reportId).then(setRuns, () => setRuns([]));
    listFrameworks().then(setFrameworks, () => setFrameworks([]));
    listPortfolios().then(setPortfolios, () => setPortfolios([]));
    listAssets().then(setProjects, () => setProjects([]));
  }, [reportId, show]);

  // The worker renders a queued report; look again every two seconds until it is done or failed.
  const waiting = runs.some((r) => r.status === "queued");
  useEffect(() => {
    if (!waiting) return;
    const t = setInterval(() => { listReportRuns(reportId).then(setRuns, () => undefined); }, 2000);
    return () => clearInterval(t);
  }, [waiting, reportId]);

  if (!draft || !report) return error ? <p role="alert" className="dash-error">{error.message}</p> : <p role="status">Loading the report…</p>;
  const names = { ...Object.fromEntries(portfolios.map((p) => [p.id, p.name])), ...Object.fromEntries(projects.map((p) => [p.id, p.label])) };
  const dirty = JSON.stringify(draft) !== JSON.stringify(report);
  // Unsaved changes besides the summary's text: drafting or confirming would replace them.
  const summaryText = (r: Report) => r.blocks.find((b) => b.type === "summary")?.config.text;
  const withText = { ...draft, blocks: draft.blocks.map((b) => (b.type === "summary" ? { ...b, config: { ...b.config, text: summaryText(report) } } : b)) };
  const otherDirty = JSON.stringify(withText) !== JSON.stringify(report);
  const setBlocks = (blocks: Block[]) => setDraft({ ...draft, blocks });

  async function save(): Promise<Report | null> {
    if (!draft) return null;
    setBusy(true); setError(null); setNotice(null);
    try {
      const r = await saveReport(draft.id, { version: draft.version, name: draft.name, period_days: draft.period_days, blocks: draft.blocks, schedule: draft.schedule });
      show(r); setNotice("Saved."); return r;
    } catch (e) {
      const x = errorOf(e, "Could not save the report."); setError({ field: x.field ?? "", message: x.message }); return null;
    } finally { setBusy(false); }
  }
  async function generate() {
    setBusy(true); setError(null); setNotice(null);
    try {
      if (dirty && !(await save())) return;
      setBusy(true);
      const run = await generateReport(reportId);
      setRuns((r) => [run, ...r]);
      setNotice(run.status === "done" ? "Generated. Download it below, or create a link to share it." : "Queued. It appears below when it is ready.");
    } catch (e) {
      const x = errorOf(e, "Could not generate the report."); setError({ field: x.field ?? "", message: x.message });
    } finally { setBusy(false); }
  }
  async function remove() {
    if (!window.confirm(`Delete “${report!.name}” and every PDF generated from it? Links to them stop working.`)) return;
    try { await deleteReport(reportId); router.push("/app/reports"); }
    catch (e) { setError({ field: "", message: errorOf(e, "Could not delete the report.").message }); }
  }
  function move(b: Block, by: -1 | 1) {
    const next = moveBlock(draft!.blocks, b.id, by);
    setBlocks(next);
    const at = next.findIndex((x) => x.id === b.id);
    say(next === draft!.blocks ? `${BLOCK_LABEL[b.type]} is already ${by < 0 ? "first" : "last"}.` : `${BLOCK_LABEL[b.type]} moved to position ${at + 1} of ${next.length}.`);
    requestAnimationFrame(() => document.getElementById(`${id}-${b.id}-${by < 0 ? "up" : "down"}`)?.focus());
  }
  const blockError = (n: number) => (error?.field.startsWith(`blocks[${n}]`) ? <p role="alert" className="dash-error">{error.message}</p> : null);

  return (
    <div className="dash rep">
      <p><Link href="/app/reports">← Reports</Link></p>
      <span className="eyebrow">Report</span>
      <h1>{report.name}</h1>
      <p className="dash-muted">{scheduleWords(report.schedule)}{report.next_run_at ? `; next on ${new Date(report.next_run_at).toLocaleString()}` : ""}.</p>
      <div aria-live="polite" className="sr-only">{announce.text && <p key={announce.n}>{announce.text}</p>}</div>
      {notice && <p role="status" className="dash-notice">{notice}</p>}
      {error && !error.field.startsWith("blocks[") && <p role="alert" className="dash-error">{error.message}</p>}

      <div className="rep-panel rep-fields">
        <div className="rep-field">
          <label htmlFor={`${id}-name`} className="dash-label">Name</label>
          <input id={`${id}-name`} value={draft.name} maxLength={120} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        </div>
        <div className="rep-field">
          <label htmlFor={`${id}-period`} className="dash-label">Covers the last</label>
          <select id={`${id}-period`} value={draft.period_days} onChange={(e) => setDraft({ ...draft, period_days: Number(e.target.value) })}>
            {[...new Set([...PERIODS, draft.period_days])].sort((a, b) => a - b).map((d) => <option key={d} value={d}>{d} days</option>)}
          </select>
        </div>
      </div>

      <h2>Blocks</h2>
      <ol className="rep-blocks">
        {draft.blocks.map((b, n) => (
          <li key={b.id} className="rep-block" aria-labelledby={`${id}-${b.id}-h`}>
            <div className="rep-block-head">
              <h3 id={`${id}-${b.id}-h`}>{n + 1}. {BLOCK_LABEL[b.type]}</h3>
              <div className="dash-row">
                <Button type="button" id={`${id}-${b.id}-up`} onClick={() => move(b, -1)} disabled={n === 0} aria-label={`Move ${BLOCK_LABEL[b.type]} up`}>Up</Button>
                <Button type="button" id={`${id}-${b.id}-down`} onClick={() => move(b, 1)} disabled={n === draft.blocks.length - 1} aria-label={`Move ${BLOCK_LABEL[b.type]} down`}>Down</Button>
                <Button type="button" onClick={() => { setBlocks(draft.blocks.filter((x) => x.id !== b.id)); say(`Removed ${BLOCK_LABEL[b.type]}.`); }}
                  aria-label={`Remove ${BLOCK_LABEL[b.type]}`}>Remove</Button>
              </div>
            </div>
            {b.type === "summary" ? (
              <SummaryEditor report={report} block={b} onReport={show} locked={otherDirty}
                onText={(t) => setBlocks(draft.blocks.map((x) => (x.id === b.id ? { ...x, config: { ...x.config, text: t } } : x)))} />
            ) : (
              <BlockSettings block={b} frameworks={frameworks} portfolios={portfolios} projects={projects} names={names}
                onChange={(nb) => setBlocks(draft.blocks.map((x) => (x.id === b.id ? nb : x)))} />
            )}
            {blockError(n)}
          </li>
        ))}
      </ol>
      <div className="dash-row rep-add">
        <label htmlFor={`${id}-add`} className="dash-label">Add a block</label>
        <select id={`${id}-add`} value={adding} onChange={(e) => setAdding(e.target.value as BlockType)}>
          {BLOCK_TYPES.filter((t) => t !== "summary" || !draft.blocks.some((b) => b.type === "summary")).map((t) => (
            <option key={t} value={t}>{BLOCK_LABEL[t]}</option>
          ))}
        </select>
        <Button type="button" onClick={() => { const b = newBlock(adding, draft.blocks); setBlocks([...draft.blocks, b]); say(`Added ${BLOCK_LABEL[adding]} at the end.`); }}>Add</Button>
      </div>

      <ScheduleEditor schedule={draft.schedule} onChange={(s) => setDraft({ ...draft, schedule: s })} />

      <div className="dash-row rep-actions">
        <Button type="button" onClick={() => void save()} disabled={busy || !dirty}>Save</Button>
        <Button type="button" variant="primary" onClick={() => void generate()} disabled={busy || report.summary_needs_review}>
          {busy ? "Working…" : dirty ? "Save and generate PDF" : "Generate PDF"}
        </Button>
        <Button type="button" onClick={() => void remove()}>Delete report</Button>
      </div>
      {report.summary_needs_review && <p className="rep-warn">Confirm the AI-drafted summary before generating.</p>}

      <h2>Generated</h2>
      {runs.length === 0 ? <p className="dash-muted">Nothing generated yet.</p> : (
        <ul className="rep-runs">{runs.map((r) => <RunRow key={r.id} run={r} />)}</ul>
      )}
    </div>
  );
}
