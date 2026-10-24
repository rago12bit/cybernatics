"use client";

import { useEffect, useId, useState } from "react";
import { ApiError, createEvidencePack, downloadEvidencePack, listEvidencePacks, listFrameworks, previewEvidencePack } from "@/lib/api";
import type { ComplianceFramework, EvidencePack, EvidencePreview, EvidenceSummary } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Loading } from "@/design-system/primitives/Loading";
import "./compliance.css";
import { formatDateTime } from "@/lib/format";

/** Evidence packs (plan §47): pick a period and frameworks, see what will be included, generate a
 * signed PDF plus a machine-readable bundle an auditor can check with its own verify.py. */

const iso = (d: Date) => d.toISOString().slice(0, 10);
const pct = (v: number | null) => (v === null ? "n/a" : `${(v * 100).toFixed(1)}%`);

function Summary({ s }: { s: EvidenceSummary }) {
  const a = s.audit;
  return (
    <ul className="ds-cmp-plain">
      <li><strong>{s.scanned}</strong> of {s.projects} projects scanned in the period</li>
      <li>SLA adherence <strong>{pct(s.sla.adherence)}</strong>: {s.sla.met} met, {s.sla.missed} missed, {s.sla.open_past_deadline} open past the deadline, {s.sla.exempt} exempt</li>
      <li><strong>{s.risk_acceptances}</strong> risk acceptances, with their approvals</li>
      <li><strong>{s.open_issues}</strong> open Issues by priority (as of generation)</li>
      <li><strong>{s.vex_confirmed}</strong> VEX statements confirmed · <strong>{s.engagements}</strong> assessments</li>
      <li>
        Audit log: {a.entries} entries, {a.disclosed} of yours shown in full, {a.ok ? "chain intact" : <span className="ds-cmp-bad">chain broken</span>};{" "}
        {a.anchored_at.length ? `anchored by Rekor checkpoints at entries ${a.anchored_at.join(", ")}` : "no Rekor checkpoint covers these entries yet"}
        {a.linked_only ? ` · ${a.linked_only} older entries checked by link only` : ""}
      </li>
    </ul>
  );
}

export function EvidenceScreen() {
  const fid = useId();
  const today = new Date();
  const [start, setStart] = useState(iso(new Date(today.getTime() - 89 * 86_400_000)));
  const [end, setEnd] = useState(iso(today));
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<EvidencePreview | null>(null);
  const [packs, setPacks] = useState<EvidencePack[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    listFrameworks().then((f) => { setFrameworks(f); setChosen(new Set(f.map((x) => x.id))); }, () => setError("Could not load the frameworks."));
    listEvidencePacks().then(setPacks, () => setPacks([]));
  }, []);
  useEffect(() => setPreview(null), [start, end, chosen]);

  const body = () => ({ start, end, frameworks: [...chosen] });
  async function run(fn: () => Promise<void>, failure: string) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : failure);
    } finally {
      setBusy(false);
    }
  }
  const toggle = (id: string) => setChosen((c) => { const n = new Set(c); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div className="ds-cmp">
      <header>
        <h1 className="ds-cmp-title">Evidence packs</h1>
        <p className="ds-cmp-lede">For a period: SLA adherence, every risk acceptance with its approvals, scan coverage, open Issues by priority, VEX, assessments, how each framework&apos;s controls map to that evidence, and an extract of the audit log an auditor can check without trusting Bulwark.</p>
        <p className="ds-cmp-meta">This shows where evidence supports a control. It is not a certification or an audit opinion.</p>
      </header>

      <section aria-labelledby={`${fid}-new`} className="ds-cmp-box">
        <h2 id={`${fid}-new`}>New pack</h2>
        <div className="ds-cmp-filters">
          <label htmlFor={`${fid}-from`}>From</label>
          <input id={`${fid}-from`} type="date" value={start} max={end} onChange={(e) => setStart(e.target.value)} />
          <label htmlFor={`${fid}-to`}>To</label>
          <input id={`${fid}-to`} type="date" value={end} min={start} onChange={(e) => setEnd(e.target.value)} />
        </div>
        <fieldset className="ds-cmp-fieldset">
          <legend>Frameworks</legend>
          {frameworks.map((f) => (
            <label key={f.id} className="ds-cmp-check">
              <input type="checkbox" checked={chosen.has(f.id)} onChange={() => toggle(f.id)} />
              {f.name} <span className="ds-cmp-meta">(mapping v{f.mapping_version}, {f.controls} controls)</span>
            </label>
          ))}
        </fieldset>
        <div className="ds-cmp-actions">
          <Button disabled={busy || !start || !end} onClick={() => run(async () => setPreview(await previewEvidencePack(body())), "Could not preview the pack.")}>See what will be included</Button>
          <Button variant="primary" disabled={busy || !preview} onClick={() => run(async () => {
            const p = await createEvidencePack(body());
            setPacks((old) => [p, ...(old ?? [])]);
            setPreview(null);
          }, "Could not generate the pack.")}>
            {busy ? "Working…" : "Generate the pack"}
          </Button>
        </div>
        {preview && (
          <div role="status" className="ds-cmp-preview">
            <Summary s={preview} />
            <p className="ds-cmp-meta">{preview.signing ? "The pack will be signed with this deployment's key." : "This deployment has no signing key: the pack will be marked unsigned."}</p>
          </div>
        )}
        {error && <p role="alert" className="ds-cmp-error">{error}</p>}
      </section>

      <section aria-labelledby={`${fid}-list`} className="ds-cmp-box">
        <h2 id={`${fid}-list`}>Generated</h2>
        {packs === null ? <Loading lines={2} /> : packs.length === 0 ? <p className="ds-cmp-meta">None yet.</p> : (
          <ul className="ds-cmp-list">
            {packs.map((p) => (
              <li key={p.id} className="ds-cmp-item">
                <div>
                  <strong>{p.period_start} to {p.period_end}</strong> · {p.signed ? "signed" : <span className="ds-cmp-bad">unsigned</span>} · {(p.size / 1024).toFixed(0)} KB
                  <span className="ds-cmp-meta"> · by {p.created_by}, {formatDateTime(p.created_at)}</span>
                </div>
                <Summary s={p.summary} />
                <p className="ds-cmp-meta ds-cmp-wrap">SHA-256 <code>{p.sha256}</code></p>
                <div className="ds-cmp-actions">
                  <Button onClick={() => run(() => downloadEvidencePack(p.id), "Could not download the pack.")}>Download the bundle (.zip)</Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
