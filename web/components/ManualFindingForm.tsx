"use client";

import Link from "next/link";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  ApiError, listRoutes, recordManualFinding, scoreCvss4, searchCwe, uploadEvidence,
} from "@/lib/api";
import type {
  CvssScore, CweEntry, EvidenceFile, FieldError, ManualFindingInput, ManualRecorded, ProjectRoute, Severity,
} from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./manual-finding-form.css";

/** Recording a finding by hand (plan §43.2, §53.1 J9: "writes up a finding in under 3 minutes").
 *
 * Title, CWE (searchable), severity from a CVSS 4.0 calculator (every score comes from the API, so
 * there is one implementation), where it is -- a route from code intelligence or a file -- steps,
 * impact, recommendation, and evidence. Accessibility per §58: every field labelled, each error
 * next to its field, and a summary of them at the top on submit. Evidence files are uploaded once
 * the finding exists, and are never displayed in the page: they can only be downloaded. */

type Metric = { key: string; label: string; values: [string, string][] };
const IMPACT: [string, string][] = [["H", "High"], ["L", "Low"], ["N", "None"]];
const GROUPS: { legend: string; metrics: Metric[] }[] = [
  {
    legend: "Exploitability",
    metrics: [
      { key: "AV", label: "Attack vector", values: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
      { key: "AC", label: "Attack complexity", values: [["L", "Low"], ["H", "High"]] },
      { key: "AT", label: "Attack requirements", values: [["N", "None"], ["P", "Present"]] },
      { key: "PR", label: "Privileges required", values: [["N", "None"], ["L", "Low"], ["H", "High"]] },
      { key: "UI", label: "User interaction", values: [["N", "None"], ["P", "Passive"], ["A", "Active"]] },
    ],
  },
  {
    legend: "Impact on the vulnerable system",
    metrics: [
      { key: "VC", label: "Confidentiality", values: IMPACT },
      { key: "VI", label: "Integrity", values: IMPACT },
      { key: "VA", label: "Availability", values: IMPACT },
    ],
  },
  {
    legend: "Impact on other systems",
    metrics: [
      { key: "SC", label: "Confidentiality", values: IMPACT },
      { key: "SI", label: "Integrity", values: IMPACT },
      { key: "SA", label: "Availability", values: IMPACT },
    ],
  },
];
const BASE_KEYS = GROUPS.flatMap((g) => g.metrics.map((m) => m.key));
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const OTHER_ROUTE = "__other__";

const titleCase = (s: string) => s[0] + s.slice(1).toLowerCase();
const routeKey = (r: ProjectRoute) => `${r.method}|${r.route}|${r.path}|${r.line}`;

/** Base metrics from a pasted vector; anything beyond the base metrics is kept as written. */
export function parseVector(vector: string): { metrics: Record<string, string>; extra: string[] } {
  const metrics: Record<string, string> = {};
  const extra: string[] = [];
  for (const part of vector.trim().replace(/^CVSS:4\.0\/?/, "").split("/")) {
    const [k, v] = part.split(":");
    if (!k || !v) continue;
    if (BASE_KEYS.includes(k)) metrics[k] = v;
    else extra.push(`${k}:${v}`);
  }
  return { metrics, extra };
}

function vectorOf(metrics: Record<string, string>, extra: string[]): string | null {
  if (!BASE_KEYS.every((k) => metrics[k])) return null;
  return ["CVSS:4.0", ...BASE_KEYS.map((k) => `${k}:${metrics[k]}`), ...extra].join("/");
}

const errorOf = (e: unknown): FieldError | string => {
  if (e instanceof ApiError) {
    const d = e.data as Partial<FieldError> | undefined;
    if (d && typeof d.field === "string" && typeof d.message === "string") return { field: d.field, message: d.message };
    return e.message;
  }
  return "Could not record the finding.";
};

export function ManualFindingForm({ assetId }: { assetId: string }) {
  const id = useId();
  const [title, setTitle] = useState("");
  const [cwe, setCwe] = useState("");
  const [cweHits, setCweHits] = useState<CweEntry[]>([]);
  const [metrics, setMetrics] = useState<Record<string, string>>({});
  const [extra, setExtra] = useState<string[]>([]);
  const [paste, setPaste] = useState("");
  const [noCvss, setNoCvss] = useState(false);
  const [severity, setSeverity] = useState<Severity | "">("");
  const [score, setScore] = useState<CvssScore | null>(null);
  const [scoreError, setScoreError] = useState<string | null>(null);
  const [kind, setKind] = useState<"route" | "file">("route");
  const [routes, setRoutes] = useState<ProjectRoute[] | null>(null);
  const [picked, setPicked] = useState("");
  const [method, setMethod] = useState("GET");
  const [route, setRoute] = useState("");
  const [host, setHost] = useState("");
  const [path, setPath] = useState("");
  const [line, setLine] = useState("");
  const [steps, setSteps] = useState("");
  const [impact, setImpact] = useState("");
  const [recommendation, setRecommendation] = useState("");
  const [references, setReferences] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [done, setDone] = useState<{ recorded: ManualRecorded; uploaded: EvidenceFile[]; failed: string[] } | null>(null);
  const summaryRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    listRoutes(assetId).then((r) => setRoutes(r.routes), () => setRoutes([]));
  }, [assetId]);

  useEffect(() => {
    const q = cwe.trim();
    const t = setTimeout(() => searchCwe(q).then(setCweHits, () => setCweHits([])), 200);
    return () => clearTimeout(t);
  }, [cwe]);

  const vector = useMemo(() => vectorOf(metrics, extra), [metrics, extra]);
  useEffect(() => {
    setScore(null);
    setScoreError(null);
    if (!vector) return;
    const c = new AbortController();
    scoreCvss4(vector, c.signal).then(
      (s) => !c.signal.aborted && setScore(s),
      (e) => !c.signal.aborted && setScoreError(e instanceof ApiError ? e.message : "Could not score this vector."),
    );
    return () => c.abort();
  }, [vector]);

  const pickedRoute = routes?.find((r) => routeKey(r) === picked) ?? null;

  function validate(): Record<string, string> {
    const e: Record<string, string> = {};
    if (!title.trim()) e.title = "Give the finding a title.";
    if (!noCvss && !vector) e.cvss_vector = "Choose a value for every CVSS metric, or set a severity without CVSS.";
    if (!noCvss && vector && scoreError) e.cvss_vector = scoreError;
    if (noCvss && !severity) e.severity = "Choose a severity.";
    if (kind === "route") {
      if (picked === OTHER_ROUTE || !routes?.length) {
        if (!route.trim().startsWith("/")) e.route = "Type the route, starting with '/'.";
      } else if (!pickedRoute) e.route = "Pick a route, or choose “Another route”.";
    } else {
      if (!path.trim()) e.path = "Give the file's path within the project.";
      if (line && !/^\d+$/.test(line)) e.line = "The line is a number.";
    }
    const bad = references.split("\n").map((r) => r.trim()).filter((r) => r && !/^https?:\/\//.test(r));
    if (bad.length) e.references = "Each reference is a web link starting with https://.";
    return e;
  }

  async function submit(ev: React.FormEvent) {
    ev.preventDefault();
    setFormError(null);
    const e = validate();
    setErrors(e);
    if (Object.keys(e).length) {
      requestAnimationFrame(() => summaryRef.current?.focus());
      return;
    }
    const otherRoute = picked === OTHER_ROUTE || !routes?.length;
    const body: ManualFindingInput = {
      title: title.trim(),
      cwe: cwe.trim() || null,
      cvss_vector: noCvss ? null : vector,
      severity: noCvss ? (severity as Severity) : null,
      location_kind: kind,
      method: kind === "route" ? (otherRoute ? method : pickedRoute?.method || null) : null,
      route: kind === "route" ? (otherRoute ? route.trim() : pickedRoute?.route ?? null) : null,
      host: kind === "route" ? host.trim() || null : null,
      path: kind === "file" ? path.trim() : null,
      line: kind === "file" && line ? Number(line) : null,
      steps, impact, recommendation,
      references: references.split("\n").map((r) => r.trim()).filter(Boolean),
    };
    setSaving(true);
    try {
      const recorded = await recordManualFinding(assetId, body);
      const uploaded: EvidenceFile[] = [];
      const failed: string[] = [];
      for (const f of files) {
        try {
          uploaded.push(await uploadEvidence(recorded.manual.id, f));
        } catch (err) {
          failed.push(`${f.name}: ${err instanceof ApiError ? err.message : "upload failed"}`);
        }
      }
      setDone({ recorded, uploaded, failed });
    } catch (err) {
      const out = errorOf(err);
      if (typeof out === "string") setFormError(out);
      else {
        setErrors({ [out.field]: out.message });
        requestAnimationFrame(() => summaryRef.current?.focus());
      }
    } finally {
      setSaving(false);
    }
  }

  if (done) {
    const m = done.recorded.manual;
    return (
      <div className="ds-mf">
        <h1 className="ds-mf-title">Finding recorded</h1>
        <p role="status" className="ds-mf-done">
          {done.recorded.created ? "Recorded" : "Already recorded"}: <strong>{m.title}</strong> —{" "}
          {m.cvss_score !== null ? `${m.cvss_score} ${titleCase(m.severity)} (CVSS 4.0)` : titleCase(m.severity)}.
        </p>
        {m.related_issue_id && (
          <p>
            Also found by <strong>{m.related_source}</strong>: this finding now carries that issue’s taint
            path as evidence. <Link href={`/app/projects/${assetId}/issues/${m.related_issue_id}`}>See the automated issue</Link>
          </p>
        )}
        {done.uploaded.length > 0 && (
          <p>{done.uploaded.length} evidence file{done.uploaded.length === 1 ? "" : "s"} attached{done.uploaded.some((u) => u.encrypted) ? ", encrypted at rest" : ""}.</p>
        )}
        {done.failed.length > 0 && (
          <div role="alert" className="ds-mf-error"><p>Some evidence was not attached:</p><ul>{done.failed.map((f) => <li key={f}>{f}</li>)}</ul></div>
        )}
        <div className="ds-mf-actions">
          <Link className="ds-mf-link" href={`/app/projects/${assetId}/issues/${done.recorded.issue_id}`}>Open the issue</Link>
          <Button onClick={() => window.location.reload()}>Record another</Button>
        </div>
      </div>
    );
  }

  const errorList = Object.entries(errors);
  const fid = (name: string) => `${id}-${name}`;
  const err = (name: string) =>
    errors[name] ? <p id={`${fid(name)}-err`} className="ds-mf-field-error">{errors[name]}</p> : null;
  const described = (name: string, help?: boolean) =>
    [errors[name] ? `${fid(name)}-err` : "", help ? `${fid(name)}-help` : ""].filter(Boolean).join(" ") || undefined;

  return (
    <form className="ds-mf" onSubmit={submit} noValidate>
      <h1 className="ds-mf-title">Record a finding</h1>
      <p className="ds-mf-intro">
        Something a scanner did not find. It becomes an issue like any other — with severity, triage and
        tickets — and you can undo it from the project’s imports.
      </p>

      {errorList.length > 0 && (
        <div ref={summaryRef} tabIndex={-1} role="alert" className="ds-mf-summary" aria-labelledby={`${id}-sum`}>
          <h2 id={`${id}-sum`}>{errorList.length === 1 ? "One thing needs fixing" : `${errorList.length} things need fixing`}</h2>
          <ul>
            {errorList.map(([name, message]) => (
              <li key={name}><a href={`#${fid(name)}`}>{message}</a></li>
            ))}
          </ul>
        </div>
      )}
      {formError && <p role="alert" className="ds-mf-error">{formError}</p>}

      <div className="ds-mf-field">
        <label htmlFor={fid("title")}>Title</label>
        <input id={fid("title")} value={title} onChange={(e) => setTitle(e.target.value)} maxLength={300}
          aria-invalid={!!errors.title} aria-describedby={described("title")} required />
        {err("title")}
      </div>

      <div className="ds-mf-field">
        <label htmlFor={fid("cwe")}>Weakness (CWE)</label>
        <input id={fid("cwe")} value={cwe} onChange={(e) => setCwe(e.target.value)} list={`${fid("cwe")}-list`}
          placeholder="Search, or type a number like 639" aria-invalid={!!errors.cwe}
          aria-describedby={described("cwe", true)} autoComplete="off" />
        <datalist id={`${fid("cwe")}-list`}>
          {cweHits.map((c) => <option key={c.id} value={c.id}>{c.name ? `${c.id}: ${c.name}` : c.id}</option>)}
        </datalist>
        <p id={`${fid("cwe")}-help`} className="ds-mf-help">Optional. With a CWE, the finding can be matched to what scanners found on the same code.</p>
        {err("cwe")}
      </div>

      <fieldset className="ds-mf-cvss" aria-describedby={described("cvss_vector")}>
        <legend>Severity: CVSS 4.0</legend>
        {!noCvss && (
          <>
            {GROUPS.map((g) => (
              <fieldset key={g.legend} className="ds-mf-group">
                <legend>{g.legend}</legend>
                {g.metrics.map((m) => (
                  <fieldset key={m.key} className="ds-mf-metric">
                    <legend>{m.label} <abbr title={m.label}>({m.key})</abbr></legend>
                    <div className="ds-mf-options">
                      {m.values.map(([v, label]) => (
                        <label key={v} className="ds-mf-choice">
                          <input type="radio" name={`${fid(m.key)}`} value={v} checked={metrics[m.key] === v}
                            onChange={() => setMetrics((x) => ({ ...x, [m.key]: v }))}
                            id={m.key === "AV" && v === "N" ? fid("cvss_vector") : undefined} />
                          {label}
                        </label>
                      ))}
                    </div>
                  </fieldset>
                ))}
              </fieldset>
            ))}
            <div className="ds-mf-score" aria-live="polite">
              {score ? (
                <p><strong className="ds-mf-score-n">{score.score}</strong> {score.rating}<span className="ds-mf-vector"><code>{score.vector}</code></span></p>
              ) : vector && !scoreError ? (
                <p>Scoring…</p>
              ) : scoreError ? (
                <p className="ds-mf-field-error">{scoreError}</p>
              ) : (
                <p className="ds-mf-help">Choose a value for each metric to see the score.</p>
              )}
            </div>
            <div className="ds-mf-field">
              <label htmlFor={fid("paste")}>Or paste a vector</label>
              <div className="ds-mf-inline">
                <input id={fid("paste")} value={paste} onChange={(e) => setPaste(e.target.value)} placeholder="CVSS:4.0/AV:N/AC:L/…" spellCheck={false} />
                <Button type="button" onClick={() => { const p = parseVector(paste); setMetrics(p.metrics); setExtra(p.extra); }} disabled={!paste.trim()}>
                  Use vector
                </Button>
              </div>
            </div>
          </>
        )}
        {err("cvss_vector")}
        <label className="ds-mf-choice ds-mf-nocvss">
          <input type="checkbox" checked={noCvss} onChange={(e) => setNoCvss(e.target.checked)} />
          Set a severity without CVSS
        </label>
        {noCvss && (
          <div className="ds-mf-field">
            <label htmlFor={fid("severity")}>Severity</label>
            <select id={fid("severity")} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}
              aria-invalid={!!errors.severity} aria-describedby={described("severity")}>
              <option value="">Choose…</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
            </select>
            {err("severity")}
          </div>
        )}
      </fieldset>

      <fieldset className="ds-mf-where">
        <legend>Where is it?</legend>
        <label className="ds-mf-choice"><input type="radio" name={fid("kind")} checked={kind === "route"} onChange={() => setKind("route")} /> A route</label>
        <label className="ds-mf-choice"><input type="radio" name={fid("kind")} checked={kind === "file"} onChange={() => setKind("file")} /> A file</label>

        {kind === "route" && (
          <>
            {routes && routes.length > 0 && (
              <div className="ds-mf-field">
                <label htmlFor={fid("route")}>Route</label>
                <select id={fid("route")} value={picked} onChange={(e) => setPicked(e.target.value)}
                  aria-invalid={!!errors.route} aria-describedby={described("route", true)}>
                  <option value="">Choose a route…</option>
                  {routes.map((r) => (
                    <option key={routeKey(r)} value={routeKey(r)}>
                      {(r.method || "ANY").padEnd(6)} {r.route} — {r.path}:{r.line}
                    </option>
                  ))}
                  <option value={OTHER_ROUTE}>Another route…</option>
                </select>
                <p id={`${fid("route")}-help`} className="ds-mf-help">
                  From the latest scan’s code. A route here links the finding to its handler’s code, and to
                  anything scanners found there.
                </p>
                {picked !== OTHER_ROUTE && err("route")}
              </div>
            )}
            {(picked === OTHER_ROUTE || (routes !== null && routes.length === 0)) && (
              <div className="ds-mf-inline-fields">
                <div className="ds-mf-field">
                  <label htmlFor={fid("method")}>Method</label>
                  <select id={fid("method")} value={method} onChange={(e) => setMethod(e.target.value)}>
                    {METHODS.map((m) => <option key={m}>{m}</option>)}
                  </select>
                </div>
                <div className="ds-mf-field ds-mf-grow">
                  <label htmlFor={routes?.length ? fid("route-other") : fid("route")}>Route path</label>
                  <input id={routes?.length ? fid("route-other") : fid("route")} value={route} onChange={(e) => setRoute(e.target.value)}
                    placeholder="/v2/orders/{id}" aria-invalid={!!errors.route} aria-describedby={described("route")} spellCheck={false} />
                  {err("route")}
                </div>
              </div>
            )}
            <div className="ds-mf-field">
              <label htmlFor={fid("host")}>Target (optional)</label>
              <input id={fid("host")} value={host} onChange={(e) => setHost(e.target.value)} placeholder="https://api.example.com" spellCheck={false} />
            </div>
          </>
        )}

        {kind === "file" && (
          <div className="ds-mf-inline-fields">
            <div className="ds-mf-field ds-mf-grow">
              <label htmlFor={fid("path")}>File</label>
              <input id={fid("path")} value={path} onChange={(e) => setPath(e.target.value)} placeholder="app/orders.py"
                aria-invalid={!!errors.path} aria-describedby={described("path")} spellCheck={false} />
              {err("path")}
            </div>
            <div className="ds-mf-field">
              <label htmlFor={fid("line")}>Line</label>
              <input id={fid("line")} value={line} onChange={(e) => setLine(e.target.value)} inputMode="numeric"
                aria-invalid={!!errors.line} aria-describedby={described("line")} />
              {err("line")}
            </div>
          </div>
        )}
      </fieldset>

      {([["steps", "Steps to reproduce", steps, setSteps], ["impact", "Impact", impact, setImpact],
        ["recommendation", "Recommendation", recommendation, setRecommendation]] as const).map(([name, label, value, set]) => (
        <div key={name} className="ds-mf-field">
          <label htmlFor={fid(name)}>{label}</label>
          <textarea id={fid(name)} value={value} onChange={(e) => set(e.target.value)} rows={name === "steps" ? 6 : 3}
            aria-invalid={!!errors[name]} aria-describedby={described(name)} />
          {err(name)}
        </div>
      ))}

      <div className="ds-mf-field">
        <label htmlFor={fid("references")}>References</label>
        <textarea id={fid("references")} value={references} onChange={(e) => setReferences(e.target.value)} rows={2}
          placeholder="One link per line" aria-invalid={!!errors.references} aria-describedby={described("references")} />
        {err("references")}
      </div>

      <div className="ds-mf-field">
        <label htmlFor={fid("evidence")}>Evidence</label>
        <input id={fid("evidence")} type="file" multiple aria-describedby={`${fid("evidence")}-help`}
          onChange={(e) => setFiles(Array.from(e.target.files ?? []))} />
        <p id={`${fid("evidence")}-help`} className="ds-mf-help">
          Screenshots, HTTP captures, up to 10 MB each. Stored encrypted and only ever downloaded, never shown in the page.
        </p>
        {files.length > 0 && <ul className="ds-mf-files">{files.map((f) => <li key={f.name}>{f.name}</li>)}</ul>}
      </div>

      <div className="ds-mf-actions">
        <Button type="submit" variant="primary" disabled={saving}>{saving ? "Recording…" : "Record finding"}</Button>
        <Link href={`/app/projects/${assetId}`}>Cancel</Link>
      </div>
    </form>
  );
}
