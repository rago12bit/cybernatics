"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useMemo, useState } from "react";
import {
  ApiError, createConnector, getConnector, listAssets, listConnectorKinds, listConnectors,
  runConnector, updateConnector,
} from "@/lib/api";
import type { AssetSummary, ConnectorKind, ConnectorStatus, ConnectorView, FieldError } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { Loading } from "@/design-system/primitives/Loading";
import "./connectors-screen.css";
import { formatDateTime, projectName } from "@/lib/format";

/** Connector health (plan §55.7, §42.5, ADR-0045): every connector's last success, what it fetched,
 * and a warning when it connects but fetches nothing -- the quiet failure. The page opens with a
 * sentence saying which ones need attention (principle 8), and status is always a word and a
 * shape, never colour alone. Adding a connector says exactly what access its credential needs, and
 * a credential, once saved, is never shown again. */

const STATUS: Record<ConnectorStatus, { word: string; mark: string }> = {
  ok: { word: "Healthy", mark: "●" },
  empty: { word: "Fetched nothing", mark: "◐" },
  failing: { word: "Failing", mark: "▲" },
  never_run: { word: "Not run yet", mark: "○" },
  disabled: { word: "Off", mark: "–" },
};
const FIELD_LABEL: Record<string, string> = {
  repo: "Repository (owner/name)",
  installation_id: "GitHub App installation ID",
  base_url: "Base URL",
  project: "Project path (group/name)",
  product_id: "DefectDojo product ID",
  engagement_id: "DefectDojo engagement ID",
  product_name: "DefectDojo product",
  engagement_name: "DefectDojo engagement",
  product_type_name: "Product type, for a new product",
};
const INTERVALS: [number, string][] = [[60, "Every hour"], [360, "Every 6 hours"], [1440, "Every day"]];

function ago(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} minutes ago`;
  if (s < 129600) return `${Math.round(s / 3600)} hours ago`;
  return `${Math.round(s / 86400)} days ago`;
}

export function verdict(list: ConnectorView[]): string {
  if (list.length === 0) return "No connectors yet.";
  const bad = list.filter((c) => c.status === "failing" || c.status === "empty");
  if (bad.length === 0) {
    const on = list.filter((c) => c.enabled).length;
    return on === list.length ? `All ${list.length} connector${list.length === 1 ? " is" : "s are"} healthy.`
      : `${on} of ${list.length} connectors are on, and healthy.`;
  }
  const parts = bad.map((c) => `${c.name} ${c.status === "failing" ? "is failing" : "connected but fetched nothing"}`);
  return `${bad.length} of ${list.length} connector${list.length === 1 ? "" : "s"} need${bad.length === 1 ? "s" : ""} attention: ${parts.join("; ")}.`;
}

export function ConnectorsScreen() {
  const [list, setList] = useState<ConnectorView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const load = useCallback(() => {
    listConnectors().then(setList, (e) => setError(e instanceof ApiError ? e.message : "Could not load connectors."));
  }, []);
  useEffect(load, [load]);

  async function act(c: ConnectorView, what: "run" | "toggle") {
    setBusy(c.id);
    setError(null);
    try {
      if (what === "run") await runConnector(c.id);
      else await updateConnector(c.id, { enabled: !c.enabled });
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That did not work.");
    } finally {
      setBusy(null);
    }
  }

  if (!list) return error ? <p role="alert" className="ds-conn-error">{error}</p> : <Loading />;

  return (
    <div className="ds-conn">
      <h1 className="ds-conn-title">Connectors</h1>
      <p className="ds-conn-verdict" role="status">{verdict(list)}</p>
      {error && <p role="alert" className="ds-conn-error">{error}</p>}

      {list.length > 0 && (
        <table className="ds-conn-table">
          <caption className="ds-conn-sr">Connectors and their health</caption>
          <thead>
            <tr>
              <th scope="col">Connector</th>
              <th scope="col">Project</th>
              <th scope="col">Health</th>
              <th scope="col">Last success</th>
              <th scope="col">Fetched</th>
              <th scope="col"><span className="ds-conn-sr">Actions</span></th>
            </tr>
          </thead>
          {list.map((c) => (
            <tbody key={c.id}>
              <tr className={c.warning ? "ds-conn-row-warn" : undefined}>
                <th scope="row">
                  {c.name}
                  <span className="ds-conn-sub">
                    {c.kind_label}{c.direction === "push" ? " · sends findings out" : ""}
                    {c.credential_store === "database" ? " · credential not encrypted" : ""}
                  </span>
                </th>
                <td><Link href={`/app/projects/${c.project_id}`} title={c.project}>{projectName(c.project)}</Link></td>
                <td>
                  <span className={`ds-conn-status ds-conn-${c.status}`}>
                    <span aria-hidden="true">{STATUS[c.status].mark}</span> {STATUS[c.status].word}
                  </span>
                </td>
                <td>{ago(c.last_success_at)}</td>
                <td>{c.last_items ?? "—"}</td>
                <td className="ds-conn-actions">
                  <Button onClick={() => act(c, "run")} disabled={!c.enabled || busy === c.id}>
                    Run now<span className="ds-conn-sr"> {c.name}</span>
                  </Button>
                  <Button onClick={() => act(c, "toggle")} disabled={busy === c.id}>
                    {c.enabled ? "Turn off" : "Turn on"}<span className="ds-conn-sr"> {c.name}</span>
                  </Button>
                  <button type="button" className="ds-conn-link" aria-expanded={open === c.id}
                    onClick={() => setOpen(open === c.id ? null : c.id)}>
                    {open === c.id ? "Hide runs" : "Runs"}<span className="ds-conn-sr"> of {c.name}</span>
                  </button>
                </td>
              </tr>
              {c.warning && (
                <tr className="ds-conn-warning-row">
                  <td colSpan={6}><p className="ds-conn-warning"><strong>{c.status === "failing" ? "Failing:" : "Check:"}</strong> {c.warning}</p></td>
                </tr>
              )}
              {open === c.id && (
                <tr><td colSpan={6}><Runs id={c.id} /></td></tr>
              )}
            </tbody>
          ))}
        </table>
      )}

      {adding ? (
        <AddConnector onDone={(created) => { setAdding(false); if (created) load(); }} />
      ) : (
        <Button variant="primary" onClick={() => setAdding(true)}>Add a connector</Button>
      )}
    </div>
  );
}

function Runs({ id }: { id: string }) {
  const [c, setC] = useState<ConnectorView | null>(null);
  useEffect(() => { getConnector(id).then(setC, () => setC(null)); }, [id]);
  if (!c) return <p role="status">Loading runs…</p>;
  if (c.runs.length === 0) return <p>No runs yet. Next run: {c.next_run_at ? formatDateTime(c.next_run_at) : "when it is turned on"}.</p>;
  return (
    <table className="ds-conn-runs">
      <caption>Recent runs of {c.name}</caption>
      <thead><tr><th scope="col">Started</th><th scope="col">Outcome</th><th scope="col">Items</th><th scope="col">What changed</th></tr></thead>
      <tbody>
        {c.runs.map((r) => (
          <tr key={r.id}>
            <td><time dateTime={r.started_at}>{formatDateTime(r.started_at)}</time></td>
            <td>{r.outcome === "ok" ? "Done" : r.outcome === "empty" ? "Fetched nothing" : "Failed"}</td>
            <td>{r.items}</td>
            <td>
              {r.error ?? describe(r.counts)}
              {r.warnings.map((w) => <span key={w} className="ds-conn-sub">{w}</span>)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function describe(counts: Record<string, unknown>): string {
  if ("exported" in counts) return `Sent ${String(counts.exported)} open issue(s)`;
  if (counts.duplicate) return "Nothing changed since the last run";
  const n = (k: string) => Number(counts[k] ?? 0);
  if (!("new" in counts)) return "Nothing was applied";
  return `${n("new")} new, ${n("reopened")} reopened, ${n("closed")} closed`;
}

function AddConnector({ onDone }: { onDone: (created: boolean) => void }) {
  const id = useId();
  const [kinds, setKinds] = useState<ConnectorKind[]>([]);
  const [projects, setProjects] = useState<AssetSummary[]>([]);
  const [kind, setKind] = useState("");
  const [project, setProject] = useState("");
  const [name, setName] = useState("");
  const [config, setConfig] = useState<Record<string, string>>({});
  const [credential, setCredential] = useState("");
  const [interval, setIntervalMinutes] = useState(360);
  const [closeOnEmpty, setCloseOnEmpty] = useState(false);
  const [exportTarget, setExportTarget] = useState<"engagement" | "create">("engagement");
  const [fieldError, setFieldError] = useState<FieldError | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    listConnectorKinds().then(setKinds, () => setKinds([]));
    listAssets().then(setProjects, () => setProjects([]));
  }, []);
  const spec = useMemo(() => kinds.find((k) => k.name === kind), [kinds, kind]);
  const fields = useMemo(() => {
    if (!spec) return [];
    if (spec.name !== "defectdojo_export") return spec.fields;
    return exportTarget === "engagement" ? ["base_url", "engagement_id"] : ["base_url", "product_name", "engagement_name", "product_type_name"];
  }, [spec, exportTarget]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setFieldError(null);
    setError(null);
    if (!project) return setFieldError({ field: "project_id", message: "Choose a project." });
    if (!spec) return setFieldError({ field: "kind", message: "Choose what to connect." });
    setSaving(true);
    try {
      await createConnector({
        project_id: project, kind, name: name.trim() || spec.label, interval_minutes: interval,
        close_on_empty: closeOnEmpty, credential: spec.needs_credential ? credential : undefined,
        config: Object.fromEntries(fields.map((f) => [f, (config[f] ?? "").trim()])),
      });
      onDone(true);
    } catch (err) {
      const d = err instanceof ApiError ? (err.data as Partial<FieldError> | undefined) : undefined;
      if (d?.field && d.message) setFieldError({ field: d.field, message: d.message });
      else setError(err instanceof ApiError ? err.message : "Could not add the connector.");
    } finally {
      setSaving(false);
    }
  }

  const fid = (f: string) => `${id}-${f}`;
  const errFor = (f: string) =>
    fieldError?.field === f ? <p id={`${fid(f)}-err`} className="ds-conn-field-error">{fieldError.message}</p> : null;
  const aria = (f: string) => ({
    "aria-invalid": fieldError?.field === f || undefined,
    "aria-describedby": fieldError?.field === f ? `${fid(f)}-err` : undefined,
  });

  return (
    <form className="ds-conn-add" onSubmit={submit} noValidate aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`}>Add a connector</h2>
      {error && <p role="alert" className="ds-conn-error">{error}</p>}
      {fieldError && <p role="alert" className="ds-conn-sr">{fieldError.message}</p>}
      <div className="ds-conn-field">
        <label htmlFor={fid("project_id")}>Project</label>
        <select id={fid("project_id")} value={project} onChange={(e) => setProject(e.target.value)} {...aria("project_id")}>
          <option value="">Choose…</option>
          {projects.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
        {errFor("project_id")}
      </div>
      <div className="ds-conn-field">
        <label htmlFor={fid("kind")}>Connect to</label>
        <select id={fid("kind")} value={kind} onChange={(e) => { setKind(e.target.value); setFieldError(null); }} {...aria("kind")}>
          <option value="">Choose…</option>
          {kinds.map((k) => <option key={k.name} value={k.name}>{k.label}</option>)}
        </select>
        {spec && <p className="ds-conn-help"><strong>Access it needs:</strong> {spec.permissions}</p>}
        {errFor("kind")}
      </div>
      {spec?.name === "defectdojo_export" && (
        <fieldset className="ds-conn-field">
          <legend>Send to</legend>
          <label className="ds-conn-choice"><input type="radio" checked={exportTarget === "engagement"} onChange={() => setExportTarget("engagement")} /> An existing engagement</label>
          <label className="ds-conn-choice"><input type="radio" checked={exportTarget === "create"} onChange={() => setExportTarget("create")} /> A product and engagement, created if needed</label>
        </fieldset>
      )}
      {fields.map((f) => (
        <div key={f} className="ds-conn-field">
          <label htmlFor={fid(f)}>{FIELD_LABEL[f] ?? f.replace(/_/g, " ")}</label>
          <input id={fid(f)} value={config[f] ?? ""} onChange={(e) => setConfig((c) => ({ ...c, [f]: e.target.value }))}
            spellCheck={false} {...aria(f)} placeholder={f === "base_url" ? "https://…" : f === "product_type_name" ? "Bulwark" : undefined} />
          {errFor(f)}
        </div>
      ))}
      {spec?.needs_credential && (
        <div className="ds-conn-field">
          <label htmlFor={fid("credential")}>Credential</label>
          <input id={fid("credential")} type="password" autoComplete="off" value={credential}
            onChange={(e) => setCredential(e.target.value)} {...aria("credential")} />
          <p className="ds-conn-help">Stored in OpenBao when it is set up, and never shown again.</p>
          {errFor("credential")}
        </div>
      )}
      {spec && (
        <>
          <div className="ds-conn-field">
            <label htmlFor={fid("name")}>Name</label>
            <input id={fid("name")} value={name} onChange={(e) => setName(e.target.value)} placeholder={spec.label} />
          </div>
          <div className="ds-conn-field">
            <label htmlFor={fid("interval")}>How often</label>
            <select id={fid("interval")} value={interval} onChange={(e) => setIntervalMinutes(Number(e.target.value))}>
              {INTERVALS.map(([m, l]) => <option key={m} value={m}>{l}</option>)}
            </select>
          </div>
          {spec.direction === "pull" && (
            <label className="ds-conn-choice ds-conn-field">
              <input type="checkbox" checked={closeOnEmpty} onChange={(e) => setCloseOnEmpty(e.target.checked)} />
              Close issues when a pull comes back empty. Off by default: an empty pull can mean the credential lost access.
            </label>
          )}
        </>
      )}
      <div className="ds-conn-actions">
        <Button type="submit" variant="primary" disabled={saving}>{saving ? "Adding…" : "Add connector"}</Button>
        <Button type="button" onClick={() => onDone(false)}>Cancel</Button>
      </div>
    </form>
  );
}
