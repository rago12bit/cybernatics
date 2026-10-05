"use client";

import Link from "next/link";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { ApiError, analyzeSample, previewMapping, saveMapping } from "@/lib/api";
import type {
  AnalyzeResult, MappingCategory, MappingField, MappingPreview, MappingSpec, SampleCandidate,
  SavedMapping,
} from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { SeverityBadge } from "@/design-system/severity";
import type { Severity as DsSeverity } from "@/design-system/severity";
import "./mapper-screen.css";

/** The universal mapper (plan §42.4, ADR-0043): map a report format Bulwark has no parser for.
 *
 * 1. Upload a sample. Its shape is described on the server (inside the parser sandbox) and a draft
 *    mapping comes back -- the model's, checked against the sample, or one made by matching names.
 * 2. The person edits every field, watching a live preview of the issues the mapping produces.
 * 3. Saving makes it a parser: deterministic, and imported with no model involved.
 *
 * Nothing the screen shows is computed here: the preview's counts and rows are the server's, from
 * the same parser an import would run. */

const FIELD_LABEL: Record<MappingField, string> = {
  title: "Title",
  severity: "Severity",
  description: "Description",
  path: "File path",
  line: "Line",
  rule: "Rule or check ID",
  cwe: "CWE",
  cve: "CVE",
  url: "URL tested",
  package: "Package",
  version: "Package version",
  ecosystem: "Ecosystem",
  recommendation: "Recommendation",
  references: "References",
};
const FIELD_HELP: Partial<Record<MappingField, string>> = {
  title: "Required. What each issue is called.",
  rule: "The tool's own stable ID for the kind of problem; used to match issues across reports.",
  url: "For web findings: becomes the host and route.",
  package: "For dependency findings.",
};
const CATEGORY_LABEL: Record<MappingCategory, string> = {
  sast: "Code (SAST)",
  sca: "Dependencies (SCA)",
  secrets: "Secrets",
  iac: "Infrastructure as code",
  container: "Container",
  dast: "Web (DAST)",
};
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const COMMON_WORDS = new Set(["critical", "crit", "high", "important", "medium", "moderate", "med", "low",
  "minor", "info", "informational", "information", "note", "none"]);
const PREVIEW_DELAY_MS = 400;

const errorText = (e: unknown, fallback: string) => (e instanceof ApiError ? e.message : fallback);
const draftLabel = (by: string) =>
  by.startsWith("model:") ? `drafted by a model (${by.slice(6)})` : "drafted by matching field names";

export function MapperScreen({ assetId }: { assetId: string }) {
  const [file, setFile] = useState<File | null>(null);
  const [useModel, setUseModel] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [spec, setSpec] = useState<MappingSpec | null>(null);
  const [name, setName] = useState("");
  const [saved, setSaved] = useState<SavedMapping | null>(null);

  async function describe(f: File) {
    setBusy(true);
    setError(null);
    setResult(null);
    setSpec(null);
    setSaved(null);
    try {
      const r = await analyzeSample(f, { useModel });
      setResult(r);
      if (r.analysis.error) setError(r.analysis.error);
      if (r.proposal) {
        setSpec({ ...r.proposal.spec, severity_map: r.proposal.spec.severity_map ?? {} });
        setName((n) => n || r.suggested_source);
      }
    } catch (e) {
      setError(errorText(e, "Could not read the sample."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="ds-map">
      <h1 className="ds-map-title">Map a new report format</h1>
      <p className="ds-map-intro">
        For a JSON, CSV or XML report Bulwark has no parser for. Upload a sample, check where each
        field comes from against a live preview, and save it. A saved mapping reads reports the same
        way every time; no AI is involved when you import with it.{" "}
        <Link href={`/app/projects/${assetId}/import`}>Back to import</Link>
      </p>

      {!saved && (
        <section aria-labelledby="map-sample-h" className="ds-map-section">
          <h2 id="map-sample-h" className="ds-map-h">1. Sample</h2>
          <label className="ds-map-label" htmlFor="map-file">A sample of the report (at most 2 MB)</label>
          <input
            id="map-file"
            type="file"
            accept=".json,.csv,.xml,.txt,application/json,text/csv,text/xml,application/xml"
            onChange={(e) => {
              const f = e.target.files?.[0] ?? null;
              setFile(f);
              if (f) void describe(f);
            }}
          />
          <label className="ds-map-check">
            <input type="checkbox" checked={useModel} onChange={(e) => setUseModel(e.target.checked)} />
            Ask the AI model for the first draft (it is shown field names and short examples, never the file)
          </label>
          {file && result && (
            <Button onClick={() => describe(file)} disabled={busy}>Draft again</Button>
          )}
          {busy && <p role="status">Reading the sample…</p>}
          {error && <p role="alert" className="ds-map-error">{error}</p>}
        </section>
      )}

      {result && spec && file && !saved && (
        <MappingEditor
          assetId={assetId}
          file={file}
          result={result}
          spec={spec}
          onSpec={setSpec}
          name={name}
          onName={setName}
          onSaved={setSaved}
        />
      )}

      {saved && (
        <section aria-labelledby="map-saved-h" className="ds-map-section">
          <h2 id="map-saved-h" className="ds-map-h">Saved</h2>
          <p role="status" className="ds-map-done">
            Saved <strong>{saved.name}</strong> as version {saved.version}. Choose it as the format when
            you import a report of this kind.
          </p>
          <p>
            Parser name for the API: <code>{saved.parser}</code>
          </p>
          <div className="ds-map-actions">
            <Link className="ds-map-button" href={`/app/projects/${assetId}/import`}>Import a report</Link>
            <Button onClick={() => { setSaved(null); setResult(null); setSpec(null); setFile(null); setName(""); }}>
              Map another format
            </Button>
          </div>
        </section>
      )}
    </div>
  );
}

function MappingEditor(props: {
  assetId: string;
  file: File;
  result: AnalyzeResult;
  spec: MappingSpec;
  onSpec: (s: MappingSpec) => void;
  name: string;
  onName: (n: string) => void;
  onSaved: (m: SavedMapping) => void;
}) {
  const { file, result, spec, onSpec } = props;
  const id = useId();
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const candidates = result.analysis.candidates;
  const candidate: SampleCandidate | undefined =
    candidates.find((c) => c.records === spec.records) ?? candidates[0];
  const isCsv = spec.format === "csv";

  const set = (patch: Partial<MappingSpec>) => onSpec({ ...spec, ...patch });
  const setField = (field: MappingField, path: string) => {
    const fields = { ...spec.fields };
    if (path.trim()) fields[field] = path;
    else delete fields[field];
    set({ fields });
  };

  const severityValues = useMemo(() => {
    const path = spec.fields.severity;
    const f = candidate?.fields.find((x) => x.path === path);
    return f ? [...new Set(f.examples.map((e) => e.trim().toLowerCase()).filter(Boolean))] : [];
  }, [candidate, spec.fields.severity]);

  const preview = usePreview(file, spec);

  async function save() {
    setSaving(true);
    setSaveError(null);
    try {
      const m = await saveMapping({
        name: props.name.trim(),
        spec,
        proposed_by: result.proposal?.proposed_by ?? null,
        sample_digest: result.sample_digest,
      });
      props.onSaved(m);
    } catch (e) {
      setSaveError(errorText(e, "Could not save the mapping."));
    } finally {
      setSaving(false);
    }
  }

  const canSave = !!props.name.trim() && !!spec.fields.title && !preview.error && !!preview.data && !preview.data.error;

  return (
    <>
      <section aria-labelledby={`${id}-draft`} className="ds-map-section">
        <h2 id={`${id}-draft`} className="ds-map-h">2. Fields</h2>
        {result.proposal && (
          <div className="ds-map-draft" role="note">
            <p>
              <strong>Draft — review every field before saving.</strong> This mapping was{" "}
              {draftLabel(result.proposal.proposed_by)}.
              {result.proposal.proposed_by.startsWith("model:") && (
                <span className="ds-map-ai"> AI suggestion</span>
              )}
            </p>
            {result.proposal.notes.length > 0 && (
              <ul>{result.proposal.notes.map((n) => <li key={n}>{n}</li>)}</ul>
            )}
          </div>
        )}

        <div className="ds-map-grid">
          <label htmlFor={`${id}-name`}>Mapping name</label>
          <input id={`${id}-name`} value={props.name} onChange={(e) => props.onName(e.target.value)} required
            aria-describedby={`${id}-name-help`} />
          <span id={`${id}-name-help`} className="ds-map-help">What people choose on the import screen.</span>

          <label htmlFor={`${id}-source`}>Tool name</label>
          <input id={`${id}-source`} value={spec.source} onChange={(e) => set({ source: e.target.value.toLowerCase() })}
            aria-describedby={`${id}-source-help`} />
          <span id={`${id}-source-help`} className="ds-map-help">
            Shown as “reported by”; lower-case letters, digits, “.”, “_” or “-”.
          </span>

          {!isCsv && (
            <>
              <label htmlFor={`${id}-records`}>Where the findings are</label>
              <select id={`${id}-records`} value={spec.records ?? ""} onChange={(e) => set({ records: e.target.value })}>
                {candidates.map((c) => (
                  <option key={c.records ?? ""} value={c.records ?? ""}>
                    {c.records} ({c.count} in the sample)
                  </option>
                ))}
              </select>
              <span className="ds-map-help">Each item there becomes one issue.</span>
            </>
          )}

          <label htmlFor={`${id}-category`}>Kind of finding</label>
          <select id={`${id}-category`} value={spec.category} onChange={(e) => set({ category: e.target.value as MappingCategory })}>
            {(Object.keys(CATEGORY_LABEL) as MappingCategory[]).map((c) => (
              <option key={c} value={c}>{CATEGORY_LABEL[c]}</option>
            ))}
          </select>
          <span className="ds-map-help" />
        </div>

        <datalist id={`${id}-paths`}>
          {candidate?.fields.map((f) => <option key={f.path} value={f.path} />)}
        </datalist>
        <table className="ds-map-fields">
          <caption>Where each field comes from</caption>
          <colgroup>
            <col className="ds-map-col-field" />
            <col className="ds-map-col-path" />
            <col />
          </colgroup>
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">{isCsv ? "Column" : "Path"}</th>
              <th scope="col">Examples from the sample</th>
            </tr>
          </thead>
          <tbody>
            {result.fields.map((field) => {
              const path = spec.fields[field] ?? "";
              const examples = candidate?.fields.find((f) => f.path === path)?.examples ?? [];
              const inputId = `${id}-f-${field}`;
              return (
                <tr key={field}>
                  <th scope="row">
                    <label htmlFor={inputId}>{FIELD_LABEL[field]}{field === "title" && " (required)"}</label>
                    {FIELD_HELP[field] && <span className="ds-map-help">{FIELD_HELP[field]}</span>}
                  </th>
                  <td>
                    <input
                      id={inputId}
                      list={`${id}-paths`}
                      value={path}
                      placeholder="not mapped"
                      onChange={(e) => setField(field, e.target.value)}
                      spellCheck={false}
                    />
                  </td>
                  <td className="ds-map-examples">
                    {examples.length ? (
                      <ul aria-label={`Examples of ${FIELD_LABEL[field]}`}>
                        {examples.map((e) => <li key={e}><code title={e}>{e}</code></li>)}
                      </ul>
                    ) : (
                      <span className="ds-map-help">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {severityValues.length > 0 && (
          <fieldset className="ds-map-sevmap">
            <legend>What the tool’s severities mean</legend>
            {severityValues.map((word) => {
              const sid = `${id}-sev-${word}`;
              const common = COMMON_WORDS.has(word);
              return (
                <div key={word} className="ds-map-sevrow">
                  <label htmlFor={sid}><code>{word}</code></label>
                  <select
                    id={sid}
                    value={spec.severity_map[word] ?? ""}
                    onChange={(e) => {
                      const m = { ...spec.severity_map };
                      if (e.target.value) m[word] = e.target.value;
                      else delete m[word];
                      set({ severity_map: m });
                    }}
                  >
                    <option value="">{common ? "Understood as is" : "Not mapped (imports as Info)"}</option>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{s[0] + s.slice(1).toLowerCase()}</option>)}
                  </select>
                </div>
              );
            })}
          </fieldset>
        )}
      </section>

      <section aria-labelledby={`${id}-preview`} className="ds-map-section">
        <h2 id={`${id}-preview`} className="ds-map-h">3. Preview</h2>
        <PreviewPanel state={preview} />
      </section>

      <section aria-labelledby={`${id}-save`} className="ds-map-section">
        <h2 id={`${id}-save`} className="ds-map-h">4. Save</h2>
        <p>Saving adds a new version if a mapping with this name exists; earlier versions are kept.</p>
        {saveError && <p role="alert" className="ds-map-error">{saveError}</p>}
        <Button variant="primary" onClick={save} disabled={!canSave || saving}>
          {saving ? "Saving…" : "Save mapping"}
        </Button>
        {!canSave && !saving && (
          <p className="ds-map-help">
            {!props.name.trim() ? "Give the mapping a name. " : ""}
            {!spec.fields.title ? "Map the title field. " : ""}
            {preview.error || preview.data?.error ? "Fix the problem shown in the preview." : ""}
          </p>
        )}
      </section>
    </>
  );
}

type PreviewState = { loading: boolean; data: MappingPreview | null; error: string | null };

/** Re-run the preview on the server shortly after the mapping stops changing. */
function usePreview(file: File, spec: MappingSpec): PreviewState {
  const [state, setState] = useState<PreviewState>({ loading: true, data: null, error: null });
  const key = JSON.stringify(spec);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => {
    setState((s) => ({ ...s, loading: true }));
    const timer = setTimeout(() => {
      controller.current?.abort();
      const c = new AbortController();
      controller.current = c;
      previewMapping(file, JSON.parse(key) as MappingSpec, c.signal).then(
        (data) => !c.signal.aborted && setState({ loading: false, data, error: null }),
        (e) => !c.signal.aborted && setState({ loading: false, data: null, error: errorText(e, "Could not preview the mapping.") }),
      );
    }, PREVIEW_DELAY_MS);
    return () => clearTimeout(timer);
  }, [file, key]);
  useEffect(() => () => controller.current?.abort(), []);
  return state;
}

function PreviewPanel({ state }: { state: PreviewState }) {
  const { loading, data, error } = state;
  if (error) return <p role="alert" className="ds-map-error">{error}</p>;
  if (!data) return <p role="status">Previewing…</p>;
  return (
    <div aria-busy={loading}>
      {data.error ? (
        <p role="alert" className="ds-map-error">The sample could not be read with this mapping: {data.error}</p>
      ) : (
        <p role="status" className="ds-map-total">
          This mapping makes <strong>{data.total}</strong> issue{data.total === 1 ? "" : "s"} from the sample
          {data.total > 0 && (
            <>
              :{" "}
              {SEVERITIES.filter((s) => data.by_severity[s]).map((s) => `${data.by_severity[s]} ${s.toLowerCase()}`).join(", ")}
            </>
          )}
          .{loading && " Updating…"}
        </p>
      )}
      {data.warnings.length > 0 && (
        <ul className="ds-map-warnings">{data.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
      )}
      {data.issues.length > 0 && (
        <table className="ds-map-preview">
          <caption>
            {data.total > data.issues.length ? `The first ${data.issues.length} of ${data.total}` : "Issues"}
          </caption>
          <thead>
            <tr>
              <th scope="col">Title</th>
              <th scope="col">Severity</th>
              <th scope="col">Where</th>
              <th scope="col">CWE</th>
              <th scope="col">Rule</th>
            </tr>
          </thead>
          <tbody>
            {data.issues.map((i, n) => (
              <tr key={`${n}-${i.title}`}>
                <td>{i.title}</td>
                <td>
                  <SeverityBadge severity={i.severity.toLowerCase() as DsSeverity} />
                  {i.native_severity && <span className="ds-map-help"> (tool: {i.native_severity})</span>}
                </td>
                <td><code>{i.location}</code></td>
                <td>{i.cwe.join(", ") || "—"}</td>
                <td>{i.rule ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
