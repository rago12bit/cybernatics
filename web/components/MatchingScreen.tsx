"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import { ApiError, applyDedup, getDedup, getDedupHistory, previewDedup } from "@/lib/api";
import type {
  DedupHistoryEntry, DedupOverview, DedupPreview, DedupSource, DedupStrategyName,
} from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./matching-screen.css";
import { formatDateTime } from "@/lib/format";

/** How each source's findings are matched into Issues (plan §42.3, §55.1's "Matching" row, ADR-0042).
 *
 * Changing it rewrites Issue identity, so a change is never one click: the person picks a strategy,
 * the server runs a dry run ("would merge 212 issues into 97 and split none"), and only then can
 * the change be applied -- exactly the previewed one, or the server refuses it as stale. The screen
 * never shows a number it computed itself; every count is the preview's. */

const LABEL: Record<DedupStrategyName, string> = {
  fingerprint_v2: "Fingerprint (the default)",
  tool_id: "Tool ID",
  hash_fields: "Hash of chosen fields",
  tool_id_or_hash: "Tool ID, or hash when there is none",
  package: "Package and vulnerability",
};
const NEEDS_FIELDS = new Set<DedupStrategyName>(["hash_fields", "tool_id_or_hash"]);

const when = (iso: string | null) => (iso ? formatDateTime(iso) : "never");
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function MatchingScreen({ assetId }: { assetId: string }) {
  const [overview, setOverview] = useState<DedupOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [changing, setChanging] = useState<string | null>(null);
  const [applied, setApplied] = useState<string | null>(null);

  const load = useCallback(() => {
    getDedup(assetId).then(setOverview, (e) => setError(e instanceof ApiError ? e.message : "Could not load."));
  }, [assetId]);
  useEffect(load, [load]);

  if (error && !overview) return <p role="alert" className="ds-match-error">{error}</p>;
  if (!overview) return <p role="status">Loading…</p>;

  return (
    <div className="ds-match">
      <h1 className="ds-match-title">Matching</h1>
      <p className="ds-match-intro">
        Every source is matched into Issues by its <strong>fingerprint</strong> unless you choose
        otherwise. Choosing is previewed first: you see what would merge and what would split, and
        nothing changes until you confirm.{" "}
        <Link href={`/app/projects/${assetId}/import`}>Import a report</Link>
      </p>

      {applied && <p role="status" className="ds-match-done">{applied}</p>}

      {overview.sources.length === 0 ? (
        <p>No source has reported findings in this project yet. Run a scan or import a report first.</p>
      ) : (
        <table className="ds-match-table">
          <caption>Matching strategy by source</caption>
          <thead>
            <tr>
              <th scope="col">Source</th>
              <th scope="col">Strategy</th>
              <th scope="col">Version</th>
              <th scope="col">Issues seen</th>
              <th scope="col">Suggested</th>
              <th scope="col"><span className="ds-match-sr">Action</span></th>
            </tr>
          </thead>
          <tbody>
            {overview.sources.map((s) => (
              <SourceRow
                key={s.source}
                source={s}
                open={changing === s.source}
                onChange={() => setChanging(changing === s.source ? null : s.source)}
              />
            ))}
          </tbody>
        </table>
      )}

      {changing && (
        <ChangePanel
          key={changing}
          assetId={assetId}
          overview={overview}
          source={overview.sources.find((s) => s.source === changing)!}
          onClose={() => setChanging(null)}
          onApplied={(message) => {
            setApplied(message);
            setChanging(null);
            load();
          }}
        />
      )}

      <History assetId={assetId} sources={overview.sources.filter((s) => s.version > 0)} />
    </div>
  );
}

function SourceRow({ source, open, onChange }: { source: DedupSource; open: boolean; onChange: () => void }) {
  const custom = source.version > 0;
  return (
    <tr>
      <th scope="row">{source.source}</th>
      <td>
        {LABEL[source.strategy]}
        {source.fields.length > 0 && <span className="muted"> ({source.fields.join(", ")})</span>}
      </td>
      <td>{custom ? `v${source.version}` : "default"}</td>
      <td>{source.issues_seen}</td>
      <td>{source.recommended ? LABEL[source.recommended] : "—"}</td>
      <td>
        <button
          type="button"
          className="ds-match-link"
          aria-expanded={open}
          onClick={onChange}
        >
          {open ? "Close" : "Change"}
          <span className="ds-match-sr"> matching for {source.source}</span>
        </button>
      </td>
    </tr>
  );
}

function ChangePanel(props: {
  assetId: string;
  overview: DedupOverview;
  source: DedupSource;
  onClose: () => void;
  onApplied: (message: string) => void;
}) {
  const { assetId, overview, source } = props;
  const id = useId();
  const [strategy, setStrategy] = useState<DedupStrategyName>(source.strategy);
  const [fields, setFields] = useState<string[]>(source.fields);
  const [note, setNote] = useState("");
  const [preview, setPreview] = useState<DedupPreview | null>(null);
  const [busy, setBusy] = useState<"preview" | "apply" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const needsFields = NEEDS_FIELDS.has(strategy);

  const request = { source: source.source, strategy, fields: needsFields ? fields : [] };
  const invalid =
    strategy === "hash_fields" && fields.length === 0 ? "Choose at least one field to hash." : null;

  function edit(next: () => void) {
    next();
    setPreview(null); // a preview belongs to exactly the choices it was made for
    setError(null);
  }

  async function runPreview() {
    setBusy("preview");
    setError(null);
    try {
      setPreview(await previewDedup(assetId, request));
    } catch (e) {
      setPreview(null);
      setError(e instanceof ApiError ? e.message : "The preview failed.");
    } finally {
      setBusy(null);
    }
  }

  async function runApply() {
    if (!preview) return;
    setBusy("apply");
    setError(null);
    try {
      const done = await applyDedup(assetId, { ...request, digest: preview.digest, note: note.trim() || undefined });
      const e = done.effect;
      props.onApplied(
        `Applied. ${plural(e.merged_away ?? 0, "Issue")} merged away and ${plural(e.created_by_split ?? 0, "new Issue")} ` +
          `split off. This is version ${done.version} of the setting for ${source.source}.`,
      );
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setPreview(null);
        setError("This project changed since the preview. Preview the change again to see what it would do now.");
      } else {
        setError(e instanceof ApiError ? e.message : "The change could not be applied.");
      }
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="ds-match-panel" aria-labelledby={`${id}-h`}>
      <h2 id={`${id}-h`} className="ds-match-h">Change matching for {source.source}</h2>

      <fieldset className="ds-match-strategies">
        <legend>How should {source.source} findings be matched into Issues?</legend>
        {overview.strategies.map((s) => (
          <label key={s.name} className="ds-match-option">
            <input
              type="radio"
              name={`${id}-strategy`}
              value={s.name}
              checked={strategy === s.name}
              onChange={() => edit(() => setStrategy(s.name))}
            />
            <span>
              <strong>{LABEL[s.name]}</strong>
              {s.name === source.recommended && <span className="muted"> · suggested for this source</span>}
              <br />
              <span className="muted">{s.description}</span>
            </span>
          </label>
        ))}
      </fieldset>

      {needsFields && (
        <fieldset className="ds-match-fields" aria-describedby={invalid ? `${id}-field-error` : undefined}>
          <legend>
            Fields to hash
            {strategy === "tool_id_or_hash" && " (used only for findings without a rule id)"}
          </legend>
          {overview.fields.map((f) => (
            <label key={f}>
              <input
                type="checkbox"
                checked={fields.includes(f)}
                onChange={(e) =>
                  edit(() => setFields(e.target.checked ? [...fields, f] : fields.filter((x) => x !== f)))
                }
              />{" "}
              {f}
            </label>
          ))}
          {invalid && <p id={`${id}-field-error`} role="alert" className="ds-match-error">{invalid}</p>}
        </fieldset>
      )}

      <div className="ds-match-actions">
        <Button variant="primary" disabled={busy !== null || !!invalid} onClick={runPreview}>
          {busy === "preview" ? "Working out what would change…" : "Preview the change"}
        </Button>
        <Button onClick={props.onClose}>Cancel</Button>
      </div>

      {error && <p role="alert" className="ds-match-error">{error}</p>}

      {preview && (
        <div className="ds-match-preview" role="status" aria-live="polite">
          <p className="ds-match-summary">{preview.summary}.</p>
          <table className="ds-match-counts">
            <caption>What the change would do</caption>
            <tbody>
              <tr><th scope="row">Issues now</th><td>{preview.issues_before}</td></tr>
              <tr><th scope="row">Issues after</th><td>{preview.issues_after}</td></tr>
              <tr><th scope="row">Merged away</th><td>{preview.issues_merged_away}</td></tr>
              <tr><th scope="row">Split</th><td>{preview.issues_split}</td></tr>
              <tr><th scope="row">New Issues from splits</th><td>{preview.new_issues_from_split}</td></tr>
              {preview.skipped_multi_source > 0 && (
                <tr><th scope="row">Left alone (another tool also reported them)</th><td>{preview.skipped_multi_source}</td></tr>
              )}
            </tbody>
          </table>

          {preview.triage_conflicts > 0 && (
            <p className="ds-match-warn">
              {plural(preview.triage_conflicts, "merge")} would combine Issues with different triage
              decisions. Those Issues are reopened for triage, so an open Issue is never hidden behind a
              decision made about another one.
            </p>
          )}
          {preview.conflicts.length > 0 && (
            <p role="alert" className="ds-match-error">
              {plural(preview.conflicts.length, "key is", "keys are")} already held by other Issues, so this
              change cannot be applied.
            </p>
          )}
          {preview.examples.length > 0 && (
            <>
              <h3 className="ds-match-h3">Examples</h3>
              <ul className="ds-match-examples">
                {preview.examples.map((ex, i) => (
                  <li key={i}>
                    <strong>
                      {ex.kind === "merge" ? `Merge ${plural(ex.issue_count, "issue")}` : "Split"}
                    </strong>{" "}
                    {ex.titles.slice(0, 3).join(" · ")}
                    {ex.titles.length > 3 && ` · and ${ex.titles.length - 3} more titles`}{" "}
                    <span className="muted">({plural(ex.occurrences, "occurrence")})</span>
                  </li>
                ))}
              </ul>
            </>
          )}
          <p className="muted ds-match-caution">
            Occurrences are never lost: they move between Issues. A merge cannot be undone one-for-one;
            choosing the previous strategy again splits what it can.
          </p>

          <label htmlFor={`${id}-note`} className="ds-match-label">Why (optional, kept in the history)</label>
          <textarea id={`${id}-note`} value={note} maxLength={500} rows={2} onChange={(e) => setNote(e.target.value)} />
          <div className="ds-match-actions">
            <Button
              variant="primary"
              disabled={busy !== null || !preview.changes_anything || preview.conflicts.length > 0}
              onClick={runApply}
            >
              {busy === "apply" ? "Applying…" : "Apply this change"}
            </Button>
            {!preview.changes_anything && <span className="muted">This would change nothing.</span>}
          </div>
        </div>
      )}
    </section>
  );
}

function History({ assetId, sources }: { assetId: string; sources: DedupSource[] }) {
  const [rows, setRows] = useState<DedupHistoryEntry[] | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (open && rows === null) getDedupHistory(assetId).then(setRows, () => setRows([]));
  }, [open, rows, assetId]);
  if (sources.length === 0) return null;
  return (
    <details className="ds-match-history" onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary>History of changes</summary>
      {rows && (
        <table>
          <caption>Every version of every setting</caption>
          <thead>
            <tr>
              <th scope="col">Source</th><th scope="col">Version</th><th scope="col">Strategy</th>
              <th scope="col">Changed</th><th scope="col">By</th><th scope="col">Effect</th><th scope="col">Why</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((h) => (
              <tr key={`${h.source}-${h.version}`}>
                <th scope="row">{h.source}</th>
                <td>v{h.version}</td>
                <td>{LABEL[h.strategy]}{h.fields.length > 0 && ` (${h.fields.join(", ")})`}</td>
                <td>{when(h.created_at)}</td>
                <td>{h.created_by ?? "—"}</td>
                <td>
                  {Number(h.effect.merged_away ?? 0)} merged, {Number(h.effect.created_by_split ?? 0)} split off
                </td>
                <td>{h.note ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </details>
  );
}
