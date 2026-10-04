"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError, cancelImport, confirmImport, getDedup, getImport, listAssets, listParsers, listProjectTests,
  revertImport, startImport,
} from "@/lib/api";
import type {
  DedupSource, FormatCandidates, ImportCounts, ImportView, ParserInfo, ProjectTest,
} from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./import-screen.css";

/** Importing a report from a tool Bulwark does not run (plan §55.1, §42.1, ADR-0040).
 *
 * The point of the screen is the four counts, shown *before* anything is saved -- new, unchanged,
 * reopened, closed -- because reimport is the operation whose mistakes people do not notice
 * (principle 9). The file is previewed first (the server counts and saves nothing), and "Import
 * file" then applies exactly that upload, ending with a confirmation in the same words and numbers.
 * The format is detected from the file; below 90% confidence the person has to confirm it before
 * any counts appear.
 *
 * Parsing happens on a worker, so every step polls the import until it reaches a resting state. */

type Phase = "pick" | "reading" | "choose-format" | "preview" | "importing" | "done" | "failed";
type Missing = "no" | "test" | "engagement";
type Into = { test: string; engagement: "import" | "assessment"; engagementName: string };

const MAX_POLLS = 240; // ~3 minutes at the default interval
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const shortId = (id: string) => id.slice(0, 8);
const sizeLabel = (bytes: number) =>
  bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;

function isCandidates(x: unknown): x is FormatCandidates {
  return !!x && typeof x === "object" && Array.isArray((x as FormatCandidates).available);
}

const STRATEGY_WORDS = {
  fingerprint_v2: "fingerprint",
  tool_id: "tool ID",
  hash_fields: "chosen fields",
  tool_id_or_hash: "tool ID or chosen fields",
  package: "package and vulnerability",
} as const;

const doneLine = (c: ImportCounts) => `${c.new} new, ${c.reopened} reopened, ${c.closed} closed`;

export function ImportScreen({ assetId, pollMs = 800 }: { assetId: string; pollMs?: number }) {
  const [phase, setPhase] = useState<Phase>("pick");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<ImportView | null>(null);
  const [confidence, setConfidence] = useState<number | null>(null);
  const [candidates, setCandidates] = useState<FormatCandidates | null>(null);
  const [parserChoice, setParserChoice] = useState("");
  const [missing, setMissing] = useState<Missing>("test");
  const [into, setInto] = useState<Into>({ test: "", engagement: "import", engagementName: "" });
  const [editInto, setEditInto] = useState(false);
  const [changeFormat, setChangeFormat] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [applied, setApplied] = useState<ImportView | null>(null);
  const [previewed, setPreviewed] = useState<ImportCounts | null>(null);
  const [undone, setUndone] = useState<string | null>(null);
  const [parsers, setParsers] = useState<ParserInfo[]>([]);
  const [tests, setTests] = useState<ProjectTest[]>([]);
  const [projectLabel, setProjectLabel] = useState<string>(assetId);
  const [matching, setMatching] = useState<DedupSource[]>([]);

  const run = useRef(0); // each analysis gets a number; a stale one's results are dropped
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    listParsers().then(setParsers, () => setParsers([]));
    listProjectTests(assetId).then(setTests, () => setTests([]));
    getDedup(assetId).then((d) => setMatching(d.sources.filter((s) => s.version > 0)), () => setMatching([]));
    listAssets().then(
      (all) => setProjectLabel(all.find((a) => a.id === assetId)?.label ?? assetId),
      () => undefined,
    );
  }, [assetId]);

  const labelOf = useCallback(
    (name: string) => parsers.find((p) => p.name === name)?.label ?? name,
    [parsers],
  );

  async function waitFor(id: string, done: (v: ImportView) => boolean, mine: number): Promise<ImportView | null> {
    for (let i = 0; i < MAX_POLLS; i++) {
      const v = await getImport(id);
      if (run.current !== mine || !mounted.current) return null;
      if (done(v)) return v;
      await sleep(pollMs);
    }
    throw new ApiError(0, "This is taking longer than expected. Check the project's imports again in a moment.");
  }

  /** Upload the file for a preview with the given choices and wait for the counts. */
  async function analyze(
    f: File,
    o: { parser: string; missing: Missing; into: Into },
  ) {
    const mine = ++run.current;
    setPhase("reading");
    setError(null);
    setView(null);
    setCandidates(null);
    try {
      const created = await startImport(assetId, f, {
        parser: o.parser || undefined,
        test: o.into.test.trim() || undefined,
        engagementType: o.into.engagement,
        engagementName: o.into.engagementName.trim() || undefined,
        closeMissing: o.missing !== "no",
        scope: o.missing === "engagement" ? "engagement" : "test",
        preview: true,
      });
      if (run.current !== mine) return;
      setConfidence(created.confidence);
      const v = await waitFor(created.import_id, (x) => x.status === "previewed" || x.status === "failed", mine);
      if (!v) return;
      if (v.status === "failed") {
        setError(v.error ?? "The file could not be read.");
        setPhase("failed");
        return;
      }
      setView(v);
      setPreviewed(v.counts);
      setPhase("preview");
    } catch (e) {
      if (run.current !== mine) return;
      if (e instanceof ApiError && e.status === 422 && isCandidates(e.data)) {
        setCandidates(e.data); // format not recognised with confidence: the person confirms it
        setPhase("choose-format");
        return;
      }
      setError(e instanceof ApiError ? e.message : "Could not read the file.");
      setPhase("failed");
    }
  }

  /** Throw away the current preview (best effort) and analyse again with changed choices. */
  function reanalyze(o: { parser?: string; missing?: Missing; into?: Into }) {
    if (!file) return;
    if (view) cancelImport(view.id).catch(() => undefined);
    const next = { parser: o.parser ?? parserChoice, missing: o.missing ?? missing, into: o.into ?? into };
    setParserChoice(next.parser);
    setMissing(next.missing);
    setInto(next.into);
    void analyze(file, next);
  }

  function pickFile(f: File | null) {
    if (!f) return;
    setFile(f);
    setApplied(null);
    setUndone(null);
    setShowClosed(false);
    setChangeFormat(false);
    setParserChoice("");
    void analyze(f, { parser: "", missing, into });
  }

  async function doImport() {
    if (!view) return;
    const mine = ++run.current;
    setPhase("importing");
    setError(null);
    try {
      await confirmImport(view.id);
      const v = await waitFor(view.id, (x) => ["applied", "duplicate", "failed"].includes(x.status), mine);
      if (!v) return;
      if (v.status === "failed") {
        setError(v.error ?? "The import failed.");
        setPhase("failed");
        return;
      }
      setApplied(v);
      setPhase("done");
      listProjectTests(assetId).then(setTests, () => undefined);
    } catch (e) {
      if (run.current !== mine) return;
      setError(e instanceof ApiError ? e.message : "The import failed.");
      setPhase("failed");
    }
  }

  async function cancel() {
    run.current++;
    if (view) await cancelImport(view.id).catch(() => undefined);
    reset();
  }

  function reset() {
    setPhase("pick");
    setFile(null);
    setView(null);
    setApplied(null);
    setError(null);
    setCandidates(null);
    setUndone(null);
  }

  async function undo() {
    if (!applied) return;
    try {
      const r = await revertImport(applied.id);
      setUndone(`Import undone: ${r.restored} issue(s) restored${r.skipped ? `, ${r.skipped} left as they are because something newer changed them` : ""}.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not undo the import.");
    }
  }

  const issueLink = (id: string) => (
    <Link key={id} href={`/app/projects/${assetId}/issues/${id}`} className="ds-import-id">
      {shortId(id)}
    </Link>
  );
  const standing = into.engagement === "import";
  const where = [
    projectLabel,
    standing ? "Imports" : into.engagementName.trim() || "New assessment",
    into.test.trim() || (view ? labelOf(view.parser) : "…"),
  ].join(" / ");

  return (
    <div className="ds-import">
      <h1 className="ds-import-title">Import a report</h1>
      <p className="small muted ds-import-intro">
        Bring in findings from a tool Bulwark does not run. Nothing is saved until you press Import:
        you see what would change first. Importing the same file twice changes nothing, and the most
        recent import can be undone.
      </p>

      {error && phase !== "failed" && <p className="ds-import-error" role="alert">{error}</p>}

      {(phase === "pick" || phase === "failed") && (
        <div>
          {phase === "failed" && (
            <p className="ds-import-error" role="alert">
              {error ?? "The import failed."}
            </p>
          )}
          <label className="ds-import-label" htmlFor="import-file">Report file</label>
          <input
            id="import-file"
            type="file"
            accept=".json,.xml,.sarif"
            onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
          />
          <p className="small muted">
            SARIF, CycloneDX (JSON or XML), OSV-Scanner JSON or SPDX JSON, up to 100 MB. The format is
            detected from the file.
          </p>
        </div>
      )}

      {phase === "reading" && (
        <p role="status" className="ds-import-status">
          Reading {file?.name}… this can take a moment for a large report.
        </p>
      )}

      {phase === "choose-format" && candidates && (
        <section aria-labelledby="import-format-h">
          <h2 id="import-format-h" className="ds-import-h">Which kind of file is this?</h2>
          <p role="status">
            Bulwark could not tell what <strong>{file?.name}</strong> is with enough confidence to
            go on without asking.
            {candidates.detected.length > 0 && (
              <>
                {" "}Closest match: {candidates.detected.map((d) => `${labelOf(d.parser)} (${Math.round(d.confidence * 100)}%)`).join(", ")}.
              </>
            )}
          </p>
          <label className="ds-import-label" htmlFor="import-format">Format</label>
          <select
            id="import-format"
            value={parserChoice}
            onChange={(e) => setParserChoice(e.target.value)}
          >
            <option value="">Choose a format…</option>
            {candidates.available.map((name) => (
              <option key={name} value={name}>{labelOf(name)}</option>
            ))}
          </select>
          <div className="ds-import-actions">
            <Button onClick={reset}>Choose a different file</Button>
            <Button
              variant="primary"
              disabled={!parserChoice}
              onClick={() => file && analyze(file, { parser: parserChoice, missing, into })}
            >
              Use this format
            </Button>
          </div>
        </section>
      )}

      {(phase === "preview" || phase === "importing") && view && view.counts && (
        <section aria-labelledby="import-results-h">
          <h2 id="import-results-h" className="ds-import-h">Import results</h2>
          <dl className="ds-import-facts">
            <div>
              <dt>File</dt>
              <dd>
                {view.file_name ?? file?.name}
                {file ? ` · ${sizeLabel(file.size)}` : ""} · looks like <strong>{labelOf(view.parser)}</strong>
                {confidence !== null && ` (${Math.round(confidence * 100)}% sure)`}{" "}
                <button type="button" className="ds-import-link" onClick={() => setChangeFormat((v) => !v)}>
                  Change
                </button>
                {changeFormat && (
                  <span className="ds-import-inline">
                    <label className="ds-import-sr" htmlFor="import-reformat">Format</label>
                    <select
                      id="import-reformat"
                      value={view.parser}
                      onChange={(e) => {
                        setChangeFormat(false);
                        reanalyze({ parser: e.target.value });
                      }}
                    >
                      {parsers.map((p) => (
                        <option key={p.name} value={p.name}>{p.label}</option>
                      ))}
                    </select>
                  </span>
                )}
              </dd>
            </div>
            <div>
              <dt>Into</dt>
              <dd>
                {where}{" "}
                <button type="button" className="ds-import-link" onClick={() => setEditInto((v) => !v)}>
                  Change
                </button>
              </dd>
            </div>
            <div>
              <dt>Matching</dt>
              <dd>
                {matching.length === 0
                  ? "Issue fingerprints, the way every scan matches"
                  : `${matching.map((m) => `${m.source}: ${STRATEGY_WORDS[m.strategy]}`).join("; ")} — issue fingerprints for every other source`}{" "}
                <Link href={`/app/projects/${assetId}/matching`}>Matching settings</Link>
              </dd>
            </div>
          </dl>

          {editInto && (
            <IntoEditor
              value={into}
              tests={tests}
              onApply={(v) => {
                setEditInto(false);
                reanalyze({ into: v });
              }}
            />
          )}

          <fieldset className="ds-import-missing">
            <legend className="ds-import-label">Close issues missing from this file</legend>
            {(
              [
                ["no", "No"],
                ["test", "This test"],
                ["engagement", "This engagement"],
              ] as const
            ).map(([value, label]) => (
              <label key={value}>
                <input
                  type="radio"
                  name="import-missing"
                  value={value}
                  checked={missing === value}
                  disabled={phase === "importing"}
                  onChange={() => reanalyze({ missing: value })}
                />{" "}
                {label}
              </label>
            ))}
          </fieldset>

          <h3 className="ds-import-h3">If you import this file</h3>
          <ul className="ds-import-counts" aria-label="What would change">
            <li><strong>{view.counts.new}</strong> new</li>
            <li><strong>{view.counts.unchanged}</strong> unchanged</li>
            <li><strong>{view.counts.reopened}</strong> reopened</li>
            <li><strong>{view.counts.closed}</strong> closed</li>
          </ul>

          {view.reopened_issue_ids.length > 0 && (
            <p className="ds-import-line">
              <strong>Reopened</strong> (these were fixed and are back):{" "}
              {view.reopened_issue_ids.map((id, i) => (
                <span key={id}>{i > 0 && ", "}{issueLink(id)}</span>
              ))}
              {view.ids_truncated && " …"}
            </p>
          )}
          {view.counts.closed > 0 && (
            <div className="ds-import-line">
              <strong>Closed</strong>: {view.counts.closed} issue{view.counts.closed === 1 ? "" : "s"} this
              file no longer reports{" "}
              <button type="button" className="ds-import-link" onClick={() => setShowClosed((v) => !v)} aria-expanded={showClosed}>
                {showClosed ? "Hide" : "Show all"}
              </button>
              {showClosed && (
                <ul className="ds-import-ids">
                  {view.closed_issue_ids.map((id) => (
                    <li key={id}>{issueLink(id)}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
          {view.counts.detached > 0 && (
            <p className="ds-import-line">
              <strong>{view.counts.detached}</strong> more issue{view.counts.detached === 1 ? "" : "s"} are no
              longer in this file but stay open, because another source still reports them.
            </p>
          )}
          {view.warnings.length > 0 && (
            <div className="ds-import-check">
              <h3 className="ds-import-h3">Check</h3>
              <ul>
                {view.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          <p className="ds-import-saved-note">Nothing is saved until you import.</p>
          <div className="ds-import-actions">
            <Button onClick={cancel} disabled={phase === "importing"}>Cancel</Button>
            <Button variant="primary" onClick={doImport} disabled={phase === "importing"}>
              {phase === "importing" ? "Importing…" : "Import file"}
            </Button>
          </div>
        </section>
      )}

      {phase === "importing" && !view && <p role="status">Importing…</p>}

      {phase === "done" && applied && applied.counts && (
        <section aria-labelledby="import-done-h">
          <h2 id="import-done-h" className="ds-import-h">Done</h2>
          <p role="status" className="ds-import-done">Imported: {doneLine(applied.counts)}</p>
          {previewed && doneLine(previewed) !== doneLine(applied.counts) && (
            <p className="ds-import-line muted">
              These numbers differ from the preview ({doneLine(previewed)}) because the project changed
              while you were deciding.
            </p>
          )}
          {applied.status === "duplicate" && (
            <p className="ds-import-line">This file was already the latest import, so nothing changed.</p>
          )}
          {applied.warnings.map((w, i) => (
            <p key={i} className="ds-import-line muted">{w}</p>
          ))}
          {undone && <p role="status" className="ds-import-line">{undone}</p>}
          {error && <p className="ds-import-error" role="alert">{error}</p>}
          <div className="ds-import-actions">
            <Link href={`/app/projects/${assetId}/issues`} className="ds-button primary">View issues</Link>
            <Button onClick={reset}>Import another file</Button>
            {!undone && <Button onClick={undo}>Undo this import</Button>}
          </div>
        </section>
      )}
    </div>
  );
}

function IntoEditor({
  value,
  tests,
  onApply,
}: {
  value: Into;
  tests: ProjectTest[];
  onApply: (v: Into) => void;
}) {
  const [draft, setDraft] = useState(value);
  return (
    <div className="ds-import-into" role="group" aria-label="Where this import goes">
      <label className="ds-import-label" htmlFor="import-test-name">Test</label>
      <input
        id="import-test-name"
        type="text"
        list="import-test-options"
        placeholder="Named after the format"
        value={draft.test}
        onChange={(e) => setDraft({ ...draft, test: e.target.value })}
      />
      <datalist id="import-test-options">
        {tests.map((t) => (
          <option key={t.id} value={t.name} />
        ))}
      </datalist>
      <fieldset className="ds-import-missing">
        <legend className="ds-import-label">Engagement</legend>
        <label>
          <input
            type="radio"
            name="import-engagement"
            checked={draft.engagement === "import"}
            onChange={() => setDraft({ ...draft, engagement: "import" })}
          />{" "}
          The project&apos;s standing imports
        </label>
        <label>
          <input
            type="radio"
            name="import-engagement"
            checked={draft.engagement === "assessment"}
            onChange={() => setDraft({ ...draft, engagement: "assessment" })}
          />{" "}
          A new assessment (a pen test, an audit)
        </label>
      </fieldset>
      {draft.engagement === "assessment" && (
        <>
          <label className="ds-import-label" htmlFor="import-engagement-name">Assessment name</label>
          <input
            id="import-engagement-name"
            type="text"
            placeholder="Q3 external pentest"
            value={draft.engagementName}
            onChange={(e) => setDraft({ ...draft, engagementName: e.target.value })}
          />
        </>
      )}
      <div className="ds-import-actions">
        <Button
          variant="primary"
          disabled={draft.engagement === "assessment" && !draft.engagementName.trim()}
          onClick={() => onApply(draft)}
        >
          Update preview
        </Button>
      </div>
    </div>
  );
}
