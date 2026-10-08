"use client";

import Link from "next/link";
import { useEffect, useId, useRef, useState } from "react";
import { ApiError, listLibraries, searchComponents } from "@/lib/api";
import type { ComponentSearch, ComponentUse, LibrarySummary } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./components-screen.css";

/** Plan §46.1: "where do we use this?" -- a library, optionally a version condition, and every
 * project whose latest SBOM has it. The library box suggests libraries by name as you type (the
 * most-used first); the query is kept in the URL so an answer can be shared. */

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function componentVerdict(r: ComponentSearch, asked: string): string {
  if (!r.library) return `No project's SBOM lists ${asked}.`;
  const name = r.library.name;
  const s = r.summary;
  const cond = r.constraint ? ` ${r.constraint}` : "";
  if (s.projects === 0) {
    const others = r.versions.reduce((n, v) => n + (v.matches === false ? v.projects : 0), 0);
    return r.constraint
      ? `No project uses ${name}${cond}.${others ? ` ${plural(others, "project")} use${others === 1 ? "s" : ""} other versions.` : ""}`
      : `No project uses ${name} now.`;
  }
  const where = `${plural(s.projects, "project")}${s.portfolios ? ` across ${plural(s.portfolios, "business unit")}` : ""}`;
  const facing = `${s.internet_facing} internet-facing${s.exposure_unset ? ` (${s.exposure_unset} not set)` : ""}`;
  return `${name}${cond} is in ${where}: ${facing}, ${s.imported_by_app} importing it from application code.`;
}

const RELATION: Record<ComponentUse["relation"], string> = {
  direct: "Direct", transitive: "Transitive", root: "The project itself", unknown: "Not known",
};
const EXPOSURE: Record<ComponentUse["exposure"], string> = { internet: "Internet", internal: "Internal", unset: "Not set" };

function Imported({ u }: { u: ComponentUse }) {
  const word = u.reachable === true ? "Yes" : u.reachable === false ? "No" : "Can't tell";
  return (
    <span className={`ds-comp-reach ds-comp-reach-${String(u.reachable)}`} title={u.reachable_reason || undefined}>
      {word}
      {u.reachable_reason && <span className="ds-comp-meta">{u.reachable_reason}</span>}
    </span>
  );
}

function urlWith(purl: string, version: string): string {
  const p = new URLSearchParams();
  if (purl) p.set("purl", purl);
  if (version) p.set("version", version);
  const q = p.toString();
  return `${window.location.pathname}${q ? `?${q}` : ""}`;
}

export function ComponentsScreen({ initialPurl = "", initialVersion = "" }: { initialPurl?: string; initialVersion?: string }) {
  const fid = useId();
  const [text, setText] = useState(initialPurl);
  const [version, setVersion] = useState(initialVersion);
  const [suggestions, setSuggestions] = useState<LibrarySummary[]>([]);
  const [top, setTop] = useState<LibrarySummary[] | null>(null);
  const [result, setResult] = useState<{ r: ComponentSearch; asked: string } | null>(null);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const typed = useRef(false);

  useEffect(() => {
    listLibraries("", 15).then((l) => setTop(Array.isArray(l) ? l : []), () => setTop([]));
    if (initialPurl) void run(initialPurl, initialVersion);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the first load only
  }, []);

  useEffect(() => {
    const q = text.trim();
    if (!typed.current || q.length < 2 || q.startsWith("pkg:")) { setSuggestions([]); return; }
    const t = setTimeout(() => {
      listLibraries(q, 8).then((l) => setSuggestions(Array.isArray(l) ? l : []), () => setSuggestions([]));
    }, 200);
    return () => clearTimeout(t);
  }, [text]);

  async function run(purl: string, ver: string) {
    setBusy(true);
    setError(null);
    setSuggestions([]);
    typed.current = false;
    try {
      const r = await searchComponents(purl, { version: ver.trim() || undefined });
      setResult({ r, asked: purl });
      window.history.replaceState(window.history.state, "", urlWith(purl, ver.trim()));
    } catch (e) {
      const data = e instanceof ApiError ? (e.data as { field?: string } | undefined) : undefined;
      setError({ field: data?.field, message: e instanceof ApiError ? e.message : "Could not search." });
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const q = text.trim();
    if (!q) { setError({ field: "purl", message: "Name a library, or paste its package URL." }); return; }
    if (q.startsWith("pkg:")) { void run(q, version); return; }
    // Asked for the text as it is now: the list under the field arrives 200 ms after typing stops,
    // so deciding from it said "no library is named like log4j-core" above the very match (Week 74).
    let found = suggestions;
    try {
      const l = await listLibraries(q, 8);
      found = Array.isArray(l) ? l : [];
      setSuggestions(found);
    } catch { /* keep what the field already shows */ }
    // "log4j-core" names Maven's org.apache.logging.log4j:log4j-core, npm's @scope/name by its name.
    const named = (l: LibrarySummary) => [l.name, l.name.split(/[:/]/).pop() ?? ""].map((n) => n.toLowerCase());
    const exact = found.filter((l) => named(l).includes(q.toLowerCase()));
    const only = exact.length === 1 ? exact[0] : found.length === 1 ? found[0] : undefined;
    if (only) { pick(only); return; }
    setError({ field: "purl", message: found.length ? "More than one library matches: pick one below." : `No library in use is named like “${q}”.` });
  }

  function pick(l: LibrarySummary) {
    setText(l.purl);
    void run(l.purl, version);
  }

  const r = result?.r;
  return (
    <div className="ds-comp">
      <h1>Components</h1>
      <p className="ds-comp-meta">Where do we use a library? Every project&apos;s latest SBOM, from scans and imported CycloneDX or SPDX files.</p>
      <form className="ds-comp-form" onSubmit={submit} noValidate>
        <div className="ds-comp-field ds-comp-lib">
          <label htmlFor={`${fid}-lib`}>Library</label>
          <input
            id={`${fid}-lib`} value={text} autoComplete="off" spellCheck={false}
            placeholder="log4j-core, or pkg:maven/org.apache.logging.log4j/log4j-core"
            aria-describedby={error?.field === "purl" ? `${fid}-err` : undefined}
            aria-invalid={error?.field === "purl" || undefined}
            onChange={(e) => { typed.current = true; setText(e.target.value); }}
          />
        </div>
        <div className="ds-comp-field">
          <label htmlFor={`${fid}-ver`}>Versions <span className="ds-comp-meta">(optional)</span></label>
          <input
            id={`${fid}-ver`} value={version} autoComplete="off" spellCheck={false} placeholder="<2.17.1 or >=2.0,<2.17.1"
            aria-describedby={error?.field === "version" ? `${fid}-err` : `${fid}-ver-help`}
            aria-invalid={error?.field === "version" || undefined}
            onChange={(e) => setVersion(e.target.value)}
          />
        </div>
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Searching…" : "Search"}</Button>
      </form>
      <p id={`${fid}-ver-help`} className="ds-comp-meta">Versions are compared the way the library&apos;s ecosystem orders them (PyPI, npm, Go and Maven).</p>
      {error && <p id={`${fid}-err`} role="alert" className="ds-comp-error">{error.message}</p>}
      {suggestions.length > 0 && (
        <section aria-label="Matching libraries">
          <ul className="ds-comp-suggest">
            {suggestions.map((l) => (
              <li key={l.id}>
                <button type="button" onClick={() => pick(l)}>
                  <span className="ds-comp-name">{l.name}</span>
                  <span className="ds-comp-meta"> · {l.ecosystem} · {plural(l.projects, "project")}, {plural(l.versions, "version")}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {r && result && (
        <section aria-labelledby={`${fid}-answer`} className="ds-comp-answer">
          <h2 id={`${fid}-answer`} className="ds-comp-verdict" aria-live="polite">{componentVerdict(r, result.asked)}</h2>
          {r.library && <p className="ds-comp-meta"><code>{r.library.purl}</code> · answered in {Math.round(r.elapsed_ms)} ms</p>}
          {r.uncomparable.length > 0 && (
            <p className="ds-comp-warn">
              {plural(r.uncomparable.length, "version")} could not be compared with {r.constraint} and {r.uncomparable.length === 1 ? "is" : "are"} not counted: {r.uncomparable.join(", ")}.
            </p>
          )}
          {r.versions.length > 0 && (
            <ul className="ds-comp-versions" aria-label="Versions in use">
              {r.versions.map((v) => (
                <li key={v.version} className={`ds-comp-v ds-comp-v-${String(v.matches)}`}>
                  <code>{v.version || "(no version)"}</code> {plural(v.projects, "project")}
                  {v.matches === false && <span className="ds-comp-meta"> · outside {r.constraint}</span>}
                  {v.matches === null && <span className="ds-comp-meta"> · not comparable</span>}
                  {v.advisories && v.advisories.length > 0 && (
                    <span className="ds-comp-advs">
                      {" · "}
                      {v.advisories.slice(0, 3).map((k, i) => (
                        <span key={k}>{i > 0 && ", "}<Link href={`/app/advisories/${encodeURIComponent(k)}`}>{k}</Link></span>
                      ))}
                      {v.advisories.length > 3 && ` +${v.advisories.length - 3}`}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
          {r.uses.length > 0 && (
            <table className="ds-comp-table">
              <caption className="ds-comp-meta">Projects using it{r.constraint ? ` (${r.constraint})` : ""}</caption>
              <thead>
                <tr>
                  <th scope="col">Project</th><th scope="col">Version</th><th scope="col">Dependency</th>
                  <th scope="col">Imported by application code</th><th scope="col">Exposure</th><th scope="col">Found in</th>
                </tr>
              </thead>
              <tbody>
                {r.uses.map((u) => (
                  <tr key={`${u.project_id}-${u.version}-${u.source}`}>
                    <th scope="row" data-label="Project">
                      <Link href={`/app/projects/${u.project_id}`}>{u.project}</Link>
                      {u.portfolio && <span className="ds-comp-meta"> · {u.portfolio}</span>}
                    </th>
                    <td data-label="Version" className="ds-comp-nowrap"><code>{u.version || "(none)"}</code></td>
                    <td data-label="Dependency" className="ds-comp-nowrap">{RELATION[u.relation]}</td>
                    <td data-label="Imported"><Imported u={u} /></td>
                    <td data-label="Exposure" className="ds-comp-nowrap" title={u.exposure === "unset" ? "Not set in the project's priority settings; ranked as internet-facing" : undefined}>{EXPOSURE[u.exposure]}</td>
                    <td data-label="Found in" className="ds-comp-paths">
                      {u.paths[0] ?? "—"}{u.paths.length > 1 ? ` +${u.paths.length - 1} more` : ""}
                      <span className="ds-comp-meta"> · {u.source === "scan" ? "scan" : "import"}, {new Date(u.seen_at).toLocaleDateString()}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {r.truncated && <p className="ds-comp-meta">Showing the first 2,000 uses; add a version condition to narrow it.</p>}
        </section>
      )}

      {!result && top && (
        <section aria-labelledby={`${fid}-top`}>
          <h2 id={`${fid}-top`}>Most used</h2>
          {top.length === 0 ? (
            <p>No SBOMs yet. Run a scan with Syft, or import a CycloneDX or SPDX file, and its packages appear here.</p>
          ) : (
            <ul className="ds-comp-top">
              {top.map((l) => (
                <li key={l.id}>
                  <button type="button" onClick={() => pick(l)}>
                    <span className="ds-comp-name">{l.name}</span>
                    <span className="ds-comp-meta"> · {l.ecosystem} · {plural(l.projects, "project")}, {plural(l.versions, "version")}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}
