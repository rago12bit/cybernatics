"use client";

import { useCallback, useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { getFindings } from "@/lib/api";
import { collectAll, exportFilename, exportPayload, saveBlob } from "@/lib/export";
import { defaultQuery, isDefaultQuery, locationLabel, pageCount, queryToSearch, rangeLabel, searchToQuery } from "@/lib/format";
import { CATEGORIES, FILTER_TOOLS, SEVERITIES, type Finding, type FindingsPage, type FindingsQuery, type GuidanceApi, type ScanView, type Severity } from "@/lib/types";
import { ConfirmedAtRuntimeBadge, IssueBadge, RiskSignals, SeverityBadge } from "./Badges";
import { FindingDetail } from "./FindingDetail";
import { FixFirst } from "./FixFirst";

type Fetcher = (id: string, q: FindingsQuery, limit?: number) => Promise<FindingsPage>;

const isTyping = (t: EventTarget | null) => t instanceof HTMLElement && /^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName);

export function FindingsTable({ scan, version, fetchFindings = getFindings, guidance }: { scan: ScanView; version: number; fetchFindings?: Fetcher; guidance?: GuidanceApi }) {
  const [q, setQ] = useState<FindingsQuery>(defaultQuery());
  const [pathInput, setPathInput] = useState("");
  const [hydrated, setHydrated] = useState(false);
  const [page, setPage] = useState<FindingsPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [open, setOpen] = useState(false); // drives the sheet's enter/exit; `selected` outlives it during exit
  const [exporting, setExporting] = useState(false);
  const [navList, setNavList] = useState<Finding[] | null>(null); // set when opened from "Fix these first"
  const exitTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const trigger = useRef<HTMLElement | null>(null);
  const tbody = useRef<HTMLTableSectionElement>(null);

  // Restore filters from the URL once after mount (never during render: avoids hydration mismatches).
  useEffect(() => {
    const init = searchToQuery(window.location.search);
    setQ(init);
    setPathInput(init.path);
    setHydrated(true);
  }, []);
  useEffect(() => {
    if (!hydrated) return;
    // Keep Next's own history state: replacing it with null makes Back/Forward reload the page.
    window.history.replaceState(window.history.state, "", `${window.location.pathname}${queryToSearch(q)}${window.location.hash}`);
  }, [q, hydrated]);

  const select = useCallback((f: Finding, el: HTMLElement | null, list: Finding[] | null = null) => {
    setNavList(list); // prev/next follow the list the finding was opened from
    // Interruptible: choosing again mid-exit cancels the exit; CSS re-targets from the live position.
    if (exitTimer.current) clearTimeout(exitTimer.current);
    if (el) trigger.current = el;
    setSelected(f);
    setOpen(true); // FindingDetail mounts closed and flips to open after a forced style flush
  }, []);

  const close = useCallback(() => {
    setOpen(false);
    if (exitTimer.current) clearTimeout(exitTimer.current);
    exitTimer.current = setTimeout(() => setSelected(null), 300);
    trigger.current?.focus({ preventScroll: true });
  }, []);

  const tableItems = page?.items ?? [];
  const items = navList ?? tableItems;
  const index = selected ? items.findIndex((f) => f.id === selected.id) : -1;
  const go = useCallback(
    (delta: number) => {
      const next = items[index + delta];
      if (!next) return;
      const scope = navList ? document.querySelector(".fixlist") : tbody.current;
      const btn = scope?.querySelector<HTMLElement>(`[data-fid="${CSS.escape(next.id)}"]`) ?? null;
      select(next, btn, navList);
      btn?.scrollIntoView({ block: "nearest" });
    },
    [items, index, navList, select],
  );

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") return close();
      if (isTyping(e.target) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "j") go(1);
      if (e.key === "k") go(-1);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, close, go]);
  useEffect(() => () => { if (exitTimer.current) clearTimeout(exitTimer.current); }, []);

  // Debounce the free-text path filter so typing does not fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => setQ((cur) => (cur.path === pathInput ? cur : { ...cur, path: pathInput, page: 0 })), 150);
    return () => clearTimeout(t);
  }, [pathInput]);

  useEffect(() => {
    if (!hydrated) return;
    let cancelled = false;
    setLoading(true);
    fetchFindings(scan.id, q).then(
      (p) => { if (!cancelled) { setPage(p); setError(null); setLoading(false); } },
      (e) => { if (!cancelled) { setError(e instanceof Error ? e.message : "Failed to load findings"); setLoading(false); } },
    );
    return () => { cancelled = true; };
  }, [scan.id, q, version, fetchFindings, hydrated]);

  // A shared link (or a shrinking result set) can point past the last page: land on the last one instead of "no findings".
  useEffect(() => {
    if (page && page.items.length === 0 && page.total > 0 && q.page > 0) setQ((cur) => ({ ...cur, page: pageCount(page.total) - 1 }));
  }, [page, q.page]);

  const update = (patch: Partial<FindingsQuery>) => setQ((cur) => ({ ...cur, ...patch, page: patch.page ?? 0 }));
  const toggleSeverity = (s: Severity) => update({ severity: q.severity.includes(s) ? q.severity.filter((x) => x !== s) : [...q.severity, s] });
  const reset = () => {
    setPathInput("");
    setQ(defaultQuery());
  };
  const pages = pageCount(page?.total ?? 0);

  // ArrowUp/Down move between rows without tabbing through every button.
  const onRowKeys = (e: ReactKeyboardEvent<HTMLTableSectionElement>) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const btns = [...(tbody.current?.querySelectorAll<HTMLElement>("button.row-title") ?? [])];
    const at = btns.indexOf(document.activeElement as HTMLElement);
    const next = btns[at + (e.key === "ArrowDown" ? 1 : -1)];
    if (next) { e.preventDefault(); next.focus(); }
  };

  async function exportAll() {
    setExporting(true);
    try {
      const all = await collectAll((qq, limit) => fetchFindings(scan.id, qq, limit), q);
      const blob = new Blob([JSON.stringify(exportPayload(scan, all, q), null, 2)], { type: "application/json" });
      saveBlob(blob, exportFilename(scan));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  const filtered = !isDefaultQuery(q);
  return (
    <section aria-labelledby="findings-h" className="section findings">
      <div className="list">
        <FixFirst scanId={scan.id} version={version} fetchFindings={fetchFindings} onOpen={(f, el, list) => select(f, el, list)} />
        <div className="app-head">
          <span className="eyebrow">Findings</span>
          <div className="head-row">
            <h2 id="findings-h" className="h1">{page ? page.total : "…"} <span className="muted">{filtered ? "match" : "to review"}</span></h2>
            <div className="head-actions">
              {filtered && <button type="button" className="btn sm" onClick={reset}>Reset filters</button>}
              <button type="button" className="btn sm" onClick={exportAll} disabled={exporting || !page || page.total === 0} aria-label={`Export ${page?.total ?? 0} findings as JSON`}>{exporting ? "Exporting…" : "Export JSON"}</button>
            </div>
          </div>
        </div>

        <div className="filters" role="search" aria-label="Filter findings">
          <div className="chips" role="group" aria-label="Severity">
            {SEVERITIES.map((s) => (
              <button key={s} type="button" className={`filter sev-${s.toLowerCase()}`} aria-pressed={q.severity.includes(s)} onClick={() => toggleSeverity(s)}><span>{s}</span></button>
            ))}
          </div>
          <label className="inline">Category
            <select value={q.category} onChange={(e) => update({ category: e.target.value })}>
              <option value="">All</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <label className="inline">Scanner
            <select value={q.tool} onChange={(e) => update({ tool: e.target.value })}>
              <option value="">All</option>
              {FILTER_TOOLS.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="inline">Sort
            <select value={q.sort} onChange={(e) => update({ sort: e.target.value as FindingsQuery["sort"] })}>
              <option value="severity">Severity</option>
              <option value="path">File path</option>
              <option value="risk">Risk score</option>
            </select>
          </label>
          <label className="inline grow">File
            <input type="search" placeholder="Filter by path…" value={pathInput} onChange={(e) => setPathInput(e.target.value)} />
          </label>
        </div>

        {error && <p className="f-empty error" role="alert">{error}</p>}
        {!error && page && page.items.length === 0 && (
          <div className="f-empty">
            <p className="muted">{page.total === 0 && scan.unique_findings === 0 ? "No findings. Nothing to review." : "No findings match these filters."}</p>
            {filtered && <button type="button" className="btn sm" onClick={reset}>Reset filters</button>}
          </div>
        )}
        {!error && !page && loading && (
          <div className="scroll" role="status" aria-busy="true" aria-label="Loading findings">
            <table className="findings-table skeleton">
              <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Scanners</th></tr></thead>
              <tbody>{Array.from({ length: 8 }, (_, i) => <tr key={i}><td><span className="sk sk-s" /></td><td><span className="sk sk-l" /></td><td><span className="sk sk-m" /></td><td><span className="sk sk-s" /></td></tr>)}</tbody>
            </table>
          </div>
        )}
        {page && page.items.length > 0 && (
          <div className={loading ? "scroll busy" : "scroll"} aria-busy={loading}>
            <table className="findings-table">
              <caption className="sr-only">Findings for this scan. Use arrow keys to move between rows and Enter to open one.</caption>
              <thead><tr><th scope="col">Severity</th><th scope="col">Finding</th><th scope="col">Location</th><th scope="col">Scanners</th></tr></thead>
              <tbody ref={tbody} onKeyDown={onRowKeys}>
                {page.items.map((f) => (
                  <tr key={f.id} className={selected?.id === f.id ? "selected" : ""}>
                    <td><span className="sevcell"><SeverityBadge severity={f.scoring.normalized_severity} /><RiskSignals score={f.scoring.risk_score} kev={f.scoring.in_cisa_kev} epss={f.scoring.epss_score} /></span></td>
                    <td>
                      <button type="button" className="row-title" data-fid={f.id} onClick={(e) => select(f, e.currentTarget)} aria-pressed={selected?.id === f.id}><span className="clamp">{f.title}</span></button>
                      <IssueBadge issue={f.issue} />
                      <ConfirmedAtRuntimeBadge issue={f.issue} />
                    </td>
                    <td><code className="loc">{locationLabel(f)}</code></td>
                    <td><span className="chips">{f.evidence.reported_by.map((t) => <span key={t} className="chip">{t}</span>)}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <nav className="pager" aria-label="Pagination">
          <button type="button" className="btn sm" disabled={q.page === 0} onClick={() => setQ({ ...q, page: q.page - 1 })}>← Prev</button>
          <span role="status" aria-live="polite">{page ? rangeLabel(page.total, q.page, page.items.length) : "Loading"}{pages > 1 ? ` · page ${q.page + 1} of ${pages}` : ""}</span>
          <button type="button" className="btn sm" disabled={q.page + 1 >= pages} onClick={() => setQ({ ...q, page: q.page + 1 })}>Next →</button>
        </nav>
        <p className="kbd-hint small dim" aria-hidden="true">↑ ↓ move between rows · Enter opens · <kbd>j</kbd> <kbd>k</kbd> next / previous finding · Esc closes</p>
      </div>
      <div className="scrim" data-state={open ? "open" : "closed"} onClick={close} aria-hidden="true" />
      {selected && (
        <FindingDetail
          finding={selected}
          scan={scan}
          open={open}
          onClose={close}
          position={index >= 0 ? { index: index + 1, total: items.length } : undefined}
          onPrev={index > 0 ? () => go(-1) : undefined}
          onNext={index >= 0 && index < items.length - 1 ? () => go(1) : undefined}
          guidance={guidance}
        />
      )}
    </section>
  );
}

