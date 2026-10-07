"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { ApiError, getMe, getTablePrefs, listIssueViews, searchIssues, setTablePrefs } from "@/lib/api";
import { QueryError, formatQuery, parse, type Query } from "@/lib/issue-query";
import {
  ALL_COLUMNS, COLUMN_LABEL, DEFAULT_COLUMNS, SORTS, chipsOf, countText, valueLabel,
  type BulkAction, type BulkResult, type Column, type Density, type IssueCount, type IssueRow, type SavedView, type Selection, type Sort,
} from "@/lib/issues";
import { SeverityIcon } from "@/design-system/severity";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { ACTION_TITLE, BulkDialog, UndoBar } from "./BulkActions";
import { FilterPanel } from "./FilterPanel";
import { QueryBar } from "./QueryBar";
import { ViewsPanel } from "./ViewsPanel";
import "./issues.css";

/* Every Issue in the organization, on one list (plan §56): the grouped filter panel and the query
 * bar say the same thing, and the address carries it, so any list can be bookmarked or shared.
 * Pages by cursor ("Show more"); a count that is exact, or "more than 10,000". Columns and density
 * are remembered per person; saved views carry a query, a sort and columns. Tick Issues, or select
 * every one matching, and change them together: previewed first, undoable for 10 seconds. */

const PAGE = 50;
const EMPTY: Query = { clauses: {}, text: [] };
type Picked = { all: false; ids: Set<string> } | { all: true };
const NONE: Picked = { all: false, ids: new Set() };

function safeParse(text: string): Query {
  try { return parse(text); } catch { return EMPTY; }
}

function day(iso: string | null): string {
  return iso ? iso.slice(0, 10) : "—";
}

const STATUS_TEXT: Record<string, string> = { open: "Open", accepted: "Accepted", not_a_risk: "Not a risk", fixed: "Fixed" };
const SLA_TEXT: Record<string, string> = { breached: "Past SLA", due_soon: "Due soon", on_track: "On track", met: "Fixed in time", missed: "Fixed late", exempt: "Paused", none: "—" };

function cell(c: Column, r: IssueRow) {
  switch (c) {
    case "project": return r.project;
    case "priority": return r.band ? <span className={`iss-band iss-band-${r.band}`}>{r.band}{r.score != null && <span className="iss-muted"> {r.score}</span>}</span> : "—";
    case "severity": return <span className="iss-sev"><SeverityIcon severity={r.severity as "critical"} size={14} /> {valueLabel(r.severity)}</span>;
    case "status": return STATUS_TEXT[r.status] ?? r.status;
    case "sla": return <span className={`iss-sla iss-sla-${r.sla.state}`}>{SLA_TEXT[r.sla.state] ?? r.sla.state}</span>;
    case "assignee": return r.assignee_name ?? <span className="iss-muted">Nobody</span>;
    case "path": return <code className="iss-path">{r.path}</code>;
    case "category": return valueLabel(r.category);
    case "source": return r.source;
    case "retest": return r.retest ? valueLabel(r.retest) : "—";
    case "first_seen": return day(r.first_seen_at);
    case "last_seen": return day(r.last_seen_at);
    case "fixed": return day(r.fixed_at);
  }
}

export function IssuesScreen({ initialQuery, initialSort, initialView }: { initialQuery: string; initialSort: string; initialView: string }) {
  const id = useId();
  const [text, setText] = useState(initialQuery);
  const [query, setQuery] = useState<Query>(() => safeParse(initialQuery));
  const [qError, setQError] = useState<{ message: string; start: number; end: number } | null>(null);
  const [applied, setApplied] = useState(() => formatQuery(safeParse(initialQuery)));
  const [sort, setSort] = useState<Sort>(SORTS.some(([s]) => s === initialSort) ? (initialSort as Sort) : "priority");
  const [rows, setRows] = useState<IssueRow[]>([]);
  const [count, setCount] = useState<IssueCount | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Picked>(NONE);
  const [action, setAction] = useState<BulkAction | null>(null);
  const [result, setResult] = useState<BulkResult | null>(null);
  const [said, setSaid] = useState("");
  const [columns, setColumns] = useState<Column[]>(DEFAULT_COLUMNS);
  const [density, setDensity] = useState<Density>("comfortable");
  const [choosing, setChoosing] = useState(false);
  const [views, setViews] = useState<SavedView[]>([]);
  const [view, setView] = useState<SavedView | null>(null);
  const [me, setMe] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);
  const wantView = useRef(initialView);
  const generation = useRef(0);

  // The address carries the list: ?q=&sort=&view=
  useEffect(() => {
    const p = new URLSearchParams();
    if (applied) p.set("q", applied);
    if (sort !== "priority") p.set("sort", sort);
    if (view) p.set("view", view.id);
    const qs = p.toString();
    window.history.replaceState(window.history.state, "", `${window.location.pathname}${qs ? `?${qs}` : ""}`);
  }, [applied, sort, view]);

  const load = useCallback(async (after: string | null) => {
    const g = ++generation.current;
    setLoading(true); setError(null);
    const p = new URLSearchParams({ q: applied, sort, limit: String(PAGE) });
    if (after) { p.set("after", after); p.set("count", "false"); }
    try {
      const page = await searchIssues(p);
      if (g !== generation.current) return;
      setRows((cur) => (after ? [...cur, ...page.rows] : page.rows));
      setNext(page.next);
      if (!after) setCount(page.count);
    } catch (e) {
      if (g !== generation.current) return;
      setError(e instanceof ApiError ? (e.data as { message?: string } | undefined)?.message ?? e.message : "Could not load the Issues.");
    } finally {
      if (g === generation.current) setLoading(false);
    }
  }, [applied, sort]);

  useEffect(() => { setPicked(NONE); void load(null); }, [load]);

  const refreshViews = useCallback((open?: SavedView | null) => {
    listIssueViews().then((list) => {
      setViews(list);
      if (open !== undefined) setView(open ? list.find((v) => v.id === open.id) ?? open : null);
      else if (wantView.current) {
        const v = list.find((x) => x.id === wantView.current);
        if (v) setOpening(v);
        wantView.current = "";
      }
    }, () => setViews([]));
  }, []);

  useEffect(() => {
    refreshViews();
    getMe().then((m) => setMe(m.actor), () => setMe(null));
    getTablePrefs("issues").then((p) => { setColumns(p.columns); setDensity(p.density); }, () => undefined);
  }, [refreshViews]);

  // Both ways: the panel writes the query; the query, once it reads, fills the panel.
  const fromPanel = (q: Query) => {
    setQuery(q); setQError(null);
    const t = formatQuery(q);
    setText(t); setApplied(t);
  };
  const typed = (t: string) => {
    setText(t);
    try { setQuery(parse(t)); setQError(null); }
    catch (e) { if (e instanceof QueryError) setQError({ message: e.message, start: e.start, end: e.end }); }
  };
  const submit = () => {
    try { const q = parse(text); setQuery(q); setQError(null); setApplied(formatQuery(q)); }
    catch (e) { if (e instanceof QueryError) setQError({ message: e.message, start: e.start, end: e.end }); }
  };
  // Typing settles: run the query a moment later if it reads.
  useEffect(() => {
    if (qError) return;
    const t = setTimeout(() => { const f = formatQuery(query); if (f !== applied) setApplied(f); }, 600);
    return () => clearTimeout(t);
  }, [query, qError, applied]);

  // A link naming a view: open it with its filters, unless the link carries filters of its own.
  const [opening, setOpening] = useState<SavedView | null>(null);
  useEffect(() => {
    if (!opening) return;
    if (initialQuery) setView(opening);
    else openView(opening);
    setOpening(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opening]);

  const openView = (v: SavedView | null) => {
    setView(v);
    if (!v) return;
    fromPanel(safeParse(v.query));
    setSort(v.sort);
    if (v.columns?.length) setColumns(v.columns);
  };

  async function chooseColumns(cols: Column[], dens: Density) {
    setColumns(cols); setDensity(dens);
    try { await setTablePrefs("issues", { columns: cols, density: dens }); } catch { /* still applied here */ }
  }

  const chips = useMemo(() => chipsOf(query), [query]);
  const total = count?.value ?? rows.length;
  const pageIds = rows.map((r) => r.id);
  const ticked = picked.all ? total : picked.ids.size;
  const allOnPage = !picked.all && rows.length > 0 && pageIds.every((i) => picked.ids.has(i));
  const selection: Selection = picked.all ? { q: applied } : { q: applied, ids: [...picked.ids] };
  const selectedText = picked.all ? `all ${countText(count)} matching` : `${picked.ids.size} selected`;
  const toggle = (rid: string) => setPicked((p) => {
    if (p.all) return p;
    const ids = new Set(p.ids);
    if (ids.has(rid)) ids.delete(rid); else ids.add(rid);
    return { all: false, ids };
  });

  return (
    <div className={`iss iss-${density}`}>
      <div className="iss-layout">
        <aside className="iss-side" aria-label="Filters and saved views">
          <button type="button" className="iss-side-toggle ds-button" aria-expanded={panelOpen} aria-controls={`${id}-side`} onClick={() => setPanelOpen((o) => !o)}>
            Filters{chips.length ? ` (${chips.length} active)` : ""} and views
          </button>
          <div id={`${id}-side`} className={panelOpen ? "iss-side-body open" : "iss-side-body"}>
            <ViewsPanel views={views} active={view} me={me} current={{ query: applied, sort, columns }}
              onOpen={openView} onChanged={(_, open) => refreshViews(open)} />
            <FilterPanel q={query} onChange={fromPanel} />
          </div>
        </aside>

        <div className="iss-main">
          <QueryBar value={text} error={qError} onChange={typed} onSubmit={submit} />

          {chips.length > 0 && (
            <ul className="iss-chips" aria-label="Active filters">
              {chips.map((c) => (
                <li key={c.id}>
                  <span>{c.label}</span>
                  <button type="button" onClick={() => fromPanel(c.remove(query))} aria-label={`Remove filter ${c.label}`}>×</button>
                </li>
              ))}
              <li><button type="button" className="iss-clear" onClick={() => fromPanel(EMPTY)}>Clear all</button></li>
            </ul>
          )}

          <div className="iss-toolbar">
            <p className="iss-total" role="status" aria-live="polite">
              {loading && !rows.length ? "Loading…" : count ? <><strong>{countText(count)}</strong> Issue{count.value === 1 && !count.at_least ? "" : "s"}{view ? <> · <span className="iss-muted">view “{view.name}”</span></> : null}</> : null}
            </p>
            <label htmlFor={`${id}-sort`} className="iss-label">Sort</label>
            <select id={`${id}-sort`} value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              {SORTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
            <Button type="button" onClick={() => setChoosing(true)}>Columns</Button>
          </div>

          {ticked > 0 && (
            <div className="iss-bulkbar" role="toolbar" aria-label="Change the selected Issues">
              <span className="iss-picked">{picked.all ? <>All <strong>{countText(count)}</strong> matching selected</> : <><strong>{picked.ids.size}</strong> selected</>}</span>
              {(["assign", "not_a_risk", "reopen", "tag", "untag", "accept"] as BulkAction[]).map((a) => (
                <Button key={a} type="button" onClick={() => setAction(a)}>{ACTION_TITLE[a]}</Button>
              ))}
              <Button type="button" onClick={() => setPicked(NONE)}>Clear selection</Button>
            </div>
          )}
          {allOnPage && total > rows.length && (
            <p className="iss-selectall">
              All {rows.length} on this page are selected.{" "}
              <button type="button" className="iss-link" onClick={() => setPicked({ all: true })}>Select all {countText(count)} matching</button>
            </p>
          )}
          {picked.all && (
            <p className="iss-selectall">
              Every Issue matching the filters is selected, on every page.{" "}
              <button type="button" className="iss-link" onClick={() => setPicked(NONE)}>Clear selection</button>
            </p>
          )}

          {result && <UndoBar result={result} onDismiss={() => setResult(null)} onUndone={(s) => { setResult(null); setSaid(s); void load(null); }} />}
          {said && !result && <p role="status" className="iss-said">{said}</p>}
          {error && <p role="alert" className="iss-error">{error}</p>}

          {!error && !loading && rows.length === 0 && (
            <p className="iss-empty">No Issues match. {chips.length > 0 && <button type="button" className="iss-link" onClick={() => fromPanel(EMPTY)}>Clear the filters</button>}</p>
          )}

          {rows.length > 0 && (
            <div className="iss-scroll" tabIndex={0} role="region" aria-label="Issues table">
              <table className="iss-table">
                <caption className="sr-only">Issues{count ? `, ${countText(count)} in all` : ""}</caption>
                <thead>
                  <tr>
                    <th scope="col" className="iss-pick">
                      <input type="checkbox" aria-label="Select every Issue on this page" checked={picked.all || allOnPage}
                        disabled={picked.all}
                        onChange={(e) => setPicked(e.target.checked ? { all: false, ids: new Set(pageIds) } : NONE)} />
                    </th>
                    <th scope="col">Issue</th>
                    {columns.map((c) => <th key={c} scope="col">{COLUMN_LABEL[c]}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className={!picked.all && picked.ids.has(r.id) ? "picked" : undefined}>
                      <td className="iss-pick">
                        <input type="checkbox" aria-label={`Select ${r.title}`} checked={picked.all || picked.ids.has(r.id)}
                          disabled={picked.all} onChange={() => toggle(r.id)} />
                      </td>
                      <th scope="row" className="iss-title">
                        <Link href={`/app/projects/${r.project_id}/issues/${r.id}`}>{r.title}</Link>
                      </th>
                      {columns.map((c) => <td key={c} className={`iss-c-${c}`}>{cell(c, r)}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {next && (
            <div className="iss-more">
              <Button type="button" onClick={() => load(next)} disabled={loading}>{loading ? "Loading…" : `Show ${PAGE} more`}</Button>
              <span className="iss-muted">Showing {rows.length.toLocaleString("en-US")} of {countText(count)}</span>
            </div>
          )}
        </div>
      </div>

      <BulkDialog action={action} selection={selection} selectedText={selectedText} onClose={() => setAction(null)}
        onDone={(r) => { setAction(null); setResult(r); setSaid(""); setPicked(NONE); void load(null); }} />
      <ColumnsDialog open={choosing} columns={columns} density={density} onClose={() => setChoosing(false)}
        onApply={(c, d) => { setChoosing(false); void chooseColumns(c, d); }} />
    </div>
  );
}

function ColumnsDialog({ open, columns, density, onClose, onApply }: {
  open: boolean; columns: Column[]; density: Density; onClose: () => void; onApply: (c: Column[], d: Density) => void;
}) {
  const id = useId();
  const [cols, setCols] = useState(columns);
  const [dens, setDens] = useState(density);
  useEffect(() => { if (open) { setCols(columns); setDens(density); } }, [open, columns, density]);
  const order = [...cols, ...ALL_COLUMNS.filter((c) => !cols.includes(c))];
  const move = (c: Column, by: number) => setCols((cur) => {
    const i = cur.indexOf(c); const j = i + by;
    if (i < 0 || j < 0 || j >= cur.length) return cur;
    const n = [...cur]; [n[i], n[j]] = [n[j]!, n[i]!]; return n;
  });
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} title="Columns and density" description="Remembered for you, on any device. The title is always shown.">
      <ul className="iss-colpick">
        {order.map((c) => {
          const on = cols.includes(c);
          return (
            <li key={c}>
              <label className="iss-check">
                <input type="checkbox" checked={on} onChange={(e) => setCols((cur) => (e.target.checked ? [...cur, c] : cur.filter((x) => x !== c)))} />
                {COLUMN_LABEL[c]}
              </label>
              {on && (
                <span className="iss-move">
                  <button type="button" className="ds-button" onClick={() => move(c, -1)} disabled={cols.indexOf(c) === 0} aria-label={`Move ${COLUMN_LABEL[c]} left`}>←</button>
                  <button type="button" className="ds-button" onClick={() => move(c, 1)} disabled={cols.indexOf(c) === cols.length - 1} aria-label={`Move ${COLUMN_LABEL[c]} right`}>→</button>
                </span>
              )}
            </li>
          );
        })}
      </ul>
      <fieldset className="iss-values">
        <legend className="iss-label">Density</legend>
        {(["comfortable", "compact"] as Density[]).map((d) => (
          <label key={d} className="iss-check">
            <input type="radio" name={`${id}-dens`} checked={dens === d} onChange={() => setDens(d)} />
            {d === "comfortable" ? "Comfortable" : "Compact"}
          </label>
        ))}
      </fieldset>
      <div className="iss-actions">
        <Button type="button" variant="primary" disabled={!cols.length} onClick={() => onApply(cols, dens)}>Apply</Button>
        <Button type="button" onClick={onClose}>Cancel</Button>
      </div>
    </Dialog>
  );
}
