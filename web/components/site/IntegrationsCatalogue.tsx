"use client";

import { useMemo, useState } from "react";
import {
  CATEGORY_LABELS,
  DEDUP_LABELS,
  INTEGRATIONS,
  KIND_LABELS,
  KINDS,
  MODE_LABELS,
  filterIntegrations,
  groupCount,
  type Integration,
  type Kind,
} from "@/lib/catalogue";

function Card({ i }: { i: Integration }) {
  return (
    <li className="card">
      <h3>{i.name}</h3>
      <div className="meta">
        {(i.categories ?? []).map((c) => <span key={c} className="chip">{CATEGORY_LABELS[c] ?? c}</span>)}
        {i.mode && <span className="chip">{MODE_LABELS[i.mode] ?? i.mode}</span>}
        {i.version && <span className="chip">{i.version}</span>}
        {(i.formats ?? []).map((f) => <span key={f} className="chip">.{f}</span>)}
        {i.direction && <span className="chip">{i.direction === "pull" ? "Pulls in" : "Pushes out"}</span>}
        {i.ported_from_defectdojo && <span className="chip">Ported from DefectDojo</span>}
      </div>
      <p>{i.how}</p>
      {(i.languages ?? []).length > 0 && <p className="perm">Languages: {i.languages!.join(", ")}</p>}
      {i.dedup && <p className="perm">Matched by default on {DEDUP_LABELS[i.dedup] ?? i.dedup}.</p>}
      {i.permissions && <p className="perm">Needs: {i.permissions}</p>}
    </li>
  );
}

// The catalogue itself is generated from the code (scripts/gen-integrations.py); this only filters it.
export function IntegrationsCatalogue() {
  const [kind, setKind] = useState<Kind | "all">("all");
  const [category, setCategory] = useState("");
  const [query, setQuery] = useState("");
  const shown = useMemo(() => filterIntegrations(INTEGRATIONS, kind, category, query), [kind, category, query]);
  const groups = KINDS.filter((k) => kind === "all" || k === kind)
    .map((k) => ({ kind: k, items: shown.filter((i) => i.kind === k) }))
    .filter((g) => g.items.length > 0);

  return (
    <>
      <div className="cat-filters" role="search" aria-label="Filter integrations">
        <label className="inline">
          Kind
          <select value={kind} onChange={(e) => setKind(e.target.value as Kind | "all")}>
            <option value="all">All</option>
            {KINDS.map((k) => <option key={k} value={k}>{KIND_LABELS[k]}</option>)}
          </select>
        </label>
        <label className="inline">
          Finds
          <select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">Anything</option>
            {Object.entries(CATEGORY_LABELS).map(([c, label]) => <option key={c} value={c}>{label}</option>)}
          </select>
        </label>
        <label className="inline grow">
          Search
          <input type="search" placeholder="nessus, sarif, jira, python…" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
      </div>
      <p className="cat-count small muted" role="status">
        {shown.length === INTEGRATIONS.length ? `${shown.length} integrations` : `${shown.length} of ${INTEGRATIONS.length} integrations`}
      </p>
      {groups.map((g) => (
        <section key={g.kind} className="cat-group" aria-labelledby={`cat-${g.kind}`}>
          <h2 id={`cat-${g.kind}`}>{KIND_LABELS[g.kind]} <span className="muted">· {groupCount(g.kind, g.items)}</span></h2>
          <ul className="cards">{g.items.map((i) => <Card key={i.id} i={i} />)}</ul>
        </section>
      ))}
      {groups.length === 0 && (
        <div className="f-empty">
          <p className="muted">Nothing matches. Any JSON, CSV or XML report can still come in through the universal mapper.</p>
          <button type="button" className="btn sm" onClick={() => { setKind("all"); setCategory(""); setQuery(""); }}>Clear filters</button>
        </div>
      )}
    </>
  );
}
