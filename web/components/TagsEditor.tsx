"use client";

import { useCallback, useEffect, useId, useState } from "react";
import {
  ApiError, createPortfolio, getIssueTags, getProjectTags, listPortfolios, setIssueTags,
  setPortfolioTags, setProjectPortfolio, setProjectTags,
} from "@/lib/api";
import type { Portfolio, TagsView } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./collab.css";

/** Plan §49: tags inherit downward from portfolio to project to issue. A target's own tags are
 * edited here; inherited ones are shown with where they come from, and changed there. For a
 * project, also which portfolio it belongs to, and that portfolio's tags. */

function Chips({ own, onRemove, label }: { own: string[]; onRemove?: (t: string) => void; label: string }) {
  return (
    <ul className="ds-tags" aria-label={label}>
      {own.map((t) => (
        <li key={t} className="ds-tag">
          {t}
          {onRemove && (
            <button type="button" aria-label={`Remove tag ${t}`} onClick={() => onRemove(t)}>×</button>
          )}
        </li>
      ))}
    </ul>
  );
}

function AddTag({ onAdd, label }: { onAdd: (t: string) => void; label: string }) {
  const [v, setV] = useState("");
  return (
    <form className="ds-tag-add" onSubmit={(e) => { e.preventDefault(); if (v.trim()) { onAdd(v.trim()); setV(""); } }}>
      <input aria-label={label} value={v} onChange={(e) => setV(e.target.value)} placeholder="Add a tag" maxLength={50} />
      <Button type="submit" disabled={!v.trim()}>Add</Button>
    </form>
  );
}

export function TagsEditor({ kind, id }: { kind: "issue" | "project"; id: string }) {
  const fid = useId();
  const [view, setView] = useState<TagsView | null>(null);
  const [portfolios, setPortfolios] = useState<Portfolio[]>([]);
  const [newPortfolio, setNewPortfolio] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    // An unexpected response must not take the page down with it: the panel just stays away.
    (kind === "issue" ? getIssueTags(id) : getProjectTags(id)).then(
      (v) => setView(Array.isArray(v?.own) && Array.isArray(v?.inherited) ? v : null),
      () => setView(null),
    );
    if (kind === "project") listPortfolios().then((p) => setPortfolios(Array.isArray(p) ? p : []), () => setPortfolios([]));
  }, [kind, id]);
  useEffect(load, [load]);

  async function save(own: string[]) {
    setError(null);
    try {
      setView(await (kind === "issue" ? setIssueTags(id, own) : setProjectTags(id, own)));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save the tags.");
    }
  }

  async function choose(pid: string) {
    setError(null);
    try {
      setView(await setProjectPortfolio(id, pid || null));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not change the portfolio.");
    }
  }

  async function makePortfolio(e: React.FormEvent) {
    e.preventDefault();
    const name = newPortfolio.trim();
    if (!name) return;
    try {
      const p = await createPortfolio(name);
      setNewPortfolio("");
      setPortfolios((xs) => [...xs, p]);
      await choose(p.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the portfolio.");
    }
  }

  async function savePortfolioTags(p: Portfolio, tags: string[]) {
    try {
      const next = await setPortfolioTags(p.id, tags);
      setPortfolios((xs) => xs.map((x) => (x.id === p.id ? next : x)));
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save the portfolio's tags.");
    }
  }

  if (!view) return null;
  const current = portfolios.find((p) => p.id === view.portfolio?.id);

  return (
    <section className="ds-tags-panel" aria-labelledby={`${fid}-h`}>
      <div className="ds-issue-label" id={`${fid}-h`}>Tags</div>
      {error && <p role="alert" className="ds-rt-error">{error}</p>}
      <Chips own={view.own} label={kind === "issue" ? "This issue's tags" : "This project's tags"}
        onRemove={(t) => save(view.own.filter((x) => x !== t))} />
      <AddTag label={kind === "issue" ? "Add a tag to this issue" : "Add a tag to this project"} onAdd={(t) => save([...view.own, t])} />
      {view.inherited.length > 0 && (
        <p className="ds-rt-meta">
          Inherited:{" "}
          {view.inherited.map((t, i) => (
            <span key={t.name}>
              {i > 0 && ", "}
              <span className="ds-tag ds-tag-inherited">{t.name}</span> from {t.source} ({t.from})
            </span>
          ))}
        </p>
      )}
      {kind === "project" && (
        <div className="ds-tags-portfolio">
          <label htmlFor={`${fid}-p`} className="ds-rt-label">Portfolio</label>
          <select id={`${fid}-p`} value={view.portfolio?.id ?? ""} onChange={(e) => choose(e.target.value)}>
            <option value="">None</option>
            {portfolios.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <form className="ds-tag-add" onSubmit={makePortfolio}>
            <input aria-label="New portfolio name" value={newPortfolio} onChange={(e) => setNewPortfolio(e.target.value)} placeholder="New portfolio" maxLength={200} />
            <Button type="submit" disabled={!newPortfolio.trim()}>Create</Button>
          </form>
          {current && (
            <>
              <p className="ds-rt-meta">{current.name}&apos;s tags, inherited by every project in it:</p>
              <Chips own={current.tags} label={`${current.name} tags`} onRemove={(t) => savePortfolioTags(current, current.tags.filter((x) => x !== t))} />
              <AddTag label={`Add a tag to ${current.name}`} onAdd={(t) => savePortfolioTags(current, [...current.tags, t])} />
            </>
          )}
        </div>
      )}
    </section>
  );
}
