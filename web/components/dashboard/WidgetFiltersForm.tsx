"use client";

import { useId, useState } from "react";
import { ENTRY, type Group, type Widget, type WidgetFilters } from "@/lib/dashboard";
import type { AssetSummary, Portfolio } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";

/* A widget's own filters (plan §48.2): portfolios, projects, a tag, the period, and grouping. */

const PERIODS = [7, 30, 90, 180, 365];
const TAG = /^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,49}$/;

export function WidgetFiltersForm({
  widget,
  portfolios,
  projects,
  onApply,
  onCancel,
}: {
  widget: Widget;
  portfolios: Portfolio[];
  projects: AssetSummary[];
  onApply: (f: WidgetFilters) => void;
  onCancel: () => void;
}) {
  const id = useId();
  const entry = ENTRY[widget.metric];
  const f = widget.filters ?? {};
  const [chosenPortfolios, setPortfolios] = useState<string[]>(f.portfolios ?? []);
  const [chosenProjects, setProjects] = useState<string[]>(f.projects ?? []);
  const [tag, setTag] = useState(f.tag ?? "");
  const [days, setDays] = useState(f.days ? String(f.days) : "");
  const [group, setGroup] = useState<Group>(f.group ?? "band");
  const [error, setError] = useState<string | null>(null);
  const toggle = (list: string[], set: (v: string[]) => void, v: string) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  function apply(e: React.FormEvent) {
    e.preventDefault();
    const t = tag.trim();
    if (t && !TAG.test(t)) {
      setError("A tag is letters, digits, spaces and . _ : / -, up to 50 characters.");
      return;
    }
    const out: WidgetFilters = {};
    if (chosenPortfolios.length) out.portfolios = chosenPortfolios;
    if (chosenProjects.length) out.projects = chosenProjects;
    if (t) out.tag = t;
    if (entry?.periodic && days) out.days = Number(days);
    if (entry?.groups && group !== "band") out.group = group;
    onApply(out);
  }

  return (
    <form onSubmit={apply} className="dash-filter-form">
      <fieldset>
        <legend>Portfolios</legend>
        {portfolios.length === 0 && <p className="dash-muted">No portfolios yet.</p>}
        <div className="dash-checks">
          {portfolios.map((p) => (
            <label key={p.id}>
              <input type="checkbox" checked={chosenPortfolios.includes(p.id)}
                onChange={() => toggle(chosenPortfolios, setPortfolios, p.id)} /> {p.name}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset>
        <legend>Projects</legend>
        <div className="dash-checks dash-checks-scroll">
          {projects.map((p) => (
            <label key={p.id}>
              <input type="checkbox" checked={chosenProjects.includes(p.id)}
                onChange={() => toggle(chosenProjects, setProjects, p.id)} /> {p.label}
            </label>
          ))}
        </div>
      </fieldset>
      <p className="dash-muted dash-small">No portfolio or project chosen means all of them.</p>
      <label htmlFor={`${id}-tag`}>Tag</label>
      <input id={`${id}-tag`} value={tag} onChange={(e) => setTag(e.target.value)} maxLength={50}
        aria-invalid={error ? true : undefined} aria-describedby={error ? `${id}-err` : `${id}-tag-help`} />
      <p id={`${id}-tag-help`} className="dash-muted dash-small">Projects, portfolios and issues carrying this tag.</p>
      {error && <p id={`${id}-err`} role="alert" className="dash-error">{error}</p>}
      {entry?.periodic && (
        <>
          <label htmlFor={`${id}-days`}>Period</label>
          <select id={`${id}-days`} value={days} onChange={(e) => setDays(e.target.value)}>
            <option value="">The metric&apos;s default</option>
            {PERIODS.map((d) => <option key={d} value={d}>Last {d} days</option>)}
          </select>
        </>
      )}
      {entry?.groups && (
        <>
          <label htmlFor={`${id}-group`}>Group by</label>
          <select id={`${id}-group`} value={group} onChange={(e) => setGroup(e.target.value as Group)}>
            <option value="band">Priority</option>
            <option value="portfolio">Portfolio</option>
            <option value="project">Project</option>
          </select>
        </>
      )}
      <div className="dash-row">
        <Button type="submit" variant="primary">Apply</Button>
        <Button type="button" onClick={onCancel}>Cancel</Button>
      </div>
    </form>
  );
}
