"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, getUnitOverview, listUnitOverviews } from "@/lib/api";
import { ago, drillHref, type UnitOverview, type UnitProject, type UnitSummary } from "@/lib/dashboard";
import { Loading } from "@/design-system/primitives/Loading";
import "../dashboard/dashboard.css";
import "./home.css";

/* The portfolio overview (plan §55.6): the sentence first -- what needs attention and why,
 * including the project nobody has scanned -- then the projects, the neediest first. */

const NEED_WORD: Record<UnitProject["needs"][number], string> = {
  past_sla: "Past SLA",
  new_advisory: "New advisory",
  not_scanned: "Not scanned lately",
};
const ON_TRACK_SHOWN = 4;

export function Trend({ values, label }: { values: number[]; label: string }) {
  const max = Math.max(1, ...values);
  const w = 60;
  const h = 18;
  const step = values.length > 1 ? w / (values.length - 1) : w;
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(" ");
  const first = values[0] ?? 0;
  const last = values[values.length - 1] ?? 0;
  const word = last > first ? "up" : last < first ? "down" : "flat";
  return (
    <svg className="home-trend" viewBox={`0 0 ${w} ${h}`} role="img"
      aria-label={`${label}: ${word}, from ${first} to ${last} over ${values.length} weeks`}>
      <polyline points={pts} className="dash-line" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export function ProjectsByNeed({ unit }: { unit: UnitOverview }) {
  const [all, setAll] = useState(false);
  const needy = unit.projects.filter((p) => p.needs.length);
  const fine = unit.projects.filter((p) => !p.needs.length);
  const keep = Math.max(0, ON_TRACK_SHOWN - needy.length);
  const shown = all ? unit.projects : [...needy, ...fine.slice(0, keep)];
  const hidden = unit.projects.length - shown.length;
  const scope = unit.id === "none" ? {} : { portfolios: [unit.id] };
  return (
    <div>
      {/* Scrolls sideways on a phone; focusable so the keyboard can scroll it too. */}
      <div className="dash-table-wrap home-units-wrap" tabIndex={0} role="region" aria-label={`Projects in ${unit.name}`}>
      <table className="dash-table home-units">
        <caption>Projects in {unit.name}, the ones needing attention first</caption>
        <thead>
          <tr>
            <th scope="col">Project</th>
            <th scope="col" className="num">Open P1</th>
            <th scope="col" className="num">Past SLA</th>
            <th scope="col">Last scan</th>
            <th scope="col">Scanners</th>
            <th scope="col">Trend</th>
            <th scope="col">Needs</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((p) => (
            <tr key={p.asset}>
              <th scope="row"><Link href={`/app/projects/${encodeURIComponent(p.asset)}`}>{p.label}</Link></th>
              <td className="num">
                {p.open_p1 ? (
                  <Link href={drillHref({ kind: "open", band: "P1", project: p.asset }, scope, `Open P1, ${p.label}`, p.open_p1)}
                    aria-label={`${p.open_p1} open P1 in ${p.label}`}>{p.open_p1}</Link>
                ) : 0}
              </td>
              <td className="num">
                {p.past_sla ? (
                  <Link href={drillHref({ kind: "past_sla", project: p.asset }, scope, `Past SLA, ${p.label}`, p.past_sla)}
                    aria-label={`${p.past_sla} past SLA in ${p.label}`}>{p.past_sla}</Link>
                ) : 0}
              </td>
              <td>{p.last_scan_at ? ago(p.last_scan_at) : "Never"}</td>
              <td>{p.scanners_applicable ? `${p.scanners_ok} of ${p.scanners_applicable}` : "—"}</td>
              <td><Trend values={p.trend} label={`Unfixed issues in ${p.label}`} /></td>
              <td>
                {p.needs.length ? p.needs.map((n) => NEED_WORD[n]).join(", ") : <span className="dash-muted">On track</span>}
                {p.new_advisories.length > 0 && (
                  <> ({p.new_advisories.map((k, i) => (
                    <span key={k}>{i > 0 && ", "}<Link href={`/app/advisories/${encodeURIComponent(k)}`}>{k}</Link></span>
                  ))})</>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      {hidden > 0 && (
        <p className="home-more">
          {hidden} more, on track.{" "}
          <button type="button" className="ds-button" onClick={() => setAll(true)}>Show all {unit.projects.length}</button>
        </p>
      )}
      <p className="dash-muted dash-small">
        Scanners: the scanner runs that worked in the last full scan, of those that apply to the project&apos;s files. Trend:
        issues found and not yet fixed at the end of each of the last {unit.trend_weeks} weeks. Not scanned lately: no
        successful full scan in {unit.stale_days} days.
      </p>
    </div>
  );
}

export function UnitOverviewScreen({ id }: { id: string }) {
  const [unit, setUnit] = useState<UnitOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    getUnitOverview(id).then(setUnit, (e) => setError(e instanceof ApiError ? e.message : "Could not load this business unit."));
  }, [id]);
  if (error) return <p role="alert" className="dash-error">{error}</p>;
  if (!unit) return <Loading />;
  return (
    <div className="dash">
      <span className="eyebrow">Business unit</span>
      <h1>{unit.name}</h1>
      <p className="dash-muted">{unit.projects.length} project{unit.projects.length === 1 ? "" : "s"}</p>
      <p className={unit.needs_attention ? "home-verdict needs" : "home-verdict"}>{unit.verdict}</p>
      <ProjectsByNeed unit={unit} />
    </div>
  );
}

export function UnitList({ heading = "Business units", level = 1 }: { heading?: string; level?: 1 | 2 }) {
  const [units, setUnits] = useState<UnitSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    listUnitOverviews().then(setUnits, (e) => setError(e instanceof ApiError ? e.message : "Could not load business units."));
  }, []);
  const H = level === 1 ? "h1" : "h2";
  return (
    <section className="home-section" aria-labelledby="units-heading">
      <H id="units-heading">{heading}</H>
      {error && <p role="alert" className="dash-error">{error}</p>}
      {!units && !error && <Loading />}
      {units?.length === 0 && <p className="dash-muted">No projects yet.</p>}
      {units && units.length > 0 && (
        <ul className="home-units-list">
          {units.map((u) => (
            <li key={u.id} className={u.needs_attention ? "needs" : undefined}>
              <Link href={`/app/portfolios/${encodeURIComponent(u.id)}`} className="home-unit-name">{u.name}</Link>
              <span className="dash-muted"> · {u.projects} project{u.projects === 1 ? "" : "s"}</span>
              <p>{u.verdict}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
