"use client";

import Link from "next/link";
import { useEffect, useId, useMemo, useState } from "react";
import { ApiError, getCalendar, listAssets } from "@/lib/api";
import type { AssetSummary, CalendarEntry, CalendarKind, CalendarView } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./calendar.css";

/** Plan §49: "a calendar of engagements, SLA due dates, and expiring risk acceptances". A month,
 * Monday first, in UTC days -- the days the server counts deadlines in -- with the same entries as a
 * list beneath, which is all a phone shows. */

const KIND_WORD: Record<CalendarKind, string> = { engagement: "Engagements", sla: "SLA due dates", acceptance: "Risk acceptances" };
const ONE: Record<CalendarKind, string> = { engagement: "Engagement", sla: "SLA", acceptance: "Acceptance" };
const KINDS: CalendarKind[] = ["engagement", "sla", "acceptance"];
const PER_DAY = 3;

const iso = (d: Date) => d.toISOString().slice(0, 10);
const utc = (y: number, m: number, d: number) => new Date(Date.UTC(y, m, d));
const addDays = (d: Date, n: number) => utc(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + n);

/** The weeks shown for a month: from the Monday on or before the 1st to the Sunday on or after the
 * last day. */
export function monthGrid(year: number, month: number): Date[] {
  const first = utc(year, month, 1);
  const start = addDays(first, -((first.getUTCDay() + 6) % 7));
  const last = utc(year, month + 1, 0);
  const end = addDays(last, (7 - last.getUTCDay()) % 7);
  const days: Date[] = [];
  for (let d = start; d <= end; d = addDays(d, 1)) days.push(d);
  return days;
}

/** Entries on a day: SLA dates and expiries on their day, an engagement on every day it spans. */
export function onDay(entries: CalendarEntry[], day: string): CalendarEntry[] {
  return entries.filter((e) => e.start <= day && day <= e.end);
}

/** The list beneath names an engagement once: on its first day, or on the month's first day with
 * entries if it began before the month. */
export function agendaFor(entries: CalendarEntry[], day: string, monthStart: string, firstDay: string): CalendarEntry[] {
  return onDay(entries, day).filter((e) => e.kind !== "engagement" || e.start === day || (e.start < monthStart && day === firstDay));
}

export function calendarVerdict(view: CalendarView, today: string): string {
  const breached = view.entries.filter((e) => e.kind === "sla" && e.state === "breached").length;
  const dueSoon = view.entries.filter((e) => e.kind === "sla" && e.state !== "breached" && e.start >= today).length;
  const expiring = view.entries.filter((e) => e.kind === "acceptance" && e.start >= today).length;
  const parts = [];
  if (breached) parts.push(`${breached} SLA${breached === 1 ? "" : "s"} already breached`);
  if (dueSoon) parts.push(`${dueSoon} still to fall due`);
  if (expiring) parts.push(`${expiring} risk acceptance${expiring === 1 ? "" : "s"} expiring`);
  return parts.length ? `This month: ${parts.join(", ")}.` : "Nothing falls due this month.";
}

const monthName = (y: number, m: number) => utc(y, m, 1).toLocaleDateString(undefined, { month: "long", year: "numeric", timeZone: "UTC" });
const dayLabel = (day: string) => utc(Number(day.slice(0, 4)), Number(day.slice(5, 7)) - 1, Number(day.slice(8, 10)))
  .toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" });

function Chip({ e }: { e: CalendarEntry }) {
  const cls = `ds-cal-chip ds-cal-${e.kind}${e.state === "breached" ? " ds-cal-breached" : ""}`;
  return (
    <Link href={e.link} className={cls} title={`${ONE[e.kind]}: ${e.title} (${e.project}) · ${e.detail}`}>
      <span className="ds-cal-kind">{ONE[e.kind]}</span> {e.title}
    </Link>
  );
}

export function CalendarScreen({ initial }: { initial?: { year: number; month: number } }) {
  const fid = useId();
  const now = new Date();
  const today = iso(utc(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const [ym, setYm] = useState(initial ?? { year: now.getUTCFullYear(), month: now.getUTCMonth() });
  const [kinds, setKinds] = useState<CalendarKind[]>(KINDS);
  const [project, setProject] = useState("");
  const [projects, setProjects] = useState<AssetSummary[]>([]);
  const [view, setView] = useState<CalendarView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const days = useMemo(() => monthGrid(ym.year, ym.month), [ym]);

  useEffect(() => {
    listAssets().then((a) => setProjects(Array.isArray(a) ? a : []), () => setProjects([]));
  }, []);
  useEffect(() => {
    setError(null);
    if (!kinds.length) { setView({ start: "", end: "", entries: [], counts: { engagement: 0, sla: 0, acceptance: 0 }, truncated: [] }); return; }
    getCalendar(iso(days[0]!), iso(days[days.length - 1]!), { projectId: project || undefined, kinds }).then(
      (v) => setView(Array.isArray(v?.entries) ? v : null),
      (e) => setError(e instanceof ApiError ? e.message : "Could not load the calendar."),
    );
  }, [days, kinds, project]);

  const move = (n: number) => setYm(({ year, month }) => {
    const d = utc(year, month + n, 1);
    return { year: d.getUTCFullYear(), month: d.getUTCMonth() };
  });
  const inMonth = (d: Date) => d.getUTCMonth() === ym.month;
  const monthEntries = (view?.entries ?? []).filter((e) => e.end >= iso(utc(ym.year, ym.month, 1)) && e.start <= iso(utc(ym.year, ym.month + 1, 0)));
  const monthStart = iso(utc(ym.year, ym.month, 1));
  const firstDay = Array.from(new Set(days.filter(inMonth).map(iso))).find((d) => onDay(monthEntries, d).length) ?? monthStart;
  const agendaDays = Array.from(new Set(days.filter(inMonth).map(iso))).filter((d) => agendaFor(monthEntries, d, monthStart, firstDay).length);

  return (
    <div className="ds-cal">
      <div className="ds-cal-top">
        <h1>Calendar</h1>
        <div className="ds-cal-nav" role="group" aria-label="Month">
          <Button onClick={() => move(-1)} aria-label="Previous month">‹</Button>
          <h2 className="ds-cal-month" aria-live="polite">{monthName(ym.year, ym.month)}</h2>
          <Button onClick={() => move(1)} aria-label="Next month">›</Button>
          <Button onClick={() => setYm({ year: now.getUTCFullYear(), month: now.getUTCMonth() })}>Today</Button>
        </div>
      </div>
      <div className="ds-cal-filters">
        <fieldset className="ds-cal-kinds">
          <legend className="ds-cal-legend">Show</legend>
          {KINDS.map((k) => (
            <label key={k} className={`ds-cal-toggle ds-cal-${k}`}>
              <input type="checkbox" checked={kinds.includes(k)} onChange={(e) => setKinds(e.target.checked ? KINDS.filter((x) => x === k || kinds.includes(x)) : kinds.filter((x) => x !== k))} />
              {KIND_WORD[k]}{view ? ` (${view.counts[k] ?? 0})` : ""}
            </label>
          ))}
        </fieldset>
        <label htmlFor={`${fid}-project`} className="ds-cal-legend">Project</label>
        <select id={`${fid}-project`} className="ds-cal-select" value={project} onChange={(e) => setProject(e.target.value)}>
          <option value="">Every project</option>
          {projects.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
      </div>
      {error && <p role="alert" className="ds-cal-error">{error}</p>}
      {view && <p className="ds-cal-verdict">{calendarVerdict({ ...view, entries: monthEntries }, today)}</p>}
      {view && view.truncated.length > 0 && (
        <p className="ds-cal-meta">Showing the first 5,000 SLA dates for {view.truncated.join(", ")}; filter by project to see them all.</p>
      )}
      <p className="ds-cal-meta">Days are UTC, the days deadlines are counted in.</p>

      <table className="ds-cal-grid">
        <caption className="ds-cal-caption">{monthName(ym.year, ym.month)}</caption>
        <thead>
          <tr>{["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => <th key={d} scope="col">{d}</th>)}</tr>
        </thead>
        <tbody>
          {Array.from({ length: days.length / 7 }, (_, w) => (
            <tr key={w}>
              {days.slice(w * 7, w * 7 + 7).map((d) => {
                const day = iso(d);
                const items = onDay(view?.entries ?? [], day);
                return (
                  <td key={day} className={`${inMonth(d) ? "" : "ds-cal-out"}${day === today ? " ds-cal-today" : ""}`}>
                    <div className="ds-cal-date">
                      {day === today ? <span aria-label={`Today, ${dayLabel(day)}`}>{d.getUTCDate()}</span> : d.getUTCDate()}
                    </div>
                    {items.slice(0, PER_DAY).map((e, i) => <Chip key={`${e.kind}-${e.link}-${i}`} e={e} />)}
                    {items.length > PER_DAY && <span className="ds-cal-more">+{items.length - PER_DAY} more</span>}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>

      <section aria-labelledby={`${fid}-agenda`} className="ds-cal-agenda">
        <h2 id={`${fid}-agenda`}>Day by day</h2>
        {view && agendaDays.length === 0 && <p>Nothing this month.</p>}
        <ol className="ds-cal-days">
          {agendaDays.map((day) => (
            <li key={day}>
              <h3 className={day === today ? "ds-cal-today-h" : undefined}>{dayLabel(day)}{day === today ? " (today)" : ""}</h3>
              <ul className="ds-cal-list">
                {agendaFor(monthEntries, day, monthStart, firstDay).map((e, i) => (
                  <li key={`${e.kind}-${e.link}-${i}`}>
                    <Link href={e.link}><span className={`ds-cal-tag ds-cal-${e.kind}${e.state === "breached" ? " ds-cal-breached" : ""}`}>{ONE[e.kind]}</span> {e.title}</Link>
                    <span className="ds-cal-meta"> · {e.project} · {e.detail}{e.kind === "engagement" && e.start !== e.end ? ` (${dayLabel(e.start)} to ${dayLabel(e.end)})` : ""}</span>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
