/* Dashboards (plan §48.2, §55.4): the widget catalogue, the grid and its keyboard alternative, and
 * how a widget's filters and a number's drill-down become the URLs the metrics API reads.
 * Pure functions, so the rules are tested without a browser. */
import { verticalCompactor } from "react-grid-layout/core";
import type { Layout, LayoutItem } from "react-grid-layout";

export const COLS = 12;
export const ROLES = ["lead", "engineer", "tester"] as const;
export type Role = (typeof ROLES)[number];
export const ROLE_LABEL: Record<Role, string> = { lead: "Leads", engineer: "Engineers", tester: "Testers" };

export type Group = "band" | "portfolio" | "project";
export interface WidgetFilters {
  portfolios?: string[];
  projects?: string[];
  tag?: string;
  days?: number;
  group?: Group;
}
export interface Widget {
  id: string;
  metric: string;
  x: number;
  y: number;
  w: number;
  h: number;
  filters?: WidgetFilters;
}
export interface Dashboard {
  id: string;
  name: string;
  owner: string | null;
  shared_with: Role[];
  widgets: Widget[];
  version: number;
  updated_at: string | null;
  updated_by: string | null;
  builtin: boolean;
  can_edit: boolean;
}
export interface DashboardList {
  role: Role | null;
  dashboards: Dashboard[];
}
export interface Me {
  actor: string;
  person: boolean;
  role: Role | null;
  roles: Role[];
}

export interface Drill {
  kind: "open" | "past_sla" | "opened" | "fixed";
  band?: string;
  portfolio?: string;
  project?: string;
  older_than?: number;
}
export type Row = Record<string, unknown> & { drill?: Drill };
export interface MetricResult {
  metric: string;
  name: string;
  definition: string;
  unit: string;
  generated_at: string;
  pending_refresh: number;
  notes: string[];
  value: number | null;
  counts: Record<string, number>;
  rows?: Row[];
  series?: Row[];
  period?: [string, string];
  drill?: Record<string, Drill>;
  days?: number;
}
export interface MetricIssue {
  id: string;
  project_id: string;
  project: string;
  title: string;
  severity: string;
  band: string | null;
  state: string;
  first_seen_at: string | null;
  fixed_at: string | null;
  assignee: string | null;
  assignee_name: string | null;
}

/** What each metric looks like as a widget. `chart` widgets get View as table; list widgets are
 * tables already. `periodic` metrics take the last-N-days filter; `groups` ones can group. */
export interface CatalogueEntry {
  metric: string;
  title: string;
  chart: boolean;
  periodic: boolean;
  groups: boolean;
  w: number;
  h: number;
}
export const CATALOGUE: CatalogueEntry[] = [
  { metric: "open_issues", title: "Open issues by priority", chart: true, periodic: false, groups: true, w: 6, h: 4 },
  { metric: "sla_adherence", title: "SLA adherence", chart: true, periodic: true, groups: false, w: 6, h: 4 },
  { metric: "mttr", title: "Mean time to remediate", chart: true, periodic: true, groups: false, w: 6, h: 4 },
  { metric: "new_vs_fixed", title: "New versus fixed", chart: true, periodic: true, groups: false, w: 6, h: 4 },
  { metric: "open_risk", title: "Open risk and burndown", chart: true, periodic: true, groups: true, w: 6, h: 5 },
  { metric: "backlog_age", title: "Backlog age", chart: true, periodic: false, groups: false, w: 6, h: 4 },
  { metric: "past_sla", title: "Past SLA", chart: false, periodic: false, groups: false, w: 12, h: 5 },
  { metric: "scan_coverage", title: "Scan coverage", chart: false, periodic: false, groups: false, w: 6, h: 5 },
  { metric: "vulnerable_components", title: "Most vulnerable components", chart: false, periodic: false, groups: false, w: 6, h: 5 },
  { metric: "expiring_acceptances", title: "Expiring risk acceptances", chart: false, periodic: false, groups: false, w: 6, h: 4 },
  { metric: "engagement_status", title: "Engagement status", chart: false, periodic: false, groups: false, w: 6, h: 4 },
  { metric: "advisory_impact", title: "Advisory impact", chart: false, periodic: true, groups: false, w: 6, h: 5 },
];
export const ENTRY: Record<string, CatalogueEntry> = Object.fromEntries(CATALOGUE.map((e) => [e.metric, e]));
export const titleOf = (w: Pick<Widget, "metric">) => ENTRY[w.metric]?.title ?? w.metric;

// --- the grid ---------------------------------------------------------------------------------

export const toLayout = (widgets: Widget[]): LayoutItem[] =>
  widgets.map((w) => ({ i: w.id, x: w.x, y: w.y, w: w.w, h: w.h, minW: 2, minH: 2, maxH: 12 }));

/** The widgets with their places taken from a layout (anything the layout lacks keeps its own). */
export function withLayout(widgets: Widget[], layout: Layout): Widget[] {
  const at = new Map(layout.map((l) => [l.i, l]));
  return widgets.map((w) => {
    const l = at.get(w.id);
    return l ? { ...w, x: l.x, y: l.y, w: l.w, h: l.h } : w;
  });
}

const compact = (layout: Layout): LayoutItem[] => [...verticalCompactor.compact(layout, COLS)];

/** A new widget goes at the bottom, full catalogue size. */
export function addWidget(widgets: Widget[], metric: string, id: string): Widget[] {
  const e = ENTRY[metric];
  const bottom = widgets.reduce((m, w) => Math.max(m, w.y + w.h), 0);
  return [...widgets, { id, metric, x: 0, y: bottom, w: e?.w ?? 6, h: e?.h ?? 4, filters: {} }];
}

const overlaps = (a: LayoutItem, b: LayoutItem) =>
  a.i !== b.i && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

/** Settle a layout in which `first` has just moved: it keeps its place, and anything it overlaps
 * goes below it (as dragging does), then everything rises as far as it can. */
function settle(layout: LayoutItem[], first: string): LayoutItem[] {
  const order = [...layout].sort((a, b) => a.y - b.y || Number(a.i !== first) - Number(b.i !== first) || a.x - b.x);
  const placed: LayoutItem[] = [];
  for (const item of order) {
    const l = { ...item };
    for (let hit = placed.find((p) => overlaps(p, l)); hit; hit = placed.find((p) => overlaps(p, l))) l.y = hit.y + hit.h;
    placed.push(l);
  }
  return compact(placed);
}

/** Move one widget a step, the way dragging it would. Left and right go a column at a time; down
 * and up step past the nearest widget in the way, which takes the vacated place if it fits there. */
export function moveWidget(widgets: Widget[], id: string, dx: number, dy: number): Widget[] {
  const layout = compact(toLayout(widgets));
  const item = layout.find((l) => l.i === id);
  if (!item) return widgets;
  const shares = (l: LayoutItem) => l.i !== id && l.x < item.x + item.w && l.x + l.w > item.x;
  let next = layout.map((l) => ({ ...l }));
  const me = next.find((l) => l.i === id)!;
  me.x = Math.min(Math.max(0, item.x + dx), COLS - item.w);
  if (dy > 0) {
    const below = layout.filter((l) => shares(l) && l.y >= item.y + item.h).sort((a, b) => a.y - b.y)[0];
    if (!below) return withLayout(widgets, layout);
    me.y = below.y + below.h;
    const lifted = { ...below, y: item.y };
    if (!next.some((l) => l.i !== id && l.i !== below.i && overlaps(l, lifted))) {
      next = next.map((l) => (l.i === below.i ? lifted : l));
    }
  } else if (dy < 0) {
    const above = layout.filter((l) => shares(l) && l.y + l.h <= item.y).sort((a, b) => b.y + b.h - (a.y + a.h))[0];
    if (!above) return withLayout(widgets, layout);
    me.y = above.y;
  }
  return withLayout(widgets, settle(next, id));
}

/** Resize one widget a step (Shift + arrows): wider or narrower by a column, taller or shorter by
 * a row, within the grid; anything it now overlaps makes room. */
export function resizeWidget(widgets: Widget[], id: string, dw: number, dh: number): Widget[] {
  const layout = compact(toLayout(widgets));
  const item = layout.find((l) => l.i === id);
  if (!item) return widgets;
  const w = Math.min(Math.max(2, item.w + dw), COLS - item.x);
  const h = Math.min(Math.max(2, item.h + dh), 12);
  return withLayout(widgets, settle(layout.map((l) => (l.i === id ? { ...l, w, h } : l)), id));
}

/** What a screen reader hears after a move or resize. */
export function describePlace(w: Widget, before?: Widget): string {
  const where = `column ${w.x + 1} of ${COLS}, row ${w.y + 1}`;
  const size = `${w.w} column${w.w === 1 ? "" : "s"} wide, ${w.h} rows tall`;
  const name = titleOf(w);
  if (before && before.x === w.x && before.y === w.y && before.w === w.w && before.h === w.h) {
    return `${name} can't go further that way. It is at ${where}, ${size}.`;
  }
  if (before && (before.w !== w.w || before.h !== w.h)) return `${name} resized to ${size}, at ${where}.`;
  return `${name} moved to ${where}, ${size}.`;
}

/** Reading order: top to bottom, then left to right -- for phones and for screen readers. */
export const readingOrder = (widgets: Widget[]) => [...widgets].sort((a, b) => a.y - b.y || a.x - b.x);

// --- filters and drill-downs ------------------------------------------------------------------

const isoDay = (d: Date) => d.toISOString().slice(0, 10);

/** A widget's filters as the metrics API's query string (`days` becomes from/to, ending today). */
export function filterParams(f: WidgetFilters = {}, today = new Date()): URLSearchParams {
  const p = new URLSearchParams();
  for (const id of f.portfolios ?? []) p.append("portfolio", id);
  for (const id of f.projects ?? []) p.append("project", id);
  if (f.tag) p.set("tag", f.tag);
  if (f.days) {
    const from = new Date(today);
    from.setUTCDate(from.getUTCDate() - (f.days - 1));
    p.set("from", isoDay(from));
    p.set("to", isoDay(today));
  }
  if (f.group) p.set("group", f.group);
  return p;
}

/** The page listing the Issues behind a number: the row's drill-down plus the widget's filters. */
export function drillHref(drill: Drill, f: WidgetFilters = {}, label = "", count?: number): string {
  const p = filterParams({ ...f, group: undefined });
  p.set("kind", drill.kind);
  if (drill.band) p.set("band", drill.band);
  if (drill.portfolio) p.set("in_portfolio", drill.portfolio);
  if (drill.project) p.set("in_project", drill.project);
  if (drill.older_than) p.set("older_than", String(drill.older_than));
  if (label) p.set("label", label);
  if (count !== undefined) p.set("n", String(count));
  return `/app/metrics/issues?${p.toString()}`;
}

/** "91% (195 of 214)": a percentage never without its counts. */
export function pctWithCounts(part: number, whole: number): string {
  if (!whole) return "No data";
  return `${Math.round((part / whole) * 100)}% (${part.toLocaleString()} of ${whole.toLocaleString()})`;
}

export function describeFilters(f: WidgetFilters = {}, names: Record<string, string> = {}): string {
  const parts: string[] = [];
  const named = (ids: string[]) => ids.map((i) => names[i] ?? "a project").join(", ");
  if (f.portfolios?.length) parts.push(`portfolio ${named(f.portfolios)}`);
  if (f.projects?.length) parts.push(`project ${named(f.projects)}`);
  if (f.tag) parts.push(`tag “${f.tag}”`);
  if (f.days) parts.push(`last ${f.days} days`);
  if (f.group && f.group !== "band") parts.push(`by ${f.group}`);
  return parts.join(" · ");
}

export function newWidgetId(widgets: Widget[], metric: string): string {
  const base = metric.replace(/_/g, "-").slice(0, 24);
  let n = 1;
  while (widgets.some((w) => w.id === `${base}-${n}`)) n++;
  return `${base}-${n}`;
}
