/* The org-wide Issues list (Week 73, plan §56): its rows, pages, saved views, each person's table
 * settings, and bulk actions with a preview and Undo. Mirrors core/search (issues.py, views.py,
 * bulk.py). */

import type { Role } from "./dashboard";
import { dateText, emptyClause, formatQuery, parse, withClause, type Clause, type DateBound, type Query } from "./issue-query";

export type Sort = "priority" | "severity" | "newest" | "oldest" | "last_seen";
export const SORTS: [Sort, string][] = [
  ["priority", "Priority"], ["severity", "Severity"], ["newest", "Newest first"],
  ["oldest", "Oldest first"], ["last_seen", "Last seen"],
];

export type IssueStatus = "open" | "accepted" | "not_a_risk" | "fixed";
export interface IssueRow {
  id: string;
  project_id: string;
  project: string;
  title: string;
  severity: string;
  band: string | null;
  score: number | null;
  status: IssueStatus;
  state: string;
  accepted_until: string | null;
  sla: { state: string; due_at: string | null };
  assignee: string | null;
  assignee_name: string | null;
  path: string;
  category: string;
  source: string;
  retest: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  fixed_at: string | null;
}

export interface IssueCount { value: number; exact: boolean; at_least?: boolean }
export interface IssuePage { rows: IssueRow[]; next: string | null; count: IssueCount | null; sort: Sort; query: string }

export function countText(c: IssueCount | null | undefined): string {
  if (!c) return "";
  const n = c.value.toLocaleString("en-US");
  return c.at_least ? `more than ${n}` : n;
}

/* Columns besides the title, which is always shown. */
export type Column =
  | "project" | "priority" | "severity" | "status" | "sla" | "assignee" | "path" | "category"
  | "source" | "retest" | "first_seen" | "last_seen" | "fixed";
export const COLUMN_LABEL: Record<Column, string> = {
  project: "Project", priority: "Priority", severity: "Severity", status: "Status", sla: "SLA",
  assignee: "Assignee", path: "Location", category: "Kind", source: "Source", retest: "Retest",
  first_seen: "First seen", last_seen: "Last seen", fixed: "Fixed",
};
export const ALL_COLUMNS = Object.keys(COLUMN_LABEL) as Column[];
export const DEFAULT_COLUMNS: Column[] = ["project", "priority", "severity", "status", "sla", "assignee", "first_seen"];
export type Density = "comfortable" | "compact";
export interface TablePrefs { columns: Column[]; density: Density; saved: boolean; all_columns?: Column[] }

export interface SavedView {
  id: string;
  name: string;
  owner: string | null;
  query: string;
  sort: Sort;
  columns: Column[] | null;
  shared_with: Role[];
  version: number;
  updated_at: string | null;
  updated_by: string | null;
  builtin: boolean;
  can_edit: boolean;
}
export interface ViewInput { name?: string; query?: string; sort?: Sort; columns?: Column[] | null; shared_with?: Role[]; version?: number }

/* Bulk actions (plan §56, principle 9: show the effect before the action). */
export type BulkAction = "assign" | "not_a_risk" | "reopen" | "tag" | "untag" | "accept";
export interface Selection { q: string; ids?: string[] | null }
export interface BulkParams { to?: string | null; reason?: string; tag?: string }
export interface BulkPreview {
  action: BulkAction;
  selected: number;
  will_change: number;
  unchanged: number;
  skipped: { reason: string; count: number }[];
  by_project: { project: string; count: number }[];
  by_severity: Record<string, number>;
  expected_count: number;
  reversible: boolean;
  sentence: string;
  /* "accept": risk acceptance is per project and needs a second person, so it is a request per
   * project in its own flow, never applied here. */
  flow?: { kind: "risk_acceptance"; projects: { project_id: string; project: string; count: number; issue_ids: string[]; truncated: boolean }[] };
}
export interface BulkResult {
  batch_id: string;
  action: BulkAction;
  changed: number;
  unchanged: number;
  skipped: { reason: string; count: number }[];
  undo_until: string | null;
  sentence: string;
}
export interface UndoResult { restored: number; kept: number; sentence: string }

/* --- The filter panel (plan §56: grouped and collapsible, each group's active count shown) --- */

export const GROUPS: { id: string; title: string; keys: string[] }[] = [
  { id: "status", title: "Status", keys: ["status"] },
  { id: "severity", title: "Severity and priority", keys: ["severity", "priority"] },
  { id: "location", title: "Location", keys: ["project", "portfolio", "path", "category"] },
  { id: "source", title: "Source", keys: ["source", "retest"] },
  { id: "owner", title: "Ownership and SLA", keys: ["assignee", "sla", "tag"] },
  { id: "dates", title: "Dates", keys: ["first_seen", "last_seen", "fixed"] },
];

export const KEY_LABEL: Record<string, string> = {
  status: "Status", severity: "Severity", priority: "Priority", sla: "SLA", project: "Project",
  portfolio: "Business unit", path: "Path", category: "Kind", source: "Source", assignee: "Assignee",
  tag: "Tag", retest: "Retest", first_seen: "First seen", last_seen: "Last seen", fixed: "Fixed",
};

export const VALUE_LABEL: Record<string, string> = {
  open: "Open", accepted: "Accepted", not_a_risk: "Not a risk", fixed: "Fixed",
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", none: "None",
  breached: "Past SLA", due_soon: "Due soon", on_track: "On track",
  sast: "Code (SAST)", sca: "Dependencies", secrets: "Secrets", iac: "Infrastructure as code",
  container: "Containers", dast: "Running app (DAST)", requested: "Requested", passed: "Passed", failed: "Failed",
};

export const valueLabel = (v: string) => VALUE_LABEL[v] ?? v;

/** How many filters a key carries (a group shows the sum when collapsed). */
export function activeCount(q: Query, keys: string[]): number {
  return keys.reduce((n, k) => {
    const c = q.clauses[k];
    return n + (c ? c.include.length + c.exclude.length + c.dates.length : 0);
  }, 0);
}

export function dateWords(d: DateBound): string {
  if (d.days !== undefined) return d.op.startsWith(">") ? `more than ${d.days} days ago` : `in the last ${d.days} days`;
  const words: Record<string, string> = { ">": "after", ">=": "on or after", "<": "before", "<=": "on or before" };
  return `${words[d.op]} ${d.day}`;
}

export interface Chip { id: string; label: string; remove: (q: Query) => Query }

/** One removable chip per value, in the panel's order, then the free text. */
export function chipsOf(q: Query): Chip[] {
  const out: Chip[] = [];
  for (const g of GROUPS) {
    for (const k of g.keys) {
      const c = q.clauses[k];
      if (!c) continue;
      for (const v of c.include) out.push({ id: `${k}:${v}`, label: `${KEY_LABEL[k]}: ${valueLabel(v)}`, remove: (x) => withClause(x, k, { include: (x.clauses[k] ?? emptyClause()).include.filter((y) => y !== v) }) });
      for (const v of c.exclude) out.push({ id: `-${k}:${v}`, label: `${KEY_LABEL[k]}: not ${valueLabel(v)}`, remove: (x) => withClause(x, k, { exclude: (x.clauses[k] ?? emptyClause()).exclude.filter((y) => y !== v) }) });
      for (const d of c.dates) out.push({ id: `${k}:${dateText(d)}`, label: `${KEY_LABEL[k]}: ${dateWords(d)}`, remove: (x) => withClause(x, k, { dates: (x.clauses[k] ?? emptyClause()).dates.filter((y) => dateText(y) !== dateText(d)) }) });
    }
  }
  for (const w of q.text) out.push({ id: `text:${w}`, label: `Title has “${w}”`, remove: (x) => ({ clauses: x.clauses, text: x.text.filter((y) => y !== w) }) });
  return out;
}

/** Turn one value on or off in a key's include list (the panel's checkboxes). */
export function toggled(q: Query, k: string, v: string, on: boolean): Query {
  const c: Clause = q.clauses[k] ?? emptyClause();
  const include = on ? [...c.include.filter((x) => x !== v), v] : c.include.filter((x) => x !== v);
  return withClause(q, k, { include, exclude: c.exclude.filter((x) => x !== v) });
}

/* --- Views saved in this browser before Week 73 (lib/saved-views.ts), turned into queries --- */

export interface LegacyQuery {
  severity?: string[]; category?: string; triage?: string[]; sla?: string[]; priority?: string[]; tag?: string[];
  sort?: "severity" | "path" | "risk";
}
export interface LegacyView { assetId: string; name: string; query: LegacyQuery }

const LEGACY_PREFIX = "bulwark.savedViews.";
export const LEGACY_DONE = "bulwark.savedViews.importedToServer";

export function readLegacyViews(storage: Pick<Storage, "length" | "key" | "getItem">): LegacyView[] {
  const out: LegacyView[] = [];
  for (let i = 0; i < storage.length; i++) {
    const k = storage.key(i);
    if (!k || !k.startsWith(LEGACY_PREFIX) || k === LEGACY_DONE) continue;
    try {
      const list = JSON.parse(storage.getItem(k) ?? "[]") as { name?: unknown; query?: unknown }[];
      for (const v of Array.isArray(list) ? list : []) {
        if (typeof v?.name === "string" && v.query && typeof v.query === "object") {
          out.push({ assetId: k.slice(LEGACY_PREFIX.length), name: v.name, query: v.query as LegacyQuery });
        }
      }
    } catch {
      /* a broken entry is skipped, not fatal */
    }
  }
  return out;
}

/** One old view as a query for its project. An old view with "every status" checked had no
 * status filter, which meant the active queue there too, so the meaning carries over. */
export function legacyToQuery(v: LegacyView, label: string): { name: string; query: string; sort: Sort } {
  let q: Query = { clauses: {}, text: [] };
  const add = (k: string, values: string[] | undefined) => {
    for (const x of values ?? []) q = toggled(q, k, k === "priority" ? x.toUpperCase() : k === "tag" ? x : x.toLowerCase(), true);
  };
  q = withClause(q, "project", { include: [label] });
  add("status", v.query.triage);
  add("severity", v.query.severity);
  add("priority", v.query.priority);
  add("sla", v.query.sla);
  add("tag", v.query.tag);
  if (v.query.category) add("category", [v.query.category]);
  const text = formatQuery(q);
  parse(text); // the API checks it again; this throws early on anything odd
  return { name: v.name.slice(0, 80), query: text, sort: v.query.sort === "severity" ? "severity" : "priority" };
}
