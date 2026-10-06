/* What each metric shows (plan §55.4): a headline, an optional chart, and the same numbers as a
 * table -- the table is what the chart draws, so View as table can never disagree with it. Every
 * number that stands for Issues links to them; other rows link to their project, advisory,
 * acceptance or engagement. Percentages always carry their counts. */
import { drillHref, pctWithCounts, type Drill, type MetricResult, type Row, type WidgetFilters } from "./dashboard";

export interface Cell {
  text: string;
  href?: string;
  num?: boolean;
}
export interface Table {
  caption: string;
  head: string[];
  rows: Cell[][];
}
export interface BarItem {
  label: string;
  value: number;
  text: string;
  href?: string;
}
export type Chart =
  | { kind: "bars"; label: string; items: BarItem[] }
  | { kind: "columns"; label: string; keys: string[]; items: { label: string; values: number[] }[] }
  | { kind: "line"; label: string; unit: string; items: { label: string; value: number | null }[] };
export interface Headline {
  text: string;
  href?: string;
}
export interface Presented {
  headline: Headline;
  detail: Headline[];
  charts: Chart[];
  tables: Table[];
  empty?: string;
}

const n = (v: unknown) => (typeof v === "number" ? v : Number(v ?? 0));
const s = (v: unknown) => (v === null || v === undefined ? "" : String(v));
const num = (v: unknown, href?: string): Cell => ({ text: n(v).toLocaleString(), num: true, href });
const plural = (k: number, one: string, many = `${one}s`) => `${k.toLocaleString()} ${k === 1 ? one : many}`;
const week = (iso: unknown) => `Week of ${s(iso)}`;
const daysAgo = (d: unknown) => (d === null || d === undefined ? "never" : n(d) === 0 ? "today" : `${plural(n(d), "day")} ago`);
const issueHref = (project: unknown, issue: unknown) => `/app/projects/${encodeURIComponent(s(project))}/issues/${encodeURIComponent(s(issue))}`;
const projectHref = (project: unknown) => `/app/projects/${encodeURIComponent(s(project))}`;

export function present(r: MetricResult, f: WidgetFilters = {}): Presented {
  const c = r.counts ?? {};
  const rows: Row[] = r.rows ?? [];
  const series: Row[] = r.series ?? [];
  const drill = (d: Drill | undefined, label: string, count?: number) => (d ? drillHref(d, f, label, count) : undefined);
  const groupName = { band: "Priority", portfolio: "Portfolio", project: "Project" }[f.group ?? "band"];

  switch (r.metric) {
    case "open_issues":
    case "open_risk": {
      const risk = r.metric === "open_risk";
      const items = rows.map((row) => ({
        label: s(row.label ?? row.key),
        value: n(risk ? row.score : row.count),
        text: risk ? `${n(row.score).toLocaleString()} (${plural(n(row.count), "issue")})` : n(row.count).toLocaleString(),
        href: drill(row.drill, `${risk ? "Open risk" : "Open issues"}, ${s(row.label ?? row.key)}`, n(row.count)),
      }));
      const out: Presented = {
        headline: risk
          ? { text: `Risk score ${n(r.value).toLocaleString()} across ${plural(n(c.open), "open issue")}`, href: drillHref({ kind: "open" }, f, "Open issues", n(c.open)) }
          : { text: `${plural(n(r.value), "open issue")}`, href: drillHref({ kind: "open" }, f, "Open issues", n(c.open)) },
        detail: [],
        charts: [{ kind: "bars", label: `${risk ? "Risk score" : "Open issues"} by ${groupName.toLowerCase()}`, items }],
        tables: [{
          caption: `${risk ? "Open risk" : "Open issues"} by ${groupName.toLowerCase()}`,
          head: [groupName, "Open issues", "Risk score"],
          rows: rows.map((row, i) => [{ text: s(row.label ?? row.key) }, num(row.count, items[i]!.href), num(row.score)]),
        }],
        empty: n(c.open) === 0 ? "No open issues." : undefined,
      };
      if (risk && series.length) {
        out.charts.push({ kind: "line", label: "Risk burndown, end of each week", unit: "", items: series.map((p) => ({ label: s(p.week), value: n(p.risk) })) });
        out.tables.push({ caption: "Risk burndown, end of each week", head: ["Week", "Risk score"],
          rows: series.map((p) => [{ text: week(p.week) }, num(p.risk)]) });
      }
      return out;
    }
    case "sla_adherence": {
      const due = n(c.due);
      return {
        headline: { text: due ? `${pctWithCounts(n(c.met), due)} fixed within SLA` : "No SLA deadlines in this period" },
        detail: [
          { text: `${plural(n(c.missed), "issue")} fixed late` },
          { text: `${plural(n(c.open_past_deadline), "issue")} still open past the deadline`,
            href: r.period ? `${drillHref({ kind: "past_sla" }, { ...f, days: undefined }, "Still open past an SLA deadline in the period", n(c.open_past_deadline))}&from=${r.period[0]}&to=${r.period[1]}` : undefined },
          { text: `${plural(n(c.exempt), "issue")} exempt` },
        ],
        charts: series.length ? [{ kind: "line", label: "Share fixed within SLA, by week", unit: "%",
          items: series.map((p) => ({ label: s(p.week), value: p.rate === null ? null : Math.round(n(p.rate) * 100) })) }] : [],
        tables: [
          { caption: "Fixed within SLA, by week", head: ["Week", "Fixed in time", "Due", "On time"],
            rows: series.map((p) => [{ text: week(p.week) }, num(p.met), num(p.due), { text: pctWithCounts(n(p.met), n(p.due)) }]) },
          { caption: "Fixed within SLA, by severity or band", head: ["Band", "Fixed in time", "Due", "On time"],
            rows: rows.map((b) => [{ text: s(b.key) }, num(b.met), num(b.due), { text: pctWithCounts(n(b.met), n(b.due)) }]) },
        ],
        empty: due === 0 ? "No issue had an SLA deadline in this period." : undefined,
      };
    }
    case "mttr": {
      const items = rows.map((row) => ({
        label: s(row.key), value: n(row.days), text: `${n(row.days)} days (${n(row.fixed).toLocaleString()} fixed)`,
        href: drill(row.drill, `Fixed, ${s(row.key)}`, n(row.fixed)),
      }));
      return {
        headline: { text: r.value === null ? "Nothing fixed in this period" : `${r.value} days on average, over ${plural(n(c.fixed), "fixed issue")}`,
          href: drillHref({ kind: "fixed" }, f, "Fixed issues", n(c.fixed)) },
        detail: [],
        charts: [{ kind: "bars", label: "Mean days to remediate by priority", items }],
        tables: [{ caption: "Mean time to remediate by priority", head: ["Priority", "Fixed", "Mean days"],
          rows: rows.map((row, i) => [{ text: s(row.key) }, num(row.fixed, items[i]!.href), { text: s(row.days), num: true }]) }],
        empty: n(c.fixed) === 0 ? "Nothing was fixed in this period." : undefined,
      };
    }
    case "new_vs_fixed":
      return {
        headline: { text: `${plural(n(c.new), "new issue")}`, href: drill(r.drill?.new, "New issues", n(c.new)) },
        detail: [{ text: `${plural(n(c.fixed), "fixed issue")}`, href: drill(r.drill?.fixed, "Fixed issues", n(c.fixed)) }],
        charts: [{ kind: "columns", label: "New and fixed issues by week", keys: ["New", "Fixed"],
          items: series.map((p) => ({ label: s(p.week), values: [n(p.new), n(p.fixed)] })) }],
        tables: [{ caption: "New and fixed issues by week", head: ["Week", "New", "Fixed"],
          rows: series.map((p) => [{ text: week(p.week) }, num(p.new), num(p.fixed)]) }],
        empty: n(c.new) + n(c.fixed) === 0 ? "No issues were found or fixed in this period." : undefined,
      };
    case "backlog_age": {
      const items = rows.map((row) => {
        const days = n(String(row.key).replace("over_", ""));
        return { label: `Older than ${days} days`, value: n(row.count), text: n(row.count).toLocaleString(),
          href: drill(row.drill, `Open longer than ${days} days`, n(row.count)) };
      });
      return {
        headline: { text: r.value === null ? "No open issues" : `Median age ${plural(n(r.value), "day")}, across ${plural(n(c.open), "open issue")}`,
          href: drillHref({ kind: "open" }, f, "Open issues", n(c.open)) },
        detail: [],
        charts: [{ kind: "bars", label: "Open issues by age", items }],
        tables: [{ caption: "Open issues by age", head: ["Age", "Open issues"],
          rows: items.map((i) => [{ text: i.label }, num(i.value, i.href)]) }],
        empty: n(c.open) === 0 ? "No open issues." : undefined,
      };
    }
    case "past_sla":
      return {
        headline: { text: `${plural(n(r.value), "issue")} past SLA`, href: drillHref({ kind: "past_sla" }, f, "Past SLA", n(r.value)) },
        detail: [],
        charts: [],
        tables: [{ caption: "Past SLA, the most overdue first", head: ["Portfolio", "Issue", "Project", "Overdue", "Assignee"],
          rows: rows.map((row) => [{ text: s(row.portfolio) || "—" }, { text: s(row.title), href: issueHref(row.project_id, row.issue_id) },
            { text: s(row.project) }, { text: plural(n(row.days_over), "day"), num: true }, { text: s(row.assignee_name ?? row.assignee) || "Unassigned" }]) }],
        empty: n(r.value) === 0 ? "Nothing is past its SLA." : undefined,
      };
    case "scan_coverage":
      return {
        headline: { text: n(c.projects) ? `${pctWithCounts(n(c.scanned_recently), n(c.projects))} projects scanned in the last ${r.days ?? 30} days` : "No project has been scanned yet" },
        detail: [],
        charts: [],
        tables: [{ caption: "Scan coverage by project", head: ["Project", "Last full scan", "Scanners"],
          rows: rows.map((row) => [{ text: s(row.project), href: projectHref(row.project_id) }, { text: daysAgo(row.days_since) },
            { text: n(row.scanners_applicable) ? `${n(row.scanners_ok)} of ${n(row.scanners_applicable)}` : "—" }]) }],
        empty: n(c.projects) === 0 ? "No project has been scanned yet." : undefined,
      };
    case "vulnerable_components":
      return {
        headline: { text: `${plural(n(r.value), "library", "libraries")} with a known vulnerability` },
        detail: [],
        charts: [],
        tables: [{ caption: "Most vulnerable components", head: ["Library", "Projects", "Most vulnerabilities", "Known exploited in"],
          rows: rows.map((row) => [{ text: s(row.library), href: row.purl ? `/app/components?purl=${encodeURIComponent(s(row.purl))}` : undefined },
            num(row.projects), num(row.vulns), { text: plural(n(row.kev_projects), "project"), num: true }]) }],
        empty: n(r.value) === 0 ? "No library in a current SBOM has a known vulnerability." : undefined,
      };
    case "expiring_acceptances":
      return {
        headline: { text: `${plural(n(r.value), "risk acceptance")} expiring in the next ${r.days ?? 30} days`, href: "/app/risk-acceptances" },
        detail: [],
        charts: [],
        tables: [{ caption: "Expiring risk acceptances, the soonest first", head: ["Project", "Issues", "Expires", "Approved by"],
          rows: rows.map((row) => [{ text: s(row.project), href: projectHref(row.project_id) }, num(row.issues),
            { text: `in ${plural(n(row.days_left), "day")}`, href: `/app/risk-acceptances/${encodeURIComponent(s(row.id))}` },
            { text: s(row.approved_by) || "—" }]) }],
        empty: n(r.value) === 0 ? "No risk acceptance expires in the next 30 days." : undefined,
      };
    case "engagement_status":
      return {
        headline: { text: `${plural(n(r.value), "active engagement")}` },
        detail: Object.entries(c).filter(([k]) => k !== "active").map(([k, v]) => ({ text: `${v.toLocaleString()} ${k.replace(/_/g, " ")}` })),
        charts: [],
        tables: [{ caption: "Active engagements", head: ["Engagement", "Project", "Lead", "Target end"],
          rows: rows.map((row) => [{ text: s(row.name), href: `/app/engagements/${encodeURIComponent(s(row.id))}` }, { text: s(row.project) },
            { text: s(row.lead) || "—" }, { text: row.target_end_at ? `${s(row.target_end_at).slice(0, 10)}${row.overdue ? " (overdue)" : ""}` : "—" }]) }],
        empty: Object.keys(c).length === 0 ? "No engagements yet." : undefined,
      };
    case "advisory_impact":
      return {
        headline: { text: `${plural(n(r.value), "new vulnerability", "new vulnerabilities")} affecting projects`, href: "/app/advisories" },
        detail: [{ text: `${n(c.kev).toLocaleString()} known exploited` }, { text: `${n(c.not_acted_on).toLocaleString()} not acted on yet`, href: "/app/advisories" }],
        charts: [],
        tables: [{ caption: "Vulnerabilities that first affected a project in the period", head: ["Vulnerability", "Projects", "Known exploited", "State"],
          rows: rows.map((row) => [{ text: s(row.vuln_key), href: `/app/advisories/${encodeURIComponent(s(row.vuln_key))}` }, num(row.projects),
            { text: row.kev ? "Yes" : "No" }, { text: row.state === "new" ? "Not acted on" : "Issues created" }]) }],
        empty: n(r.value) === 0 ? "No new vulnerability affected a project in this period." : undefined,
      };
    default:
      return { headline: { text: String(r.value ?? "") }, detail: [], charts: [], tables: [] };
  }
}
