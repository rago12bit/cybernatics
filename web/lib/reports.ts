/* Reports (plan §48.3): what the builder edits and what the API returns. */
import { ENTRY, type WidgetFilters } from "./dashboard";

export type BlockType =
  | "cover" | "summary" | "metric" | "issues" | "issue" | "acceptances" | "compliance" | "engagement" | "appendix";

export interface Block {
  id: string;
  type: BlockType;
  config: Record<string, unknown> & { filters?: WidgetFilters };
}
export interface Schedule {
  cadence: "weekly" | "monthly";
  weekday: number;
  day: number;
  hour: number;
  recipients: string[];
  link_days: number;
}
export interface Report {
  id: string;
  name: string;
  owner: string;
  period_days: number;
  blocks: Block[];
  schedule: Schedule | null;
  next_run_at: string | null;
  version: number;
  updated_at: string;
  updated_by: string;
  summary_needs_review: boolean;
  notes?: string[];
}
export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  period_days: number;
  blocks: Block[];
}
export interface ReportRun {
  id: string;
  report_id: string;
  report_name: string;
  trigger: "manual" | "schedule";
  status: "queued" | "done" | "failed";
  error: string | null;
  period: [string, string];
  sha256: string;
  signed: boolean;
  size: number;
  ai_summary: boolean;
  delivery: { to: string; status: string; reason?: string }[];
  created_by: string;
  created_by_name?: string;
  created_at: string;
}
export interface ReportLink {
  id: string;
  run_id: string;
  created_by: string;
  created_by_name?: string;
  created_at: string;
  expires_at: string;
  state: "active" | "expired" | "revoked";
  revoked_by: string | null;
  opens: number;
  last_opened_at: string | null;
}
export interface NewLink extends ReportLink {
  token: string;
  path: string;
  url: string | null;
}

export const BLOCK_LABEL: Record<BlockType, string> = {
  cover: "Cover",
  summary: "Executive summary",
  metric: "Metric",
  issues: "Issue table",
  issue: "One issue in detail",
  acceptances: "Risk acceptances",
  compliance: "Compliance mapping",
  engagement: "Engagement scope",
  appendix: "Appendix",
};
export const BLOCK_TYPES = Object.keys(BLOCK_LABEL) as BlockType[];
/** What a person hears and reads for a block: a metric block by its metric ("Metric: SLA
 * adherence"), so a template's five metrics are not five identical "Move Metric up" buttons. */
export function blockName(b: Pick<Block, "type" | "config">): string {
  const metric = b.type === "metric" ? String((b.config as { metric?: unknown }).metric ?? "") : "";
  return metric ? `${BLOCK_LABEL.metric}: ${ENTRY[metric]?.title ?? metric}` : BLOCK_LABEL[b.type];
}
export const ISSUE_KINDS: [string, string][] = [
  ["open", "Open now"], ["past_sla", "Past their SLA"], ["opened", "First seen in the period"], ["fixed", "Fixed in the period"],
  ["view", "A saved view of the Issues list"],
];
export const ACCEPTANCE_STATES: [string, string][] = [
  ["approved", "In force"], ["requested", "Awaiting a decision"], ["expiring", "Expiring within 30 days"], ["all", "All"],
];
export const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
/** The last id in a pasted link or id ("…/issues/<id>" or "…/engagements/<id>"). */
export function idFrom(text: string): string | null {
  const all = text.match(UUID);
  return all ? all[all.length - 1]!.toLowerCase() : null;
}

export function newBlock(type: BlockType, blocks: Block[]): Block {
  let n = 1;
  while (blocks.some((b) => b.id === `${type}-${n}`)) n++;
  const config: Block["config"] =
    type === "cover" ? { title: "Report", subtitle: "" }
    : type === "summary" ? { text: "" }
    : type === "metric" ? { metric: "open_issues", filters: {} }
    : type === "issues" ? { kind: "open", band: null, limit: 50, title: "", filters: {} }
    : type === "acceptances" ? { state: "approved" }
    : type === "compliance" ? { framework: "owasp-top10-2021" }
    : type === "issue" ? { issue_id: "" }
    : type === "engagement" ? { engagement_id: "" }
    : {};
  return { id: `${type}-${n}`, type, config };
}

/** Move a block up or down one place; the list is unchanged at either end. */
export function moveBlock(blocks: Block[], id: string, by: -1 | 1): Block[] {
  const i = blocks.findIndex((b) => b.id === id);
  const j = i + by;
  if (i < 0 || j < 0 || j >= blocks.length) return blocks;
  const out = [...blocks];
  [out[i], out[j]] = [out[j]!, out[i]!];
  return out;
}

export function scheduleWords(s: Schedule | null): string {
  if (!s) return "Not scheduled";
  const hour = `${String(s.hour).padStart(2, "0")}:00 UTC`;
  const when = s.cadence === "weekly" ? `every ${WEEKDAYS[s.weekday]} at ${hour}` : `on day ${s.day} of each month at ${hour}`;
  return `Sent ${when} to ${s.recipients.length} recipient${s.recipients.length === 1 ? "" : "s"}`;
}
