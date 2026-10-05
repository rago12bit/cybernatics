import type { IssueSla, SlaState } from "./types";

/** How an Issue's SLA reads (plan §44.1): a word for the state, never colour alone, and the time
 * left or overdue in whole days. */
export const SLA_WORD: Record<SlaState, string> = {
  on_track: "On track",
  due_soon: "Due soon",
  breached: "Breached",
  met: "Fixed in time",
  missed: "Fixed late",
  exempt: "Paused",
  none: "No SLA",
};

export const SLA_MARK: Record<SlaState, string> = {
  on_track: "●",
  due_soon: "◐",
  breached: "▲",
  met: "✓",
  missed: "✕",
  exempt: "–",
  none: "",
};

const DAY = 86_400_000;

export function slaDetail(sla: IssueSla | undefined, now: number = Date.now()): string {
  if (!sla?.due_at) return "";
  const left = (new Date(sla.due_at).getTime() - now) / DAY;
  if (sla.state === "met" || sla.state === "missed") return `due ${new Date(sla.due_at).toLocaleDateString()}`;
  if (left < 0) {
    const n = Math.floor(-left);
    return n >= 1 ? `${n} day${n === 1 ? "" : "s"} overdue` : "overdue today";
  }
  const n = Math.floor(left);
  return n >= 1 ? `${n} day${n === 1 ? "" : "s"} left` : "due today";
}

/** "Breached · 3 days overdue" -- the whole sentence, for a screen reader or a tooltip. */
export function slaSentence(sla: IssueSla | undefined, now?: number): string {
  if (!sla || sla.state === "none") return SLA_WORD.none;
  const detail = slaDetail(sla, now);
  return detail ? `${SLA_WORD[sla.state]} · ${detail}` : SLA_WORD[sla.state];
}
