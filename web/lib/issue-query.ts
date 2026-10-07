/* The Issues query language, in the browser (Week 73, plan §56): the twin of core/search/language.py.

   The API's parser is the authority (it runs the query). This one reads the same text as you type,
   so the filter panel and the query bar stay in step, errors are underlined where they are, and
   autocomplete knows which key you are in. Both run tests/fixtures/issue_query_cases.json
   (web/tests/issue-query.test.ts and tests/unit/test_issue_search.py), so they cannot drift apart
   silently. Spans count UTF-16 code units here, code points in Python: they differ only for
   characters outside the Basic Multilingual Plane (emoji), and only the browser underlines. */

export type Kind = "enum" | "glob" | "text" | "date";

export const KEYS: Record<string, { kind: Kind; values: string[] }> = {
  status: { kind: "enum", values: ["open", "accepted", "not_a_risk", "fixed"] },
  severity: { kind: "enum", values: ["critical", "high", "medium", "low", "info"] },
  priority: { kind: "enum", values: ["P1", "P2", "P3", "P4", "none"] },
  sla: { kind: "enum", values: ["breached", "due_soon", "on_track"] },
  project: { kind: "glob", values: [] },
  portfolio: { kind: "glob", values: [] },
  path: { kind: "glob", values: [] },
  category: { kind: "enum", values: ["sast", "sca", "secrets", "iac", "container", "dast"] },
  source: { kind: "text", values: [] },
  assignee: { kind: "text", values: [] },
  tag: { kind: "text", values: [] },
  retest: { kind: "enum", values: ["requested", "passed", "failed"] },
  first_seen: { kind: "date", values: [] },
  last_seen: { kind: "date", values: [] },
  fixed: { kind: "date", values: [] },
};
export const ALIASES: Record<string, string> = {
  sev: "severity", prio: "priority", unit: "portfolio", bu: "portfolio", owner: "assignee", state: "status",
};
export const ORDER = Object.keys(KEYS);
const MAX_LENGTH = 2000;
const MAX_TERMS = 40;
const MAX_VALUES = 50;

export class QueryError extends Error {
  constructor(message: string, public start: number, public end: number) {
    super(message);
  }
}

export type DateOp = ">" | ">=" | "<" | "<=";
export interface DateBound { op: DateOp; days?: number; day?: string }
export interface Clause { include: string[]; exclude: string[]; dates: DateBound[] }
export interface Query { clauses: Record<string, Clause>; text: string[] }
export interface Token { start: number; end: number; negated: boolean; key: string | null; values: [string, number, number][] }

const isSpace = (c: string | undefined) => c !== undefined && /\s/.test(c);
const BARE_OK = /^[^\s",:]+$/;

export const dateText = (d: DateBound) => `${d.op}${d.days !== undefined ? `${d.days}d` : d.day}`;
const quote = (v: string) => (BARE_OK.test(v) ? v : `"${v.replaceAll('"', "")}"`);

function readQuoted(text: string, i: number): [string, number] {
  const end = text.indexOf('"', i + 1);
  if (end === -1) throw new QueryError("This quote is never closed.", i, text.length);
  return [text.slice(i + 1, end), end + 1];
}

function readValues(text: string, i: number): [[string, number, number][], number] {
  const values: [string, number, number][] = [];
  const n = text.length;
  for (;;) {
    const start = i;
    let value: string;
    if (i < n && text[i] === '"') {
      [value, i] = readQuoted(text, i);
      if (i < n && !isSpace(text[i]) && text[i] !== ",") throw new QueryError("Leave a space after the closing quote.", start, i + 1);
    } else {
      while (i < n && !isSpace(text[i]) && text[i] !== "," && text[i] !== '"') i++;
      value = text.slice(start, i);
    }
    values.push([value, start, i]);
    if (i < n && text[i] === ",") {
      i++;
      continue;
    }
    return [values, i];
  }
}

/** Split into terms, keeping each one's span. */
export function tokenize(text: string): Token[] {
  if (text.length > MAX_LENGTH) throw new QueryError(`A query is at most ${MAX_LENGTH} characters.`, MAX_LENGTH, text.length);
  const tokens: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (isSpace(text[i])) { i++; continue; }
    const start = i;
    let negated = false;
    if (text[i] === "-" && i + 1 < n && !isSpace(text[i + 1])) { negated = true; i++; }
    if (text[i] === '"') {
      let value: string;
      [value, i] = readQuoted(text, i);
      if (i < n && !isSpace(text[i])) throw new QueryError("Leave a space after the closing quote.", start, i + 1);
      tokens.push({ start, end: i, negated, key: null, values: [[value, start + (negated ? 1 : 0), i]] });
      continue;
    }
    let j = i;
    while (j < n && !isSpace(text[j]) && text[j] !== ":" && text[j] !== '"') j++;
    if (j < n && text[j] === ":") {
      const key = text.slice(i, j);
      let values: [string, number, number][];
      [values, i] = readValues(text, j + 1);
      tokens.push({ start, end: i, negated, key, values });
      continue;
    }
    while (j < n && !isSpace(text[j])) {
      if (text[j] === '"') throw new QueryError("Put quotes around the whole phrase.", start, j + 1);
      j++;
    }
    tokens.push({ start, end: j, negated, key: null, values: [[text.slice(i, j), i, j]] });
    i = j;
  }
  return tokens;
}

/** The key a name means (aliases, any case), or null. */
export function keyOf(name: string): string | null {
  const k = name.toLowerCase();
  const real = ALIASES[k] ?? k;
  return real in KEYS ? real : null;
}

function key(name: string, start: number, end: number): string {
  const k = keyOf(name);
  if (!k) throw new QueryError(`There is no filter called “${name}”. Filters: ${ORDER.join(", ")}.`, start, end);
  return k;
}

const RELATIVE = /^(\d{1,4})d$/;
const ABSOLUTE = /^\d{4}-\d{2}-\d{2}$/;

function realDay(s: string): boolean {
  const [y, m, d] = s.split("-").map(Number);
  const dt = new Date(Date.UTC(y!, m! - 1, d!));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m! - 1 && dt.getUTCDate() === d && y! >= 1;
}

function nextDay(s: string): string {
  const [y, m, d] = s.split("-").map(Number);
  return new Date(Date.UTC(y!, m! - 1, d! + 1)).toISOString().slice(0, 10);
}

function oneDate(value: string, start: number, end: number, next = false): DateBound {
  const m = /^(>=|<=|>|<)?(.*)$/.exec(value)!;
  const op = (m[1] ?? ">=") as DateOp;
  const rest = m[2]!;
  const rel = RELATIVE.exec(rest);
  if (rel) return { op, days: Number(rel[1]) };
  if (ABSOLUTE.test(rest)) {
    if (!realDay(rest)) throw new QueryError(`“${rest}” is not a real date.`, start, end);
    return { op, day: next ? nextDay(rest) : rest };
  }
  throw new QueryError("A date is like >30d (more than 30 days ago), <7d, >=2026-01-01, or 2026-01-01..2026-02-01.", start, end);
}

function dates(value: string, start: number, end: number): DateBound[] {
  if (value.includes("..")) {
    const at = value.indexOf("..");
    const lo = value.slice(0, at);
    const hi = value.slice(at + 2);
    if (/^[<>]/.test(lo) || /^[<>]/.test(hi)) throw new QueryError("A range is two dates: 2026-01-01..2026-02-01.", start, end);
    return [oneDate(`>=${lo}`, start, end), oneDate(`<${hi}`, start, end, true)];
  }
  return [oneDate(value, start, end)];
}

export const emptyClause = (): Clause => ({ include: [], exclude: [], dates: [] });

/** Read a query; throws QueryError with the span at fault. */
export function parse(text: string): Query {
  const tokens = tokenize(text);
  if (tokens.length > MAX_TERMS) throw new QueryError(`A query has at most ${MAX_TERMS} terms.`, tokens[MAX_TERMS]!.start, text.length);
  const q: Query = { clauses: {}, text: [] };
  for (const t of tokens) {
    if (t.key === null) {
      const word = t.values[0]![0].trim();
      if (t.negated) throw new QueryError("Free text cannot be excluded; use a filter.", t.start, t.end);
      if (word && !q.text.some((w) => w.toLowerCase() === word.toLowerCase())) q.text.push(word);
      continue;
    }
    const k = key(t.key, t.start, t.start + t.key.length + (t.negated ? 1 : 0));
    const { kind, values: allowed } = KEYS[k]!;
    const clause = (q.clauses[k] ??= emptyClause());
    for (const [raw, vs, ve] of t.values) {
      let value = raw;
      if (!value) throw new QueryError(`“${k}:” needs a value.`, t.start, Math.max(ve, t.end));
      if (kind === "date") {
        if (t.negated) throw new QueryError("Write the opposite comparison instead of “-”.", t.start, t.end);
        clause.dates.push(...dates(value, vs, ve));
        continue;
      }
      if (kind === "enum") {
        const match = allowed.find((a) => a.toLowerCase() === value.toLowerCase());
        if (!match) throw new QueryError(`“${value}” is not a ${k}. Choose from: ${allowed.join(", ")}.`, vs, ve);
        value = match;
      } else if (value.includes("*") && kind !== "glob") {
        throw new QueryError(`“*” works in project, portfolio and path, not ${k}.`, vs, ve);
      }
      const target = t.negated ? clause.exclude : clause.include;
      if (!target.includes(value)) target.push(value);
      if (clause.include.length + clause.exclude.length > MAX_VALUES) throw new QueryError(`At most ${MAX_VALUES} values for ${k}.`, vs, ve);
    }
  }
  for (const k of Object.keys(q.clauses)) {
    const c = q.clauses[k]!;
    if (!c.include.length && !c.exclude.length && !c.dates.length) delete q.clauses[k];
  }
  return q;
}

/** The plain, ordered form the shared fixtures compare against. */
export function toDict(q: Query): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of ORDER) {
    const c = q.clauses[k];
    if (!c) continue;
    const entry: Record<string, unknown> = {};
    if (c.include.length) entry.include = c.include;
    if (c.exclude.length) entry.exclude = c.exclude;
    if (c.dates.length) entry.dates = c.dates.map(dateText);
    if (Object.keys(entry).length) out[k] = entry;
  }
  if (q.text.length) out.text = q.text;
  return out;
}

/** Write a query back as text, in the fixed order: how the panel updates the query bar. */
export function formatQuery(q: Query): string {
  const parts: string[] = [];
  for (const k of ORDER) {
    const c = q.clauses[k];
    if (!c) continue;
    if (c.include.length) parts.push(`${k}:${c.include.map(quote).join(",")}`);
    if (c.exclude.length) parts.push(`-${k}:${c.exclude.map(quote).join(",")}`);
    for (const d of c.dates) parts.push(`${k}:${dateText(d)}`);
  }
  parts.push(...q.text.map(quote));
  return parts.join(" ");
}

/** A copy with one key's values replaced (the panel's edits); an empty clause removes the key. */
export function withClause(q: Query, k: string, next: Partial<Clause>): Query {
  const clause = { ...(q.clauses[k] ?? emptyClause()), ...next };
  const clauses = { ...q.clauses };
  if (!clause.include.length && !clause.exclude.length && !clause.dates.length) delete clauses[k];
  else clauses[k] = clause;
  return { clauses, text: [...q.text] };
}

/** What the caret is in, for autocomplete: a key being typed, or a value of a key. */
export function caretContext(text: string, caret: number): { kind: "key" | "value"; key?: string; prefix: string; start: number } {
  let start = caret;
  while (start > 0 && !isSpace(text[start - 1])) start--;
  const word = text.slice(start, caret);
  const neg = word.startsWith("-") ? 1 : 0;
  const colon = word.indexOf(":");
  if (colon === -1) return { kind: "key", prefix: word.slice(neg), start: start + neg };
  const k = keyOf(word.slice(neg, colon)) ?? word.slice(neg, colon).toLowerCase();
  const afterComma = word.lastIndexOf(",");
  const vStart = afterComma > colon ? afterComma + 1 : colon + 1;
  return { kind: "value", key: k, prefix: word.slice(vStart).replace(/^"/, ""), start: start + vStart };
}
