"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useState } from "react";
import {
  ApiError, createRule, getRule, getRulesCatalogue, listAssets, listPeople, listRuleTemplates, testRuleDraft, updateRule,
} from "@/lib/api";
import type { AssetSummary, Person, RuleAction, RuleDryRun, RuleInput, RulesCatalogue, RuleTemplate, RuleTrigger } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./automation.css";

/** Plan §55.7: "Trigger, condition, and action builders, with a Rego view for people who prefer to
 * write the condition. Test this rule runs the dry run against the last 7 days." The builder writes
 * Rego; the Rego view shows the module OPA runs. A condition written by hand stays hand-written --
 * the builder only takes over again if every line is one it understands. */

export type Op = "==" | "!=" | ">=" | "<=" | "contains" | "set" | "unset";
export type Row = { path: string; op: Op; value: string };

const BOOL = new Set(["input.issue.in_cisa_kev", "input.issue.reachable", "input.project.internet_facing"]);
const NUM = new Set(["input.issue.priority_score", "input.issue.age_days", "input.project.days_since_scan", "input.scan.counts.new"]);
const LIST = new Set(["input.issue.tags", "input.issue.cwe", "input.project.tags"]);
const OP_WORD: Record<Op, string> = {
  "==": "is", "!=": "is not", ">=": "is at least", "<=": "is at most", contains: "contains", set: "is set", unset: "is not set",
};

function literal(path: string, value: string): string {
  const v = value.trim();
  if (BOOL.has(path)) return v === "false" ? "false" : "true";
  if (NUM.has(path) && /^-?\d+(\.\d+)?$/.test(v)) return v;
  return JSON.stringify(v);
}

export function toRego(rows: Row[]): string {
  return rows
    .filter((r) => r.path)
    .map((r) => {
      if (r.op === "set") return r.path;
      if (r.op === "unset") return `not ${r.path}`;
      if (r.op === "contains") return `${r.path}[_] == ${literal(r.path, r.value)}`;
      return `${r.path} ${r.op} ${literal(r.path, r.value)}`;
    })
    .join("\n");
}

const LINE = /^(input(?:\.[a-z_]+)+)(\[_\])? (==|!=|>=|<=) (.+)$/;

/** The builder's rows for a condition, or null when a line is something it did not write. */
export function fromRego(condition: string): Row[] | null {
  const rows: Row[] = [];
  for (const raw of condition.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const not = /^not (input(?:\.[a-z_]+)+)$/.exec(line);
    if (not) { rows.push({ path: not[1]!, op: "unset", value: "" }); continue; }
    if (/^input(?:\.[a-z_]+)+$/.test(line)) { rows.push({ path: line, op: "set", value: "" }); continue; }
    const m = LINE.exec(line);
    if (!m) return null;
    const [, path, each, op, lit] = m as unknown as [string, string, string | undefined, string, string];
    let value: string;
    try {
      const parsed = JSON.parse(lit);
      if (typeof parsed === "object" && parsed !== null) return null;
      value = String(parsed);
    } catch {
      return null;
    }
    if (each) {
      if (op !== "==") return null;
      rows.push({ path, op: "contains", value });
    } else {
      rows.push({ path, op: op as Op, value });
    }
  }
  return rows;
}

export function moduleFor(condition: string): string {
  const body = condition.trim() ? condition.split("\n").map((l) => `  ${l}`.trimEnd()).join("\n") : "  true";
  return `package bulwark.rule\n\nimport rego.v1\n\ndefault match := false\n\nmatch if {\n${body}\n}`;
}

const EMPTY: RuleInput = { name: "", trigger: "issue.created", trigger_params: {}, condition: "", actions: [{ type: "tag", tags: [] }], confirm_over: 25, enabled: true };

function blankAction(type: RuleAction["type"]): RuleAction {
  switch (type) {
    case "assign": return { type, to: "" };
    case "set_priority": return { type, band: "P1" };
    case "tag": return { type, tags: [] };
    case "request_retest": return { type, note: "" };
    case "request_fix": return { type, max_per_day: 3 };
    case "notify": return { type, message: "" };
    case "group": return { type, name: "" };
    case "ticket": return { type };
  }
}

/** A list typed as words: the text stays as typed (a trailing space included) while the parsed
 * list goes up on every keystroke. */
function ListInput({ value, onChange, prefix = "", ...rest }: {
  value: string[]; onChange: (v: string[]) => void; prefix?: string;
} & Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  const [text, setText] = useState(value.map((v) => `${prefix}${v}`).join(" "));
  return (
    <input {...rest} value={text} onChange={(e) => {
      setText(e.target.value);
      onChange(e.target.value.split(/[\s,]+/).map((v) => (prefix ? v.replace(new RegExp(`^${prefix}`), "") : v)).filter(Boolean));
    }} />
  );
}

/** "actions.0.to" -> "choose who action 1 assigns to". */
export function needWords(path: string): string {
  const m = /^actions\.(\d+)\.(\w+)$/.exec(path);
  if (!m) return `fill in ${path}`;
  const n = Number(m[1]) + 1;
  return { to: `choose who action ${n} assigns to`, people: `name who action ${n} tells`, name: `name the group in action ${n}` }[m[2]!] ?? `fill in action ${n}`;
}

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

export function RuleEditor({ ruleId, templateKey }: { ruleId?: string; templateKey?: string }) {
  const fid = useId();
  const router = useRouter();
  const [cat, setCat] = useState<RulesCatalogue | null>(null);
  const [projects, setProjects] = useState<AssetSummary[]>([]);
  const [people, setPeople] = useState<Person[]>([]);
  const [draft, setDraft] = useState<RuleInput>(EMPTY);
  const [rows, setRows] = useState<Row[] | null>([]);
  const [regoText, setRegoText] = useState("");
  const [showRego, setShowRego] = useState(false);
  const [needs, setNeeds] = useState<string[]>([]);
  const [dry, setDry] = useState<RuleDryRun | null>(null);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    getRulesCatalogue().then(setCat, () => setError({ message: "Could not load the rule catalogue." }));
    listAssets().then((a) => setProjects(Array.isArray(a) ? a : []), () => setProjects([]));
    listPeople().then((p) => setPeople(Array.isArray(p) ? p : []), () => setPeople([]));
    const load = async () => {
      let start: RuleInput = EMPTY;
      if (ruleId) {
        const r = await getRule(ruleId);
        start = { name: r.name, description: r.description, project_id: r.project_id, enabled: r.enabled, trigger: r.trigger,
                  trigger_params: r.trigger_params, condition: r.condition, actions: r.actions, confirm_over: r.confirm_over, template: r.template };
      } else if (templateKey) {
        const t = (await listRuleTemplates()).find((x: RuleTemplate) => x.key === templateKey);
        if (t) {
          start = { ...EMPTY, ...t.draft };
          setNeeds(t.needs);
        }
      }
      setDraft(start);
      setRows(fromRego(start.condition));
      setRegoText(start.condition);
      setShowRego(fromRego(start.condition) === null);
      setLoaded(true);
    };
    load().catch((e) => setError({ message: e instanceof ApiError ? e.message : "Could not load the rule." }));
  }, [ruleId, templateKey]);

  const trigger = cat?.triggers.find((t) => t.key === draft.trigger);
  const subject = trigger?.subject ?? "issue";
  const fields = useMemo(() => {
    if (!cat) return [];
    const list = subject === "issue" ? [...cat.fields.issue!, ...cat.fields.project!] : [...cat.fields.project!];
    return [...list, ...cat.fields.event!];
  }, [cat, subject]);
  const condition = rows !== null ? toRego(rows) : regoText;
  const body: RuleInput = { ...draft, condition };

  function set<K extends keyof RuleInput>(key: K, value: RuleInput[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
    setDry(null);
  }
  function setParam(key: string, value: unknown) {
    set("trigger_params", { ...(draft.trigger_params ?? {}), [key]: value });
  }
  function setAction(i: number, a: RuleAction) {
    set("actions", draft.actions.map((x, j) => (j === i ? a : x)));
  }
  function setRow(i: number, r: Row) {
    setRows((rs) => (rs ?? []).map((x, j) => (j === i ? r : x)));
    setDry(null);
  }

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      if (e instanceof ApiError) {
        const d = e.data as { field?: string } | undefined;
        setError({ field: d?.field, message: e.message });
      } else setError({ message: "That did not work." });
    } finally {
      setBusy(false);
    }
  }

  const test = () => run(async () => setDry(await testRuleDraft(body)));
  const save = () => run(async () => {
    const saved = ruleId ? await updateRule(ruleId, body) : await createRule(body);
    router.push(`/app/automation?saved=${saved.id}`);
  });

  if (!cat || !loaded) return error ? <p role="alert" className="ds-au-error">{error.message}</p> : <p role="status">Loading the editor…</p>;
  const fieldError = (f: string) => (error?.field && (error.field === f || error.field.startsWith(`${f}.`)) ? error.message : null);
  const allowed = cat.actions.filter((a) => a.subjects.includes(subject));
  const p = draft.trigger_params ?? {};

  return (
    <form className="ds-au ds-ed" onSubmit={(e) => { e.preventDefault(); void save(); }} aria-labelledby={`${fid}-h`}>
      <div className="ds-au-top">
        <h1 id={`${fid}-h`}>{ruleId ? "Edit rule" : "New rule"}</h1>
        <Link href="/app/automation">Back to automation</Link>
      </div>
      {needs.length > 0 && <p className="ds-au-meta">Before saving, {needs.map(needWords).join(" and ")}.</p>}

      <div className="ds-ed-row">
        <label htmlFor={`${fid}-name`}>Name</label>
        <input id={`${fid}-name`} value={draft.name} maxLength={120} onChange={(e) => set("name", e.target.value)} aria-invalid={!!fieldError("name")} />
        {fieldError("name") && <p className="ds-au-error">{fieldError("name")}</p>}
      </div>
      <div className="ds-ed-row">
        <label htmlFor={`${fid}-project`}>Applies to</label>
        <select id={`${fid}-project`} value={draft.project_id ?? ""} onChange={(e) => set("project_id", e.target.value || null)}>
          <option value="">Every project</option>
          {projects.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
        </select>
      </div>

      <fieldset className="ds-ed-block">
        <legend><span className="ds-au-word">WHEN</span></legend>
        <label htmlFor={`${fid}-trigger`} className="ds-ed-sub">Trigger</label>
        <select id={`${fid}-trigger`} value={draft.trigger} onChange={(e) => {
          const t = e.target.value as RuleTrigger;
          const subj = cat.triggers.find((x) => x.key === t)?.subject;
          setDraft((d) => ({ ...d, trigger: t, trigger_params: t === "project.quiet" ? { days: 14 } : t === "schedule" ? { every: "day", hour: 9 } : {},
                              actions: d.actions.filter((a) => cat.actions.find((c) => c.key === a.type)?.subjects.includes(subj ?? "issue")) }));
          setDry(null);
        }}>
          <optgroup label="About an issue">{cat.triggers.filter((t) => t.subject === "issue").map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}</optgroup>
          <optgroup label="About a project">{cat.triggers.filter((t) => t.subject === "project").map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}</optgroup>
        </select>
        {trigger?.help && <p className="ds-au-meta">{trigger.help}</p>}
        {draft.trigger === "project.quiet" && (
          <div className="ds-ed-inline">
            <label htmlFor={`${fid}-days`}>Days without a scan</label>
            <input id={`${fid}-days`} type="number" min={1} max={365} value={Number(p.days ?? 14)} onChange={(e) => setParam("days", Number(e.target.value))} />
          </div>
        )}
        {draft.trigger === "schedule" && (
          <div className="ds-ed-inline">
            <label htmlFor={`${fid}-every`}>Every</label>
            <select id={`${fid}-every`} value={String(p.every ?? "day")} onChange={(e) => setParam("every", e.target.value)}>
              <option value="hour">hour</option><option value="day">day</option><option value="week">week</option>
            </select>
            {p.every === "week" && (
              <>
                <label htmlFor={`${fid}-weekday`}>on</label>
                <select id={`${fid}-weekday`} value={Number(p.weekday ?? 0)} onChange={(e) => setParam("weekday", Number(e.target.value))}>
                  {WEEKDAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
                </select>
              </>
            )}
            {p.every !== "hour" && (
              <>
                <label htmlFor={`${fid}-hour`}>at (UTC)</label>
                <select id={`${fid}-hour`} value={Number(p.hour ?? 9)} onChange={(e) => setParam("hour", Number(e.target.value))}>
                  {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, "0")}:00</option>)}
                </select>
              </>
            )}
          </div>
        )}
        {fieldError("trigger") && <p className="ds-au-error">{fieldError("trigger")}</p>}
      </fieldset>

      <fieldset className="ds-ed-block">
        <legend><span className="ds-au-word">IF</span></legend>
        <div className="ds-ed-tabs" role="group" aria-label="How to write the condition">
          <Button type="button" aria-pressed={!showRego} onClick={() => {
            const parsed = fromRego(condition);
            if (parsed === null) { setError({ field: "condition", message: "The builder cannot show this condition; edit it in the Rego view." }); return; }
            setRows(parsed);
            setShowRego(false);
          }}>Builder</Button>
          <Button type="button" aria-pressed={showRego} onClick={() => { setRegoText(condition); setShowRego(true); }}>Rego</Button>
        </div>
        {!showRego && rows !== null && (
          <>
            {rows.length === 0 && <p className="ds-au-meta">No conditions: the rule acts every time it is triggered.</p>}
            <ul className="ds-ed-conds">
              {rows.map((r, i) => (
                <li key={i} className="ds-ed-cond">
                  <select aria-label={`Condition ${i + 1}: field`} value={r.path} onChange={(e) => setRow(i, { ...r, path: e.target.value, op: LIST.has(e.target.value) ? "contains" : r.op === "contains" ? "==" : r.op })}>
                    {fields.map((f) => <option key={f.path} value={f.path}>{f.path.replace(/^input\./, "")}</option>)}
                  </select>
                  <select aria-label={`Condition ${i + 1}: test`} value={r.op} onChange={(e) => setRow(i, { ...r, op: e.target.value as Op })}>
                    {(LIST.has(r.path) ? (["contains", "set", "unset"] as Op[]) : NUM.has(r.path) ? (["==", "!=", ">=", "<=", "set", "unset"] as Op[]) : (["==", "!=", "set", "unset"] as Op[]))
                      .map((o) => <option key={o} value={o}>{OP_WORD[o]}</option>)}
                  </select>
                  {r.op !== "set" && r.op !== "unset" && (
                    BOOL.has(r.path) ? (
                      <select aria-label={`Condition ${i + 1}: value`} value={r.value || "true"} onChange={(e) => setRow(i, { ...r, value: e.target.value })}>
                        <option value="true">true</option><option value="false">false</option>
                      </select>
                    ) : (
                      <input aria-label={`Condition ${i + 1}: value`} value={r.value} onChange={(e) => setRow(i, { ...r, value: e.target.value })}
                             placeholder={fields.find((f) => f.path === r.path)?.help ?? ""} />
                    )
                  )}
                  <Button type="button" aria-label={`Remove condition ${i + 1}`} onClick={() => setRows(rows.filter((_, j) => j !== i))}>×</Button>
                </li>
              ))}
            </ul>
            <Button type="button" onClick={() => setRows([...rows, { path: fields[0]?.path ?? "input.issue.severity", op: "==", value: "" }])}>Add a condition</Button>
            <p className="ds-au-meta">All conditions must hold.</p>
          </>
        )}
        {showRego && (
          <div className="ds-ed-rego">
            <pre aria-hidden="true" className="ds-ed-rego-frame">{"package bulwark.rule\n\nimport rego.v1\n\nmatch if {"}</pre>
            <label htmlFor={`${fid}-rego`} className="ds-ed-sub">Condition lines (Rego; all must hold)</label>
            <textarea id={`${fid}-rego`} rows={6} spellCheck={false} value={regoText} aria-invalid={!!fieldError("condition")}
                      onChange={(e) => { setRegoText(e.target.value); setRows(null); setDry(null); }} />
            <pre aria-hidden="true" className="ds-ed-rego-frame">{"}"}</pre>
            <details>
              <summary>The whole module OPA runs</summary>
              <pre className="ds-ed-module">{moduleFor(condition)}</pre>
            </details>
          </div>
        )}
        {fieldError("condition") && <p role="alert" className="ds-au-error ds-ed-pre">{fieldError("condition")}</p>}
      </fieldset>

      <fieldset className="ds-ed-block">
        <legend><span className="ds-au-word">THEN</span></legend>
        <ol className="ds-ed-actions">
          {draft.actions.map((a, i) => (
            <li key={i} className="ds-ed-action">
              <select aria-label={`Action ${i + 1}`} value={a.type} onChange={(e) => setAction(i, blankAction(e.target.value as RuleAction["type"]))}>
                {allowed.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}
              </select>
              {a.type === "assign" && (
                <select aria-label={`Action ${i + 1}: person`} value={a.to.replace(/^@/, "")} onChange={(e) => setAction(i, { ...a, to: e.target.value })}>
                  <option value="">Choose a person</option>
                  {people.map((p2) => <option key={p2.actor} value={p2.handle}>{p2.name} (@{p2.handle})</option>)}
                </select>
              )}
              {a.type === "set_priority" && (
                <select aria-label={`Action ${i + 1}: band`} value={a.band} onChange={(e) => setAction(i, { ...a, band: e.target.value })}>
                  {["P1", "P2", "P3", "P4"].map((b) => <option key={b}>{b}</option>)}
                </select>
              )}
              {a.type === "tag" && (
                <ListInput aria-label={`Action ${i + 1}: tags`} placeholder="tags, separated by spaces" value={a.tags}
                           onChange={(tags) => setAction(i, { ...a, tags })} />
              )}
              {a.type === "group" && (
                <input aria-label={`Action ${i + 1}: group name`} placeholder="Group name" value={a.name}
                       onChange={(e) => setAction(i, { ...a, name: e.target.value })} />
              )}
              {a.type === "request_fix" && (
                <input aria-label={`Action ${i + 1}: at most per day`} type="number" min={1} max={20} value={a.max_per_day ?? 3}
                       onChange={(e) => setAction(i, { ...a, max_per_day: Number(e.target.value) })} />
              )}
              {(a.type === "notify" || a.type === "request_retest") && (
                <input aria-label={`Action ${i + 1}: ${a.type === "notify" ? "message" : "note"}`} placeholder={a.type === "notify" ? "Message (optional)" : "Note (optional)"}
                       value={(a.type === "notify" ? a.message : a.note) ?? ""}
                       onChange={(e) => setAction(i, a.type === "notify" ? { ...a, message: e.target.value } : { ...a, note: e.target.value })} />
              )}
              {a.type === "notify" && (
                <ListInput aria-label={`Action ${i + 1}: people`} placeholder="@people (optional)" prefix="@" value={a.people ?? []}
                           onChange={(people) => setAction(i, { ...a, people })} />
              )}
              <Button type="button" aria-label={`Remove action ${i + 1}`} disabled={draft.actions.length === 1} onClick={() => set("actions", draft.actions.filter((_, j) => j !== i))}>×</Button>
              {fieldError(`actions.${i}`) && <p className="ds-au-error">{fieldError(`actions.${i}`)}</p>}
              {allowed.find((x) => x.key === a.type)?.help && <p className="ds-au-meta">{allowed.find((x) => x.key === a.type)!.help}</p>}
            </li>
          ))}
        </ol>
        <Button type="button" disabled={draft.actions.length >= cat.limits.max_actions} onClick={() => set("actions", [...draft.actions, blankAction(allowed[0]?.key ?? "notify")])}>Add an action</Button>
        {fieldError("actions") && error?.field === "actions" && <p className="ds-au-error">{error.message}</p>}
      </fieldset>

      <div className="ds-ed-row">
        <label htmlFor={`${fid}-confirm`}>Ask an Admin first when one cause would touch more than</label>
        <div className="ds-ed-inline">
          <input id={`${fid}-confirm`} type="number" min={1} max={cat.limits.max_confirm_over} value={draft.confirm_over ?? 25}
                 onChange={(e) => set("confirm_over", Number(e.target.value))} /> <span>issues</span>
        </div>
      </div>
      <label className="ds-ed-check"><input type="checkbox" checked={draft.enabled ?? true} onChange={(e) => set("enabled", e.target.checked)} /> On</label>

      {dry && (
        <div className="ds-au-dry" role="status">
          <p>{dry.sentence}</p>
          <p className="ds-au-meta">{dry.note}</p>
          {dry.sample.length > 0 && (
            <ul className="ds-au-subjects">
              {dry.sample.map((x) => <li key={x.id}>{x.text}</li>)}
            </ul>
          )}
        </div>
      )}
      {error && !["name", "condition"].includes(error.field ?? "") && !error.field?.startsWith("actions") && error.field !== "trigger" && (
        <p role="alert" className="ds-au-error">{error.message}</p>
      )}
      <div className="ds-au-actions">
        <Button type="button" disabled={busy} onClick={() => void test()}>Test this rule</Button>
        <Button type="submit" variant="primary" disabled={busy || !draft.name.trim()}>{ruleId ? "Save changes" : "Save rule"}</Button>
      </div>
    </form>
  );
}
