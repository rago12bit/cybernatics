"use client";

import { useEffect, useId, useState } from "react";
import { suggestIssueValues } from "@/lib/api";
import { KEYS, dateText, emptyClause, withClause, type DateBound, type DateOp, type Query } from "@/lib/issue-query";
import { GROUPS, KEY_LABEL, activeCount, dateWords, toggled, valueLabel } from "@/lib/issues";

/* The grouped filter panel (plan §56): Status; Severity and priority; Location; Source; Ownership
 * and SLA; Dates. Each group folds away and, folded, says how many of its filters are on. Every
 * change here is written straight back into the query bar, and the query bar's into here. */

function Values({ q, k, onChange, quiet }: { q: Query; k: string; onChange: (q: Query) => void; quiet?: boolean }) {
  const c = q.clauses[k] ?? emptyClause();
  return (
    <fieldset className="iss-values">
      <legend className={quiet ? "sr-only" : "iss-label"}>{KEY_LABEL[k]}</legend>
      {KEYS[k]!.values.map((v) => (
        <label key={v} className="iss-check">
          <input type="checkbox" checked={c.include.includes(v)} onChange={(e) => onChange(toggled(q, k, v, e.target.checked))} />
          {valueLabel(v)}
        </label>
      ))}
      {c.exclude.length > 0 && <p className="iss-small">Leaving out: {c.exclude.map(valueLabel).join(", ")}</p>}
    </fieldset>
  );
}

function Names({ q, k, onChange }: { q: Query; k: string; onChange: (q: Query) => void }) {
  const id = useId();
  const c = q.clauses[k] ?? emptyClause();
  const [text, setText] = useState("");
  const [offers, setOffers] = useState<string[]>([]);
  const remote = k === "project" || k === "portfolio" || k === "assignee" || k === "tag" || k === "source";
  useEffect(() => {
    if (!remote) return;
    const ac = new AbortController();
    const t = setTimeout(() => suggestIssueValues(k, text, ac.signal).then((r) => setOffers(r.values), () => undefined), 150);
    return () => { clearTimeout(t); ac.abort(); };
  }, [k, text, remote]);
  const add = () => {
    const t = text.trim();
    const v = k === "assignee" ? t.replace(/^@/, "") : t;
    if (!v) return;
    onChange(withClause(q, k, { include: [...c.include.filter((x) => x !== v), v] }));
    setText("");
  };
  const remove = (v: string, from: "include" | "exclude") => onChange(withClause(q, k, { [from]: c[from].filter((x) => x !== v) }));
  return (
    <div className="iss-names">
      <label htmlFor={`${id}-in`} className="iss-label">{KEY_LABEL[k]}</label>
      <div className="iss-add">
        <input id={`${id}-in`} value={text} list={remote ? `${id}-dl` : undefined} onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }}
          placeholder={KEYS[k]!.kind === "glob" ? "a name, * allowed" : k === "assignee" ? "@handle, me or none" : "a name"} />
        <button type="button" className="ds-button" onClick={add} disabled={!text.trim()} aria-label={`Add ${KEY_LABEL[k]!.toLowerCase()}`}>Add</button>
      </div>
      {remote && <datalist id={`${id}-dl`}>{offers.map((o) => <option key={o} value={o} />)}</datalist>}
      {(c.include.length > 0 || c.exclude.length > 0) && (
        <ul className="iss-tokens" aria-label={`${KEY_LABEL[k]} filters`}>
          {c.include.map((v) => <li key={`+${v}`}><span>{v}</span><button type="button" onClick={() => remove(v, "include")} aria-label={`Remove ${KEY_LABEL[k]} ${v}`}>×</button></li>)}
          {c.exclude.map((v) => <li key={`-${v}`}><span>not {v}</span><button type="button" onClick={() => remove(v, "exclude")} aria-label={`Remove ${KEY_LABEL[k]} not ${v}`}>×</button></li>)}
        </ul>
      )}
    </div>
  );
}

function Dates({ q, k, onChange }: { q: Query; k: string; onChange: (q: Query) => void }) {
  const id = useId();
  const c = q.clauses[k] ?? emptyClause();
  const [op, setOp] = useState<DateOp>("<");
  const [days, setDays] = useState("30");
  const n = Number(days);
  const ok = Number.isInteger(n) && n >= 0 && n <= 36500;
  const add = () => {
    if (!ok) return;
    const d: DateBound = { op, days: n };
    onChange(withClause(q, k, { dates: [...c.dates.filter((x) => dateText(x) !== dateText(d)), d] }));
  };
  return (
    <fieldset className="iss-values">
      <legend className="iss-label">{KEY_LABEL[k]}</legend>
      <div className="iss-add">
        <label htmlFor={`${id}-op`} className="sr-only">{KEY_LABEL[k]}: when</label>
        <select id={`${id}-op`} value={op} onChange={(e) => setOp(e.target.value as DateOp)}>
          <option value="<">in the last</option>
          <option value=">">more than</option>
        </select>
        <label htmlFor={`${id}-n`} className="sr-only">Days</label>
        <input id={`${id}-n`} type="number" min={0} max={36500} value={days} onChange={(e) => setDays(e.target.value)} className="iss-days" />
        <span aria-hidden="true">{op === ">" ? "days ago" : "days"}</span>
        <button type="button" className="ds-button" onClick={add} disabled={!ok} aria-label={`Add ${KEY_LABEL[k]!.toLowerCase()} date`}>Add</button>
      </div>
      {c.dates.length > 0 && (
        <ul className="iss-tokens">
          {c.dates.map((d) => (
            <li key={dateText(d)}><span>{dateWords(d)}</span>
              <button type="button" aria-label={`Remove ${KEY_LABEL[k]} ${dateWords(d)}`}
                onClick={() => onChange(withClause(q, k, { dates: c.dates.filter((x) => dateText(x) !== dateText(d)) }))}>×</button>
            </li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

const OPEN_BY_DEFAULT = new Set(["status", "severity"]);

export function FilterPanel({ q, onChange }: { q: Query; onChange: (q: Query) => void }) {
  const id = useId();
  const [open, setOpen] = useState<Set<string>>(() => {
    const s = new Set(OPEN_BY_DEFAULT);
    for (const g of GROUPS) if (activeCount(q, g.keys) > 0) s.add(g.id);
    return s;
  });
  const flip = (g: string) => setOpen((cur) => { const n = new Set(cur); if (n.has(g)) n.delete(g); else n.add(g); return n; });
  return (
    <div className="iss-panel">
      <h2 className="iss-views-head iss-panel-head">Filters</h2>
      {GROUPS.map((g) => {
        const n = activeCount(q, g.keys);
        const isOpen = open.has(g.id);
        return (
          <section key={g.id} className="iss-group" aria-labelledby={`${id}-${g.id}-h`}>
            <h3 id={`${id}-${g.id}-h`} className="iss-group-head">
              <button type="button" aria-expanded={isOpen} aria-controls={`${id}-${g.id}`} onClick={() => flip(g.id)}>
                <span className="iss-caret" aria-hidden="true">{isOpen ? "▾" : "▸"}</span>
                {g.title}
                {n > 0 && <span className="iss-count">{n} active</span>}
              </button>
            </h3>
            <div id={`${id}-${g.id}`} hidden={!isOpen} className="iss-group-body">
              {g.keys.map((k) => {
                const kind = KEYS[k]!.kind;
                if (kind === "enum") return <Values key={k} q={q} k={k} onChange={onChange} quiet={g.keys.length === 1} />;
                if (kind === "date") return <Dates key={k} q={q} k={k} onChange={onChange} />;
                return <Names key={k} q={q} k={k} onChange={onChange} />;
              })}
            </div>
          </section>
        );
      })}
      {(q.clauses.status === undefined) && <p className="iss-small iss-muted">No status chosen: the list shows the active queue (open, and accepted whose acceptance ran out).</p>}
    </div>
  );
}
