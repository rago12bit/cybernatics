"use client";

import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { suggestIssueValues } from "@/lib/api";
import { KEYS, caretContext } from "@/lib/issue-query";
import { KEY_LABEL } from "@/lib/issues";

/* The query bar (plan §56: "a query language for experts, with autocomplete"). A combobox: as you
 * type it offers keys, then values (the enum values here, projects, people, tags and sources from
 * the server). A mistake is underlined where it is, in the echo below the field, with what was
 * expected. */

type Option = { insert: string; label: string; hint?: string };
const BARE = /^[^\s",:]+$/;

export function QueryBar({ value, error, onChange, onSubmit }: {
  value: string;
  error: { message: string; start: number; end: number } | null;
  onChange: (text: string) => void;
  onSubmit: () => void;
}) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [options, setOptions] = useState<Option[]>([]);
  const [active, setActive] = useState(-1);
  const [open, setOpen] = useState(false);
  const [ctx, setCtx] = useState<ReturnType<typeof caretContext> | null>(null);

  function look(text: string, caret: number) {
    const c = caretContext(text, caret);
    setCtx(c);
    if (c.kind === "key") {
      const p = c.prefix.toLowerCase();
      const keys = Object.keys(KEYS).filter((k) => k.startsWith(p) && p.length > 0);
      setOptions(keys.map((k) => ({ insert: `${k}:`, label: `${k}:`, hint: KEY_LABEL[k] })));
      setActive(-1);
      setOpen(keys.length > 0);
      return;
    }
    const spec = c.key ? KEYS[c.key] : undefined;
    if (!spec) { setOpen(false); return; }
    if (spec.values.length) {
      const vs = spec.values.filter((v) => v.toLowerCase().startsWith(c.prefix.toLowerCase()));
      setOptions(vs.map((v) => ({ insert: v, label: v })));
      setActive(-1);
      setOpen(vs.length > 0);
    } else if (spec.kind === "date") {
      const vs = [">30d", "<7d", ">90d", ">=2026-01-01"].filter((v) => v.startsWith(c.prefix));
      setOptions(vs.map((v) => ({ insert: v, label: v, hint: v.endsWith("d") ? (v.startsWith(">") ? "older than" : "within") : "on or after" })));
      setActive(-1);
      setOpen(vs.length > 0);
    } else if (c.key) {
      setRemoteFor({ key: c.key, prefix: c.prefix });
    }
  }

  // Server suggestions (projects, people, tags...), a moment after typing stops.
  const [remoteFor, setRemoteFor] = useState<{ key: string; prefix: string } | null>(null);
  useEffect(() => {
    if (!remoteFor) return;
    const ac = new AbortController();
    const t = setTimeout(() => {
      suggestIssueValues(remoteFor.key, remoteFor.prefix, ac.signal).then((r) => {
        setOptions(r.values.map((v) => ({ insert: BARE.test(v) ? v : `"${v}"`, label: v })));
        setActive(-1);
        setOpen(r.values.length > 0);
      }, () => undefined);
    }, 150);
    return () => { clearTimeout(t); ac.abort(); };
  }, [remoteFor]);

  function pick(o: Option) {
    if (!ctx) return;
    const caret = input.current?.selectionStart ?? value.length;
    const next = value.slice(0, ctx.start) + o.insert + value.slice(caret);
    const at = ctx.start + o.insert.length;
    onChange(next);
    setOpen(false);
    requestAnimationFrame(() => {
      input.current?.setSelectionRange(at, at);
      input.current?.focus();
      if (o.insert.endsWith(":")) look(next, at);
    });
  }

  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (open && options.length && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      e.preventDefault();
      setActive((a) => (e.key === "ArrowDown" ? (a + 1) % options.length : (a - 1 + options.length) % options.length));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (open && active >= 0 && options[active]) pick(options[active]!);
      else { setOpen(false); onSubmit(); }
    } else if (e.key === "Tab" && open && active >= 0 && options[active]) {
      e.preventDefault();
      pick(options[active]!);
    } else if (e.key === "Escape" && open) {
      e.preventDefault();
      setOpen(false);
    }
  }

  const listId = `${id}-list`;
  return (
    <div className="iss-query">
      <label htmlFor={`${id}-q`} className="iss-label">Query</label>
      <div className="iss-query-row">
        <input
          ref={input}
          id={`${id}-q`}
          className="iss-query-input"
          role="combobox"
          aria-expanded={open}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={open && active >= 0 ? `${id}-o${active}` : undefined}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${id}-err` : `${id}-help`}
          spellCheck={false}
          autoComplete="off"
          value={value}
          placeholder="priority:P1 sla:breached project:payments-* -status:accepted"
          onChange={(e) => { onChange(e.target.value); look(e.target.value, e.target.selectionStart ?? e.target.value.length); }}
          onKeyDown={onKey}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onClick={(e) => look(value, e.currentTarget.selectionStart ?? value.length)}
          maxLength={2000}
        />
        <button type="button" className="ds-button" onClick={onSubmit}>Search</button>
      </div>
      <ul id={listId} role="listbox" className="iss-suggest" hidden={!open} aria-label="Suggestions">
        {options.map((o, i) => (
          <li key={o.insert} id={`${id}-o${i}`} role="option" aria-selected={i === active}
            className={i === active ? "active" : undefined}
            onMouseDown={(e) => { e.preventDefault(); pick(o); }}>
            <code>{o.label}</code>{o.hint && <span className="iss-hint"> {o.hint}</span>}
          </li>
        ))}
      </ul>
      {error ? (
        <div id={`${id}-err`} role="alert" className="iss-query-error">
          <p className="iss-echo" aria-hidden="true">
            {value.slice(0, error.start)}
            <mark>{value.slice(error.start, Math.max(error.end, error.start + 1)) || " "}</mark>
            {value.slice(Math.max(error.end, error.start + 1))}
          </p>
          <p>{error.message}</p>
        </div>
      ) : (
        <p id={`${id}-help`} className="iss-help">
          <code>key:value</code>; a comma means any of; <code>-</code> leaves out; <code>*</code> matches anything;
          dates as <code>&gt;30d</code> or <code>&gt;=2026-01-01</code>; other words search titles.
        </p>
      )}
      <details className="iss-keys">
        <summary>Every filter</summary>
        <dl>
          {Object.entries(KEYS).map(([k, spec]) => (
            <div key={k}>
              <dt><code>{k}</code></dt>
              <dd>{spec.values.length ? spec.values.join(", ") : spec.kind === "date" ? "an age (>30d, <7d) or a day (2026-01-01, a..b)" : spec.kind === "glob" ? "a name; * allowed" : k === "assignee" ? "a @handle, me, or none" : "a name"}</dd>
            </div>
          ))}
        </dl>
      </details>
    </div>
  );
}
