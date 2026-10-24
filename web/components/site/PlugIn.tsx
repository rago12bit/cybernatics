"use client";

import { useId, useRef, useState, type KeyboardEvent } from "react";
import type { Snippet } from "@/lib/snippets";

/**
 * One working snippet per way in (CLI, GitHub Action, MCP, REST), as tabs with a copy button. The
 * snippets are props, built on the server from lib/snippets.ts, so the first paint already holds the
 * first one and the rest are a click away. Tabs follow the WAI-ARIA pattern: arrow keys, Home and End.
 */
export function PlugIn({ items }: { items: Snippet[] }) {
  const uid = useId();
  const [active, setActive] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = items[active]!;

  const select = (i: number) => {
    setActive(i);
    setCopied(null);
    tabs.current[i]?.focus();
  };
  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const last = items.length - 1;
    const next = { ArrowRight: active === last ? 0 : active + 1, ArrowLeft: active === 0 ? last : active - 1, Home: 0, End: last }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    select(next);
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(current.code);
      setCopied(current.id);
    } catch {
      setCopied("failed");
    }
  };

  return (
    <div className="plug">
      <div className="plug-tabs" role="tablist" aria-label="Ways to run Bulwark" onKeyDown={onKey}>
        {items.map((s, i) => (
          <button
            key={s.id}
            ref={(el) => { tabs.current[i] = el; }}
            type="button"
            role="tab"
            id={`${uid}-tab-${s.id}`}
            aria-selected={i === active}
            aria-controls={`${uid}-panel`}
            tabIndex={i === active ? 0 : -1}
            onClick={() => select(i)}
          >
            {s.label}
          </button>
        ))}
      </div>
      <div className="plug-panel" role="tabpanel" id={`${uid}-panel`} aria-labelledby={`${uid}-tab-${current.id}`}>
        <div className="codewin">
          <header>
            <span className="dots" aria-hidden="true"><i /><i /><i /></span>
            <span className="name">{current.file}</span>
            <button type="button" className="plug-copy" onClick={copy} aria-describedby={`${uid}-said`}>
              {copied === current.id ? "Copied" : "Copy"}
            </button>
          </header>
          <pre tabIndex={0} aria-label={`${current.label} snippet`}><code>{current.code}</code></pre>
        </div>
        <p className="plug-when">{current.when}</p>
        <p className="sr-only" id={`${uid}-said`} role="status" aria-live="polite">
          {copied === current.id ? `${current.label} snippet copied.` : copied === "failed" ? "Could not copy: select the text instead." : ""}
        </p>
      </div>
    </div>
  );
}
