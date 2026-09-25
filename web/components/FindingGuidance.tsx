"use client";

import { Fragment, useEffect, useState } from "react";
import { ApiError } from "@/lib/api";
import { safeHttpsUrl } from "@/lib/safe";
import type { Guidance, GuidanceApi, Remediation } from "@/lib/types";

// Every string in a Remediation may derive from a scanned repository (through a model), so it is rendered
// as React text nodes and never as HTML. Links are built only from https URLs.

function Refs({ items }: { items: Remediation["references"] }) {
  const seen = new Set<string>();
  const uniq = items.filter((r) => (seen.has(r.url) ? false : (seen.add(r.url), true)));
  if (uniq.length === 0) return null;
  return (
    <ul className="refs">
      {uniq.map((r) => {
        const url = safeHttpsUrl(r.url);
        return <li key={r.url}>{url ? <a href={url} target="_blank" rel="noopener noreferrer">{r.title}</a> : <span>{r.title}</span>}</li>;
      })}
    </ul>
  );
}

/** A unified diff as text, one line per row, marked by +/- characters as well as colour. */
function Patch({ patch }: { patch: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1600);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <div className="patch">
      <div className="patch-head">
        <span className="label dimmed">Suggested patch (text only)</span>
        <button type="button" className="btn sm" onClick={() => navigator.clipboard?.writeText(patch).then(() => setCopied(true), () => undefined)}>{copied ? "Copied" : "Copy patch"}</button>
      </div>
      <pre className="snippet diff" tabIndex={0} aria-label="Suggested patch"><code>
        {patch.split("\n").map((line, i, all) => (
          <Fragment key={i}>
            <span className={line.startsWith("+") ? "d-add" : line.startsWith("-") ? "d-del" : line.startsWith("@@") ? "d-hunk" : undefined}>{line}</span>
            {i < all.length - 1 ? "\n" : null}
          </Fragment>
        ))}
      </code></pre>
      <p className="small muted">Bulwark never applies patches. Review it, and test it, before using it.</p>
    </div>
  );
}

function StaticBlock({ r }: { r: Remediation }) {
  return (
    <div className="guide static" role="group" aria-label="Reference guidance">
      <span className="tag ref">{r.label}</span>
      <p className="prose">{r.explanation}</p>
      {r.fix_summary && <p className="prose"><b>How to fix:</b> {r.fix_summary}</p>}
      <Refs items={r.references} />
    </div>
  );
}

export function AiBlock({ r }: { r: Remediation }) {
  return (
    <div className="guide ai" role="group" aria-label="AI suggestion">
      <div className="ai-head">
        <span className="tag ai-tag">AI suggestion</span>
        <strong>Review before applying.</strong>
        <span className="small muted">
          {r.model ? `Written by ${r.model}` : "Written by a model"} · confidence in this fix: {r.confidence}
          {r.from_cache ? " · reused from an earlier identical finding" : ""}
        </span>
      </div>
      {r.warnings.length > 0 && <div role="note" aria-label="Notes about this suggestion"><ul className="ai-warn">{r.warnings.map((w) => <li key={w}>{w}</li>)}</ul></div>}
      <p className="prose">{r.explanation}</p>
      <p className="prose"><b>Impact:</b> {r.impact}</p>
      <p className="prose"><b>How to fix:</b> {r.fix_summary}</p>
      {r.suggested_patch && <Patch patch={r.suggested_patch} />}
      <Refs items={r.references} />
    </div>
  );
}

export function FindingGuidance({ scanId, findingId, api }: { scanId: string; findingId: string; api: GuidanceApi }) {
  const [g, setG] = useState<Guidance | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ai, setAi] = useState<Remediation | null>(null);
  const [busy, setBusy] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setG(null); setError(null); setAi(null); setAiError(null); setBusy(false);
    api.get(scanId, findingId).then(
      (v) => { if (!cancelled) { setG(v); setAi(v.ai); } },
      (e) => { if (!cancelled) setError(e instanceof Error ? e.message : "Could not load guidance"); },
    );
    return () => { cancelled = true; };
  }, [scanId, findingId, api]);

  async function generate() {
    setBusy(true);
    setAiError(null);
    try {
      const r = await api.request(scanId, findingId);
      setAi(r);
    } catch (e) {
      setAiError(e instanceof ApiError && e.status === 429 ? `${e.message}. Reference guidance above still applies.` : e instanceof Error ? e.message : "Could not generate a suggestion");
    } finally {
      setBusy(false);
    }
  }

  if (error) return <section className="guidance" aria-label="Fix guidance"><h4>Fix guidance</h4><p className="error small" role="alert">{error}</p></section>;
  if (!g) return <section className="guidance" aria-busy="true" aria-label="Fix guidance"><h4>Fix guidance</h4><span className="sk sk-l" /><span className="sk sk-m" /></section>;
  // A degraded AI attempt (rejected reply, failed call) is shown as what it is: reference text, with the reason.
  const aiOk = ai && ai.source === "ai";
  return (
    <section className="guidance" aria-label="Fix guidance">
      <h4>Fix guidance</h4>
      <StaticBlock r={g.static} />
      {aiOk ? (
        <AiBlock r={ai} />
      ) : g.ai_enabled ? (
        <div className="guide ai-ask">
          <button type="button" className="btn sm" onClick={generate} disabled={busy} aria-describedby="ai-consent">{busy ? "Asking the model…" : "Generate AI suggestion"}</button>
          <p id="ai-consent" className="small muted">
            Sends this finding&apos;s title, description and code snippet (secrets removed) to the AI provider ({g.model ?? "model"}). It runs only when you click. The result is cached and always labelled.
          </p>
          {ai && ai.source === "static" && ai.degraded_reason && <p className="small warn" role="status">The model&apos;s answer was not usable ({ai.degraded_reason}); the reference guidance above is shown instead.</p>}
          {aiError && <p className="error small" role="alert">{aiError}</p>}
        </div>
      ) : (
        <p className="small muted ai-off">AI suggestions are off on this server. The guidance above is reference text from CWE and the OWASP cheat sheets.</p>
      )}
    </section>
  );
}
