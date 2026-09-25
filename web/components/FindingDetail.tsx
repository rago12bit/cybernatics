import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { agreementLabel, locationLabel, nativeSeverities } from "@/lib/format";
import { owaspLabel } from "@/lib/owasp";
import { cveUrl, cweUrl, owaspUrl, safeHttpsUrl } from "@/lib/safe";
import type { Finding, ScanView } from "@/lib/types";
import { SeverityBadge } from "./Badges";

function Ref({ href, label }: { href: string | null; label: string }) {
  // Untrusted ids without a valid URL render as plain text, never as a link.
  return href ? (
    <a className="chip" href={href} target="_blank" rel="noopener noreferrer">{label}</a>
  ) : (
    <span className="chip">{label}</span>
  );
}

function CopyButton({ label, text }: { label: string; text: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1600);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button
      type="button"
      className="btn sm"
      onClick={() => navigator.clipboard?.writeText(text).then(() => setDone(true), () => undefined)}
    >
      {done ? "Copied" : label}
    </button>
  );
}

export function FindingDetail({
  finding: f,
  scan,
  open = true,
  onClose,
  position,
  onPrev,
  onNext,
}: {
  finding: Finding;
  scan: ScanView | null;
  open?: boolean;
  onClose: () => void;
  position?: { index: number; total: number };
  onPrev?: () => void;
  onNext?: () => void;
}) {
  const refs = f.remediation.references.map((r) => ({ raw: r, url: safeHttpsUrl(r) }));
  const closeRef = useRef<HTMLButtonElement>(null);
  const sheetRef = useRef<HTMLElement>(null);
  // Mount closed, force the browser to compute that style, THEN flip to open in the same frame, so
  // the enter transition always runs. This needs no rAF/timer, which browsers pause when the tab
  // is not being painted.
  const [entered, setEntered] = useState(false);
  useLayoutEffect(() => {
    void sheetRef.current?.getBoundingClientRect();
    setEntered(true);
  }, []);
  const shown = open && entered;
  // Keyboard users land in the sheet when it opens (focus returns to the row in FindingsTable).
  useEffect(() => {
    if (open) closeRef.current?.focus({ preventScroll: true });
  }, [open]);
  return (
    <aside ref={sheetRef} className="sheet" data-state={shown ? "open" : "closed"} aria-label="Finding details" aria-hidden={!open}>
      <div className="sheet-head">
        <SeverityBadge severity={f.scoring.normalized_severity} />
        <div className="sheet-nav">
          {position && <span className="label dimmed" aria-live="polite">{position.index} of {position.total}</span>}
          <button type="button" className="btn sm" onClick={onPrev} disabled={!onPrev} aria-label="Previous finding (k)" tabIndex={open ? 0 : -1}>↑</button>
          <button type="button" className="btn sm" onClick={onNext} disabled={!onNext} aria-label="Next finding (j)" tabIndex={open ? 0 : -1}>↓</button>
          <button ref={closeRef} type="button" className="btn sm" onClick={onClose} aria-label="Close details (Escape)" tabIndex={open ? 0 : -1}>Close</button>
        </div>
      </div>
      {/* All scanner-derived strings below are rendered as React text nodes: never as HTML. */}
      <h3>{f.title}</h3>
      <p className="agree">{agreementLabel(f, scan)} · confidence {Math.round(f.scoring.confidence * 100)}%</p>
      {f.evidence.agreement_count > 1 && <p className="muted small">Independent scanners agreed, which raises confidence. Their reports were merged into this one finding.</p>}

      <dl>
        <dt>Location</dt>
        <dd><code>{locationLabel(f)}</code></dd>
        {nativeSeverities(f) && (<><dt>Severity per scanner</dt><dd>{nativeSeverities(f)}</dd></>)}
        {f.package && (<><dt>Package</dt><dd><code>{f.package.name}@{f.package.version}</code> ({f.package.ecosystem})</dd></>)}
        {f.scoring.cvss_v3_1 !== null && (<><dt>CVSS v3.1</dt><dd>{f.scoring.cvss_v3_1}</dd></>)}
        <dt>Rules</dt>
        <dd>{Object.entries(f.evidence.rule_ids).map(([tool, rules]) => (
          <div key={tool}><span className="muted">{tool}:</span> <code>{rules.join(", ")}</code></div>
        ))}</dd>
      </dl>

      <div className="copyrow">
        <CopyButton label="Copy location" text={locationLabel(f)} />
        <CopyButton label="Copy as JSON" text={JSON.stringify(f, null, 2)} />
      </div>

      {f.location.snippet && (
        <>
          <h4>Code</h4>
          <pre className="snippet" tabIndex={0}><code>{f.location.snippet}</code></pre>
        </>
      )}

      {f.description && (<><h4>What it means</h4><p className="prose">{f.description}</p></>)}
      {f.remediation.summary && (<><h4>How to fix</h4><p className="prose">{f.remediation.summary}</p></>)}

      <div className="chips">
        {f.taxonomy.cwe.map((c) => <Ref key={c} href={cweUrl(c)} label={c} />)}
        {f.taxonomy.cve.map((c) => <Ref key={c} href={cveUrl(c)} label={c} />)}
        {f.taxonomy.owasp_top_10_2021.map((c) => <Ref key={c} href={owaspUrl(c)} label={owaspLabel(c)} />)}
      </div>
      {refs.length > 0 && (
        <ul className="refs">
          {refs.map((r) => (<li key={r.raw}>{r.url ? <a href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a> : <span>{r.raw}</span>}</li>))}
        </ul>
      )}
    </aside>
  );
}
