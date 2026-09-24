import { agreementLabel, locationLabel, nativeSeverities } from "@/lib/format";
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

export function FindingDetail({ finding: f, scan, onClose }: { finding: Finding; scan: ScanView | null; onClose: () => void }) {
  const refs = f.remediation.references.map((r) => ({ raw: r, url: safeHttpsUrl(r) }));
  return (
    <aside className="detail card" aria-label="Finding details">
      <div className="detail-head">
        <SeverityBadge severity={f.scoring.normalized_severity} />
        <button className="link" onClick={onClose} aria-label="Close details">Close ✕</button>
      </div>
      {/* All scanner-derived strings below are rendered as React text nodes: never as HTML. */}
      <h3>{f.title}</h3>
      <p className="agree"><strong>{agreementLabel(f, scan)}</strong>{" "}
        <span className="muted">· confidence {Math.round(f.scoring.confidence * 100)}%</span></p>
      {f.evidence.agreement_count > 1 && <p className="muted small">Independent scanners agreeing raises confidence and merged into this single finding.</p>}

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
        {f.taxonomy.owasp_top_10_2021.map((c) => <Ref key={c} href={owaspUrl(c)} label={`OWASP ${c}`} />)}
      </div>
      {refs.length > 0 && (
        <ul className="refs">
          {refs.map((r) => (<li key={r.raw}>{r.url ? <a href={r.url} target="_blank" rel="noopener noreferrer">{r.url}</a> : <span>{r.raw}</span>}</li>))}
        </ul>
      )}
    </aside>
  );
}
