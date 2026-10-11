import Link from "next/link";
import { formatDuration } from "@/lib/format";
import {
  codeFindings,
  codeScan,
  fingerprintCount,
  provenance,
  refusedEgress,
  refusedTotal,
  runtimeFindings,
  runtimeScan,
  severityRows,
  shortDigest,
  toolRows,
  widthClass,
} from "@/lib/recording";
import type { ScanView, Severity } from "@/lib/types";
import "./site-pages.css";

function SevBars({ scan }: { scan: ScanView }) {
  const rows = severityRows(scan);
  const max = Math.max(...rows.map((r) => r.count), 1);
  return (
    <div className="sevbars" aria-label="Findings by severity">
      {rows.map((r) => (
        <div key={r.severity} className={`sevrow sev-${r.severity.toLowerCase()}`}>
          <span>{r.severity}</span>
          <span className="track"><i className={widthClass(r.count, max)} /></span>
          <span className="n">{scan.severity_counts[r.severity as Severity]}</span>
        </div>
      ))}
    </div>
  );
}

function Tools({ scan }: { scan: ScanView }) {
  const rows = toolRows(scan);
  const max = Math.max(...rows.map((r) => r.findings), 1);
  return (
    <ul className="rec-tools" aria-label="What each scanner reported">
      {rows.map((t) => (
        <li key={t.name}>
          <span className={`st-${t.status}`}>{t.name}</span>
          {t.status === "skipped" ? (
            <span className="muted">skipped</span>
          ) : (
            <span className="bar-track"><span className={`bar-fill ${widthClass(t.findings, max)}`} /><span className="bar-rest" /></span>
          )}
          <span>{t.status === "skipped" ? "" : `${t.findings} · ${formatDuration(t.seconds)}`}</span>
          {t.note && <p className="why">{t.status === "skipped" ? "Skipped: " : "Warning: "}{t.note}</p>}
        </li>
      ))}
    </ul>
  );
}

// The home page's recorded scan (Week 77, plan §57): one release of OWASP Juice Shop, scanned as
// source and as a running container. Numbers come from lib/juiceshop-demo-data.json, made by
// scripts/record-juiceshop.py; nothing here is typed in.
export function Recording() {
  const merged = codeScan.raw_findings - codeScan.unique_findings;
  const hosts = refusedEgress.map((e) => e.host);
  return (
    <section className="section" id="recording" aria-labelledby="recording-h">
      <div className="rec-head">
        <div className="stack">
          <span className="eyebrow">Recorded scan</span>
          <h2 id="recording-h">{provenance.app} {provenance.version}, scanned twice</h2>
          <p className="lede">
            The same release, scanned as source by the default scanners and as a running container by a passive web
            campaign. Every number here is what Bulwark reported on {provenance.recorded_on}.
          </p>
        </div>
        <Link href="/sample" className="btn primary">Explore the findings →</Link>
      </div>
      <div className="rec-grid">
        <div className="rec-half">
          <span className="eyebrow plain">The code</span>
          <div className="rec-nums">
            <div><span className="numeral">{codeScan.raw_findings}</span><span className="label dimmed">Reported</span></div>
            <div><span className="numeral">{codeScan.unique_findings}</span><span className="label dimmed">After merging</span></div>
            <div><span className="numeral">{merged}</span><span className="label dimmed">Reported more than once</span></div>
          </div>
          <SevBars scan={codeScan} />
          <Tools scan={codeScan} />
        </div>
        <div className="rec-half">
          <span className="eyebrow plain">The running app</span>
          <div className="rec-nums">
            <div><span className="numeral">{runtimeScan.raw_findings}</span><span className="label dimmed">Alerts</span></div>
            <div><span className="numeral">{refusedTotal()}</span><span className="label dimmed">Connections refused</span></div>
          </div>
          <SevBars scan={runtimeScan} />
          <Tools scan={runtimeScan} />
          <p className="small muted">
            The campaign&apos;s proxy let ZAP reach the target and nothing else. It refused {refusedTotal()} connections, to{" "}
            {hosts.join(", ")}.
          </p>
        </div>
      </div>
      <div className="rec-prov" aria-label="Where this recording came from">
        <span>App <b>{provenance.app} {provenance.version}</b></span>
        <span>Commit <b>{provenance.commit.slice(0, 12)}</b></span>
        <span>Image <b>{shortDigest(provenance.image)}</b></span>
        <span>Recorded <b>{provenance.recorded_on}</b></span>
        <span>Bulwark <b>{provenance.bulwark_version}</b></span>
        <span>Made by <b>{provenance.made_by}</b></span>
      </div>
      <details className="rec-caveats">
        <summary>What this recording does not show</summary>
        <ul>
          <li>
            Dependencies. This release commits no lockfile, so OSV-Scanner had nothing to read and Trivy reported only the
            Dockerfile.
          </li>
          <li>
            The active web tier. Nuclei is not in this recording. Run directly, it finishes against this target in about
            two minutes; through the campaign&apos;s egress proxy it stalls before finishing, so an active campaign keeps
            what Nuclei found by its time limit. The stall is being fixed.
          </li>
          <li>
            Every URL. ZAP lists at most five URLs for each kind of alert, and which five changes between runs, so the
            running-app count is a sample.
          </li>
          <li>
            &ldquo;Confirmed at runtime&rdquo; links between the two halves. Matching a web finding to code needs the
            app&apos;s routes, and that is read today from Python route decorators only; Juice Shop is Express.
          </li>
          <li>
            One Issue per finding. Each finding is one place, but identical code on several lines of one file is one Issue
            (it stays open until every line is fixed), so the {codeScan.unique_findings} code findings are{" "}
            {fingerprintCount(codeFindings)} Issues and the {runtimeScan.unique_findings} running-app findings are{" "}
            {fingerprintCount(runtimeFindings)}.
          </li>
          <li>Raw scanner output. Gitleaks found secrets (Juice Shop ships them on purpose), so raw output is withheld.</li>
        </ul>
      </details>
    </section>
  );
}
