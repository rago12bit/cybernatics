import type { Metadata } from "next";
import Link from "next/link";
import { SitePage } from "@/components/site/SitePage";
import { counts } from "@/lib/catalogue";

export const metadata: Metadata = {
  title: "How it works · Bulwark",
  description: "How a finding travels through Bulwark: in, sandboxed, normalised, matched, ranked, tracked and reported.",
};

export default function HowItWorks() {
  const c = counts();
  return (
    <SitePage
      eyebrow="How it works"
      title="From a scan to a fixed Issue"
      lede="Bulwark does not detect vulnerabilities itself. It runs mature open-source scanners, reads the reports of the ones you already run, and turns all of it into one list of Issues that each have an owner, a deadline and a history."
      actions={<Link href="/#recording" className="btn sm">See it on a real app →</Link>}
    >
      <ol className="steps" aria-label="How a finding travels">
        <li>
          <div className="step-body">
            <h2 className="h3">Findings come in four ways</h2>
            <ul>
              <li>
                <b>A scan</b> of a repository, folder or archive by {c.defaultScanners} scanners by default ({c.scanners} in all),
                from the command line, the API, the web app, the VS Code extension or the GitHub Action. They are all thin
                clients over the same engine.
              </li>
              <li>
                <b>A web campaign</b> against a site you have proved you own (a DNS TXT record or a file at a well-known
                path), passive by default.
              </li>
              <li>
                <b>An import</b> of a report from {c.parsers} formats, or any other JSON, CSV or XML report through a mapping
                you save once.
              </li>
              <li><b>A connector</b> that pulls on a schedule from GitHub, GitLab or DefectDojo.</li>
            </ul>
            <span className="src">core/scan.py · core/dast/ownership.py · core/imports/parsers/ · core/connectors/</span>
          </div>
        </li>
        <li>
          <div className="step-body">
            <h2 className="h3">Untrusted input stays in a box</h2>
            <p>
              Each scanner runs in its own container with no network, a read-only filesystem, every capability dropped, a
              non-root user and memory, CPU and process limits. The code is mounted read-only and its dependencies are never
              installed. Uploaded reports are parsed in a separate container the same way. A web campaign&apos;s tools reach
              the target through a proxy that refuses every other host.
            </p>
            <span className="src">core/sandbox/docker_runtime.py · core/imports/parsers/sandbox.py · core/dast/proxy.py</span>
          </div>
        </li>
        <li>
          <div className="step-body">
            <h2 className="h3">Everything becomes one shape</h2>
            <p>
              Every tool&apos;s output becomes the same finding: where it is, what it is (CWE, CVE, package), how bad the tool
              said it was, and how bad that is on one shared scale. The scale is a published table, a judgement call written
              down rather than hidden.
            </p>
            <span className="src">core/models/finding.py · docs/severity-matrix.md</span>
          </div>
        </li>
        <li>
          <div className="step-body">
            <h2 className="h3">Duplicates are merged, and you can see why</h2>
            <p>
              Two scanners reporting the same problem in the same place become one finding that shows both. Across scans, a
              fingerprint keeps a finding the same Issue as code moves. Each source can match differently (its own id, a
              package and advisory, chosen fields), and a change is previewed as a dry run before it touches anything. Web
              findings are never merged: each URL is its own Issue.
            </p>
            <span className="src">core/correlation/engine.py · core/dedup/ · docs/adr/0041-dast-and-network-identity.md · docs/adr/0042-dedup-strategies-per-source.md</span>
          </div>
        </li>
        <li>
          <div className="step-body">
            <h2 className="h3">The list is ranked by risk, not count</h2>
            <p>
              Severity is combined with the chance of exploitation (EPSS), known exploitation (CISA KEV) and whether the
              vulnerable code is reachable. Each project can weigh these differently, and context such as &ldquo;not exposed
              to the internet&rdquo; can only lower a priority, never raise it.
            </p>
            <span className="src">core/scoring/ · core/reachability/ · core/priority/engine.py</span>
          </div>
        </li>
        <li>
          <div className="step-body">
            <h2 className="h3">Issues are tracked until they are gone</h2>
            <p>
              An Issue is new, open, fixed or reintroduced. Its SLA clock starts at first detection. Accepting a risk needs a
              second person and expires. Tickets in Jira or GitHub follow it both ways, rules written in Rego act on events,
              and people are told by the channels they choose.
            </p>
            <span className="src">core/issues.py · core/sla/ · core/acceptance/ · core/tickets/ · core/rules/ · core/notify/</span>
          </div>
        </li>
        <li>
          <div className="step-body">
            <h2 className="h3">Results leave as evidence</h2>
            <p>
              Dashboards answer program questions; reports are built from blocks and exported as PDFs signed with cosign;
              findings leave as SARIF or straight into DefectDojo; and VEX statements and evidence packs say what was checked
              and how.
            </p>
            <span className="src">core/reports/ · core/export/ · core/vex/ · core/evidence/</span>
          </div>
        </li>
      </ol>
    </SitePage>
  );
}
