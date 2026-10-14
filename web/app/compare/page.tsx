import type { Metadata } from "next";
import Link from "next/link";
import { SitePage, SiteSection } from "@/components/site/SitePage";
import { counts } from "@/lib/catalogue";

export const metadata: Metadata = {
  title: "Compare · Bulwark",
  description: "Bulwark and DefectDojo side by side: what each does, where DefectDojo is ahead, and how to use them together.",
};

// What is said about DefectDojo here is checked against its own repository (README, dojo/tools,
// licence, releases) on the date below, or against its parser code where Bulwark ported a parser.
// Re-check before changing a number.
const CHECKED_ON = "2026-10-07";
const DD_TOOL_DIRS = 369; // directories under dojo/tools on master, counted CHECKED_ON
const DD_LATEST = "3.4.0"; // released 2026-10-05
const DD_TESTED = "3.3.300"; // the version the round trip ran against (M13)

export default function Compare() {
  const c = counts();
  return (
    <SitePage
      eyebrow="Compare"
      title="Bulwark and DefectDojo"
      lede={
        <>
          DefectDojo is the open-source standard for collecting security findings, and Bulwark reads and writes it. This
          page says where each is stronger, from facts either side can check. Facts about DefectDojo were checked on{" "}
          {CHECKED_ON}.
        </>
      }
      actions={<Link href="/migrate" className="btn primary sm">Migration guides, both ways →</Link>}
    >
      <SiteSection id="side-by-side" title="Side by side">
        <div className="cmp-wrap">
          <table className="cmp">
            <colgroup><col className="topic" /><col /><col /></colgroup>
            <thead>
              <tr>
                <th scope="col"><span className="sr-only">Topic</span></th>
                <th scope="col" className="us"><span className="cmp-name">Bulwark</span></th>
                <th scope="col"><span className="cmp-name">DefectDojo</span></th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th scope="row">What it is</th>
                <td className="us" data-label="Bulwark">Runs open-source scanners in sandboxes, imports other tools&apos; reports, and tracks the results as Issues.</td>
                <td data-label="DefectDojo">Describes itself as a DevSecOps, application security posture management and vulnerability management tool.<span className="src">its README</span></td>
              </tr>
              <tr>
                <th scope="row">Scanners it runs</th>
                <td className="us" data-label="Bulwark">{c.scanners}, each in a locked-down container; {c.defaultScanners} run by default.<span className="src">core/scan.py · core/sandbox/docker_runtime.py</span></td>
                <td data-label="DefectDojo">Not compared here: check its documentation for which tools it runs itself.</td>
              </tr>
              <tr>
                <th scope="row">Report formats</th>
                <td className="us" data-label="Bulwark">{c.parsers} built-in parsers, plus any JSON, CSV or XML report through a saved mapping.<span className="src">core/imports/parsers/registry.py</span></td>
                <td data-label="DefectDojo">{DD_TOOL_DIRS} tool directories under <code>dojo/tools</code>. Far broader.<span className="src">github.com/DefectDojo/django-DefectDojo, master</span></td>
              </tr>
              <tr>
                <th scope="row">One finding is</th>
                <td className="us" data-label="Bulwark">One problem in one place. A Nessus plugin on fifty hosts is fifty Issues, so fixing one host closes one.<span className="src">core/imports/parsers/nessus.py · docs/adr/0041-dast-and-network-identity.md</span></td>
                <td data-label="DefectDojo">Its Tenable parser folds a plugin seen on many hosts into one finding.<span className="src">dojo/tools/tenable/ (read when porting)</span></td>
              </tr>
              <tr>
                <th scope="row">Duplicates</th>
                <td className="us" data-label="Bulwark">Merged across scanners within a scan, showing which scanners agree; matching rules per source, changed through a dry run.<span className="src">core/correlation/engine.py · core/dedup/</span></td>
                <td data-label="DefectDojo">Lets each tool be deduplicated its own way. Bulwark took that idea from it and added the dry run.<span className="src">docs/adr/0042-dedup-strategies-per-source.md</span></td>
              </tr>
              <tr>
                <th scope="row">Licence</th>
                <td className="us" data-label="Bulwark">Apache-2.0.</td>
                <td data-label="DefectDojo">BSD-3-Clause. An OWASP Flagship project.</td>
              </tr>
              <tr>
                <th scope="row">Editions</th>
                <td className="us" data-label="Bulwark">One, self-hosted. No hosted service and no paid support.</td>
                <td data-label="DefectDojo">A community edition and a commercial Pro edition.<span className="src">its README</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </SiteSection>

      <SiteSection id="choose" title="Which to choose">
        <div className="facts">
          <div className="fact">
            <span className="label">Choose DefectDojo when</span>
            <ul className="notes">
              <li>you already run many tools and need their reports in one place; it reads far more formats;</li>
              <li>you want a mature project with years of production use, a large community, or a commercial edition with support.</li>
            </ul>
          </div>
          <div className="fact">
            <span className="label">Choose Bulwark when</span>
            <ul className="notes">
              <li>you want the scanning done for you, in sandboxes, with the results already merged;</li>
              <li>you want each host, URL or file to be its own Issue, ranked by exploitability and reachability;</li>
              <li>you want SLAs, four-eyes risk acceptance and tickets both ways in the same tool.</li>
            </ul>
          </div>
          <div className="fact">
            <span className="label">Or use both</span>
            <p>
              Bulwark can pull a DefectDojo product&apos;s findings and push its own Issues into a DefectDojo engagement.
              Both directions were run against a real DefectDojo {DD_TESTED}; the latest release is {DD_LATEST}, which has
              not been tested.
            </p>
            <span className="src">core/connectors/defectdojo.py · tests/integration/test_defectdojo_live.py</span>
          </div>
        </div>
      </SiteSection>
    </SitePage>
  );
}
