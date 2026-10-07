import type { Metadata } from "next";
import Link from "next/link";
import { SitePage, SiteSection } from "@/components/site/SitePage";
import { counts } from "@/lib/catalogue";

export const metadata: Metadata = {
  title: "Migration guides · Bulwark",
  description: "Moving findings from DefectDojo into Bulwark, and from Bulwark into DefectDojo: the steps, what carries over and what does not.",
};

// Both directions are the DefectDojo connectors (core/connectors/defectdojo.py), run against a real
// DefectDojo 3.3.300 for milestone M13 (docs/v2-week59-60-verification.md). What "does not carry
// over" is read from the connector's code, not guessed.
export default function Migrate() {
  const c = counts();
  return (
    <SitePage
      eyebrow="Migration guides"
      title="Moving between DefectDojo and Bulwark"
      lede="Both directions use a connector you set up once, so you can run the two side by side while you decide, and leave either way. Each was tested against a real DefectDojo 3.3.300."
      actions={
        <>
          <a href="#from-defectdojo" className="btn sm">DefectDojo → Bulwark</a>
          <a href="#to-defectdojo" className="btn sm">Bulwark → DefectDojo</a>
          <Link href="/compare" className="btn sm">Compare first</Link>
        </>
      }
    >
      <SiteSection id="from-defectdojo" title="From DefectDojo to Bulwark">
        <div className="site-body">
          <ol>
            <li>In DefectDojo, make an API v2 key for a user who can <b>read</b> the product, and nothing more.</li>
            <li>In Bulwark, create the project the findings belong to.</li>
            <li>
              Open <b>Connectors</b>, add <b>DefectDojo (import from)</b>, and give it DefectDojo&apos;s address, the
              product&apos;s numeric id and the key. Bulwark fetches the product first, so a wrong id fails at once with
              &ldquo;not found&rdquo;.
            </li>
            <li>
              Run it. It pulls the product&apos;s active, non-duplicate findings, following DefectDojo&apos;s own pages, then
              keeps pulling on a schedule (every six hours unless you change it).
            </li>
          </ol>
          <h3>What carries over</h3>
          <ul>
            <li>Each finding&apos;s title, description, severity and CVSS v3 score.</li>
            <li>Where it is: file and line for code, package and version for dependencies.</li>
            <li>CWEs and CVEs (and other vulnerability ids), references, and the mitigation as the fix.</li>
            <li>
              Identity: DefectDojo&apos;s finding id becomes the rule id, so a finding stays the same Issue on every pull,
              and one closed or marked a false positive in DefectDojo is closed in Bulwark on the next pull.
            </li>
          </ul>
          <h3>What does not</h3>
          <ul>
            <li>Inactive, false-positive, risk-accepted and duplicate findings: only active, non-duplicate ones are pulled.</li>
            <li>Notes, history, risk acceptances and JIRA links. Set triage again in Bulwark.</li>
            <li>
              A web finding&apos;s URLs. DefectDojo keeps them as separate Endpoints, which are not fetched yet, so such a
              finding arrives with no route.
            </li>
          </ul>
          <div className="callout">
            <span className="label">Or bring the original reports</span>
            <p>
              If you still have the scanner reports you uploaded to DefectDojo, import them directly: {c.parsers} formats are
              built in, ten of them ported from DefectDojo&apos;s own parsers, and anything else can be mapped once. You keep
              the scanner&apos;s own identity for each finding instead of DefectDojo&apos;s.{" "}
              <Link href="/integrations">See the formats →</Link>
            </p>
          </div>
          <div className="callout warn-box">
            <span className="label">Safety checks you will notice</span>
            <p>
              A pull that suddenly returns nothing after returning something is held back rather than closing every Issue
              (it looks the same as a key that lost access). A pull that fails part-way is never applied. A finding from
              another product refuses the whole pull: DefectDojo 3.3.300 ignored a product filter it did not know and
              returned every product&apos;s findings.
            </p>
          </div>
          <span className="src">core/connectors/defectdojo.py · core/connectors/service.py</span>
        </div>
      </SiteSection>

      <SiteSection id="to-defectdojo" title="From Bulwark to DefectDojo">
        <div className="site-body">
          <ol>
            <li>
              In DefectDojo, make an API v2 key for a user who can import scans into the engagement the findings should go
              to.
            </li>
            <li>
              In Bulwark, open <b>Connectors</b> on the project and add <b>DefectDojo (export to)</b> with DefectDojo&apos;s
              address and the key, and either an existing engagement&apos;s id, or a product and engagement name for Bulwark
              to create (with a product type, &ldquo;Bulwark&rdquo; unless you name another).
            </li>
            <li>
              Run it. The project&apos;s open Issues go to DefectDojo as a SARIF report: the first run creates a &ldquo;Bulwark
              Scan (SARIF)&rdquo; Test, and every run after reimports into that Test, so DefectDojo closes what Bulwark no
              longer has open.
            </li>
          </ol>
          <h3>What carries over</h3>
          <ul>
            <li>Every open Issue as a SARIF result: rule, message, severity, file and line.</li>
            <li>Fixes. An Issue fixed in Bulwark is closed in DefectDojo on the next export.</li>
          </ul>
          <h3>What does not</h3>
          <ul>
            <li>Issues that came from DefectDojo in the first place, or the two would echo each other forever.</li>
            <li>
              Anything SARIF has no place for: triage decisions, SLA dates, risk acceptances, tickets and comments.
            </li>
          </ul>
          <div className="callout">
            <span className="label">Or hand over a file</span>
            <p>
              <code>bulwark scan ./repo --format sarif -o results.sarif</code> writes the same kind of report, which
              DefectDojo&apos;s SARIF importer reads.
            </p>
          </div>
          <span className="src">core/connectors/defectdojo.py · core/export/sarif.py</span>
        </div>
      </SiteSection>

      <SiteSection id="tested" title="What was tested, and what was not">
        <div className="site-body">
          <ul>
            <li>
              Both directions ran against a real DefectDojo 3.3.300 from its own docker-compose: 13 findings in (code,
              dependency and web), 3 Issues out, one closed on each side and seen closed on the other.
            </li>
            <li>That run found two connector bugs, both fixed before release; it is repeatable as a test.</li>
            <li>Only one DefectDojo version was tried. Newer and older ones may name fields differently.</li>
          </ul>
          <span className="src">tests/integration/test_defectdojo_live.py · docs/v2-week59-60-verification.md</span>
        </div>
      </SiteSection>
    </SitePage>
  );
}
