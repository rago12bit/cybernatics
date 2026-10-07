import type { Metadata } from "next";
import Link from "next/link";
import { Fact, SitePage, SiteSection } from "@/components/site/SitePage";
import { INTEGRATIONS } from "@/lib/catalogue";
import { CONTACT_URL, REPO_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Community · Bulwark",
  description: "Bulwark is Apache-2.0 open source. How to contribute, extend it, and who it is built on.",
};

export default function Community() {
  const ported = INTEGRATIONS.filter((i) => i.ported_from_defectdojo).length;
  return (
    <SitePage
      eyebrow="Community"
      title="Open source, and built on open source"
      lede="Bulwark is Apache-2.0. It is a small project with a single maintainer, so issues and pull requests are read by the person who will fix them."
      actions={
        <>
          {REPO_URL && <a href={REPO_URL} className="btn primary sm" rel="noopener noreferrer">Source code →</a>}
          {CONTACT_URL && <a href={CONTACT_URL} className="btn sm" rel="noopener noreferrer">Contact</a>}
        </>
      }
    >
      <SiteSection id="contribute" title="Contributing" intro="Bug reports, scanner and parser improvements and documentation fixes are welcome. For anything larger than a small fix, open an issue first so the approach can be agreed.">
        <div className="facts">
          <Fact label="A change needs a test that fails without it" src="CONTRIBUTING.md">
            Show it in the pull request, and say what you verified and what you did not. CI runs ruff, black, mypy and pytest
            (80% coverage is enforced) and the web typecheck, tests and build.
          </Fact>
          <Fact label="Add a scanner" src="docs/adding-a-scanner.md · core/adapters/">
            Run the real tool on a frozen fixture, keep its raw output as the golden file, and parse that. It runs in its
            container with the sandbox flags; never relax them to make a scan work.
          </Fact>
          <Fact label="Write a plugin" src="docs/plugins.md · examples/bulwark-plugin-demo/">
            A package with an entry point adds a scanner without changing Bulwark. The demo plugin is installed in CI exactly
            as a plugin author would install theirs.
          </Fact>
          <Fact label="Import a new report format" src="core/imports/parsers/universal.py">
            Most reports need no code: map their fields once in the app, preview, save. A saved mapping is a parser that runs in
            the same sandbox as the built-in ones.
          </Fact>
          <Fact label="Report a vulnerability" src="SECURITY.md">
            Privately, please. <Link href="/security#report">How to report one →</Link>
          </Fact>
        </div>
      </SiteSection>

      <SiteSection id="credits" title="Built on" intro="Detection is done by other people's mature tools. Bulwark's part is running them safely and making sense of what they say together.">
        <div className="site-body">
          <ul>
            <li>
              The scanners Bulwark runs, each under its own licence: <Link href="/integrations">every one, with its version →</Link>
            </li>
            <li>
              {ported} of the report parsers are ported from DefectDojo&apos;s (BSD-3-Clause) and credited in
              THIRD_PARTY_LICENSES.md, which is generated so a ported file cannot ship without its notice. Bulwark is not
              affiliated with or endorsed by DefectDojo.
            </li>
            <li>The OSV, CISA KEV, NVD and EPSS feeds behind advisories and risk scores.</li>
          </ul>
          <span className="src">THIRD_PARTY_LICENSES.md · scripts/gen-licenses.py</span>
        </div>
      </SiteSection>
    </SitePage>
  );
}
