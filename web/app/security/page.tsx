import type { Metadata } from "next";
import { Fact, SitePage, SiteSection } from "@/components/site/SitePage";
import { refusedTotal, provenance } from "@/lib/recording";
import { CONTACT_URL, REPO_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Security · Bulwark",
  description: "How Bulwark contains the untrusted code and reports it handles, who can see what, and what is not proven yet.",
};

// Every claim names the file that enforces it (tests/site-pages.test.tsx checks the paths exist).
export default function Security() {
  return (
    <SitePage
      eyebrow="Security"
      title="Built to handle code and reports it does not trust"
      lede="A security tool reads hostile input for a living: repositories, archives, scanner output, uploaded reports, web pages. Here is what contains each, where in the code it lives, and what has not been proven yet."
    >
      <SiteSection id="containment" title="Containing untrusted input">
        <div className="facts">
          <Fact label="Scanners" status="ok" src="core/sandbox/docker_runtime.py">
            One container per scanner per run: --network=none, --read-only, --cap-drop=ALL, user 10001, no-new-privileges,
            memory, CPU and 256-process limits, and a small noexec /tmp. The code is mounted read-only; dependencies are never
            installed.
          </Fact>
          <Fact label="Uploaded reports" status="ok" src="core/imports/parsers/sandbox.py · core/imports/parsers/safe.py">
            Parsed in their own container with no network and a 1 GB memory limit, under size and time limits. XML may not
            declare entities or fetch a DTD; regular expressions run on RE2, so a hostile file cannot make matching slow.
          </Fact>
          <Fact label="Archives and Git URLs" status="ok" src="core/gitfetch.py · core/netsafety.py · core/ingest.py">
            HTTPS only, to an allowlist of hosts; every resolved address must be public and is pinned for the clone; no
            redirects, submodules, hooks or credential helpers. Archives are checked for path traversal, symlinks and bombs.
          </Fact>
          <Fact label="Web campaigns" status="ok" src="core/dast/ownership.py · core/dast/proxy.py · core/dast/campaign.py">
            A site is scanned only after its owner proves control (DNS TXT or a well-known file), re-checked at the start of
            every campaign. Active campaigns are rate-limited, and the tools reach the target through a proxy that refuses
            every other host: recording {provenance.app}, it refused {refusedTotal()} connections.
          </Fact>
          <Fact label="Secrets in results" status="ok" src="core/redact.py">
            Gitleaks runs with redaction, other scanners&apos; output is redacted too, and a scan that found secrets withholds
            its raw output.
          </Fact>
          <Fact label="Scanner output in the browser" status="ok" src="web/proxy.ts">
            Everything a scanner says is rendered as text, never as HTML, under a per-request-nonce Content-Security-Policy
            with no inline scripts or styles.
          </Fact>
        </div>
      </SiteSection>

      <SiteSection id="access" title="Who can see and change what">
        <div className="facts">
          <Fact label="Sign-in" status="ok" src="core/identity/ · tests/unit/test_saml.py">
            OIDC with PKCE and strict ID-token checks, or SAML 2.0 accepting signed assertions only. Tested against signature
            wrapping, comment injection in the NameID, unsigned, replayed and unsolicited responses.
          </Fact>
          <Fact label="Sessions" status="ok" src="core/identity/sessions.py">
            Short sessions in an HttpOnly cookie, stored only as a hash. Every change needs a CSRF token as well.
          </Fact>
          <Fact label="Tenants and projects" status="ok" src="core/tenancy.py · migrations/">
            Organizations are separated by Postgres row-level security. A person limited to some projects runs as a role whose
            policies hide every other project&apos;s rows.
          </Fact>
          <Fact label="Deprovisioning" status="ok" src="core/identity/">
            SCIM 2.0 for identity providers. Turning someone off ends their sessions and API tokens in the same request.
          </Fact>
          <Fact label="Decisions" status="ok" src="core/acceptance/service.py">
            Accepting a risk needs a second person, enforced by the server, and the acceptance expires.
          </Fact>
          <Fact label="Audit" status="ok" src="core/audit.py · core/audit_rekor.py">
            A hash-chained audit log, so an edit or a deletion in the middle shows.
          </Fact>
          <Fact label="Outgoing messages" status="ok" src="core/integrations/webhooks.py · core/integrations/ssrf.py">
            Webhooks are signed with HMAC-SHA256 over a timestamp and the body, and every destination is checked so it
            cannot point inside your network.
          </Fact>
        </div>
      </SiteSection>

      <SiteSection id="unproven" title="Not proven yet" intro="Written down so nobody relies on it by accident.">
        <div className="facts">
          <Fact label="Signed releases" status="open" src=".github/workflows/release.yml">
            The release workflow signs images with cosign (keyless) and attaches SLSA provenance. No run of it has been observed
            yet, so treat release signatures as unverified.
          </Fact>
          <Fact label="Stronger sandboxes" status="open" src="core/sandbox/gvisor_runtime.py · docs/sandbox-runtimes.md">
            A gVisor runtime is written and its command line tested, but it has never run (it needs Linux). Firecracker is not
            built.
          </Fact>
          <Fact label="Kernel-level egress denial" status="open" src="core/dast/egress.py">
            Web campaign tools are held to the target by their proxy settings. The nftables rule that would stop a tool which
            ignores its proxy is Linux-only and has not been exercised.
          </Fact>
          <Fact label="Encryption at rest without OpenBao" status="open" src="core/secrets/">
            Connector credentials and evidence files are encrypted through OpenBao. Without it they are stored unencrypted,
            and the API and screens say so.
          </Fact>
        </div>
      </SiteSection>

      <SiteSection id="report" title="Reporting a vulnerability">
        <div className="site-body">
          <p>
            Please do not open a public issue. Use the repository&apos;s private vulnerability reporting
            {CONTACT_URL ? (
              <>, or <a href={CONTACT_URL} rel="noopener noreferrer">contact the maintainer</a></>
            ) : null}
            . You will get an acknowledgement within five working days. The full policy is SECURITY.md
            {REPO_URL ? <> in <a href={REPO_URL} rel="noopener noreferrer">the repository</a></> : " in the repository"}, and
            the threat model, with the status of every threat, is docs/THREAT-MODEL.md.
          </p>
        </div>
      </SiteSection>
    </SitePage>
  );
}
