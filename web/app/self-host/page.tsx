import type { Metadata } from "next";
import Link from "next/link";
import { ScrollReveal } from "@/components/site/ScrollReveal";
import { CONTACT_URL, REPO_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Run it yourself · Bulwark",
  description: "Bulwark scans code on your own machine. This site shows a sample report only.",
};

export default function SelfHost() {
  return (
    <div className="page">
      <ScrollReveal selector=".state-page > *" />
      <div className="state-page">
        <span className="eyebrow">Run it yourself</span>
        <h1>Scanning happens on your machine.</h1>
        <p className="lede">
          This site is read-only: it shows a recorded scan of OWASP Juice Shop. It runs no scanners and accepts no code.
          Bulwark is built to run locally, next to the code it scans.
        </p>
        <h2>Why there is no hosted scanner</h2>
        <ul className="prose">
          <li>Scanning means running third-party tools over untrusted code. That belongs on a host you control, in the sandbox described in the threat model.</li>
          <li>Semgrep&apos;s community rules cannot be offered as a hosted service under their licence.</li>
          <li>Accounts, single sign-on and project roles belong to a deployment you run. This site has none.</li>
        </ul>
        <h2>Start locally</h2>
        <pre className="snippet" tabIndex={0} aria-label="Commands to run Bulwark"><code>{`./scripts/init-env.sh                     # writes .env with random secrets
docker compose --profile scanners build   # app image + scanner images
docker compose up -d                      # UI on http://localhost:3000

# or just the command line:
pip install -e ".[dev]"
bulwark scan ./my-project --format html -o report.html`}</code></pre>
        <p className="muted">Needs Docker. The first build downloads scanner databases (about 1.4 GB for Trivy).</p>
        <div className="hero-actions">
          <Link href="/sample" className="btn primary">Back to the recorded scan</Link>
          <Link href="/" className="btn">About Bulwark</Link>
          {REPO_URL && <a href={REPO_URL} className="btn" rel="noopener noreferrer">Source code</a>}
          {CONTACT_URL && <a href={CONTACT_URL} className="btn" rel="noopener noreferrer">Contact</a>}
        </div>
      </div>
    </div>
  );
}
