import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Run it yourself · Bulwark",
  description: "Bulwark scans code on your own machine. This site shows a sample report only.",
};

export default function SelfHost() {
  return (
    <div className="page">
      <div className="state-page">
        <span className="eyebrow">Run it yourself</span>
        <h1>Scanning happens on your machine.</h1>
        <p className="lede">
          This site is a read-only sample: a real report from a small test project. It runs no scanners and accepts no code.
          Bulwark is built to run locally, next to the code it scans.
        </p>
        <h2>Why there is no hosted scanner</h2>
        <ul className="prose">
          <li>Scanning means running third-party tools over untrusted code. That belongs on a host you control, in the sandbox described in the threat model.</li>
          <li>Semgrep&apos;s community rules cannot be offered as a hosted service under their licence.</li>
          <li>There are no user accounts yet: access is one shared token, meant for a private machine.</li>
        </ul>
        <h2>Start locally</h2>
        <pre className="snippet"><code>{`./scripts/init-env.sh                     # writes .env with random secrets
docker compose --profile scanners build   # app image + scanner images
docker compose up -d                      # UI on http://localhost:3000

# or just the command line:
pip install -e ".[dev]"
bulwark scan ./my-project --format html -o report.html`}</code></pre>
        <p className="muted">Needs Docker. The first build downloads scanner databases (about 1.4 GB for Trivy).</p>
        <div className="hero-actions">
          <Link href="/" className="btn primary">Back to the sample report</Link>
          <Link href="/about" className="btn">About Bulwark</Link>
        </div>
      </div>
    </div>
  );
}
