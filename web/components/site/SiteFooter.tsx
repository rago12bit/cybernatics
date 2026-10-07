import Link from "next/link";
import { APP_HREF, CONTACT_URL, DEMO_ONLY, DOCS_HREF, REPO_URL } from "@/lib/site";
import { Stripes } from "./graphics";

// The public site's footer: every site page, plus the project's own links when the build was given
// them (REPO_URL and CONTACT_URL are configured, never hard-coded).
export function SiteFooter() {
  return (
    <footer className="foot">
      <div className="foot-links">
        <div>
          <h3>Product</h3>
          <ul>
            <li><Link href="/how-it-works">How it works</Link></li>
            <li><Link href="/integrations">Integrations</Link></li>
            <li><Link href="/sample">Recorded scan</Link></li>
            <li><Link href={APP_HREF}>{DEMO_ONLY ? "Run it yourself" : "Open app"}</Link></li>
          </ul>
        </div>
        <div>
          <h3>Trust</h3>
          <ul>
            <li><Link href="/security">Security</Link></li>
            <li><Link href="/compare">Compare</Link></li>
            <li><Link href="/migrate">Migration guides</Link></li>
          </ul>
        </div>
        <div>
          <h3>Developers</h3>
          <ul>
            <li><a href={DOCS_HREF}>API reference</a></li>
            <li>CLI: bulwark scan</li>
            <li><Link href="/community#contribute">Add a scanner or parser</Link></li>
          </ul>
        </div>
        <div>
          <h3>Project</h3>
          <ul>
            <li><Link href="/community">Community</Link></li>
            <li>Apache-2.0</li>
            {REPO_URL && <li><a href={REPO_URL} rel="noopener noreferrer">Source code</a></li>}
            {CONTACT_URL && <li><a href={CONTACT_URL} rel="noopener noreferrer">Contact</a></li>}
          </ul>
        </div>
      </div>
      <Stripes seed={11} groups={16} rows={3} />
    </footer>
  );
}
