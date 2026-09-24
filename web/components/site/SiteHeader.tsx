"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BrandMark } from "./graphics";

export function SiteHeader() {
  const path = usePathname();
  const inApp = path.startsWith("/app") || path.startsWith("/scans");
  return (
    <header className="top">
      <div className="top-inner">
        <Link href="/" className="brand" aria-label="Bulwark home"><BrandMark />Bulwark</Link>
        <nav aria-label="Primary">
          <Link href="/#product">Product</Link>
          <Link href="/#results">Results</Link>
          <Link href="/#scanners">Scanners</Link>
          <Link href="/app" aria-current={inApp ? "page" : undefined}>App</Link>
        </nav>
        <span className="spacer" />
        {!inApp && <Link href="/app" className="btn primary sm">Open app →</Link>}
      </div>
    </header>
  );
}
