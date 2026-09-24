import type { Metadata } from "next";
import { connection } from "next/server";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Bulwark",
  description: "Unified security scanning: one report, fewer duplicates, ranked by what matters.",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  await connection(); // dynamic rendering so the per-request CSP nonce is applied (see proxy.ts)
  return (
    <html lang="en">
      <body>
        <header className="top">
          <a href="/" className="brand">Bulwark</a>
          <nav aria-label="Primary">
            <a href="/" aria-current="page">Scans</a>
          </nav>
          <span className="spacer" />
          <span className="muted small">One report, fewer duplicates</span>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
