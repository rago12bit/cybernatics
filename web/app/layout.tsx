import type { Metadata } from "next";
import { Geist, JetBrains_Mono } from "next/font/google";
import { connection } from "next/server";
import type { ReactNode } from "react";
import { SiteHeader } from "@/components/site/SiteHeader";
import "./globals.css";

// Self-hosted at build time by next/font (no runtime request to Google; satisfies font-src 'self').
const sans = Geist({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "Bulwark: security scanning without the noise",
  description: "Sandboxed open-source scanners, merged into one report that shows which scanners agree.",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  await connection(); // dynamic rendering so the per-request CSP nonce is applied (see proxy.ts)
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <a href="#main" className="skip">Skip to content</a>
        <SiteHeader />
        <main id="main" tabIndex={-1}>{children}</main>
      </body>
    </html>
  );
}
