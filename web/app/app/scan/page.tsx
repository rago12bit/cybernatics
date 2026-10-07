"use client";

import Link from "next/link";
import { RecentScans } from "@/components/RecentScans";
import { SubmitForm } from "@/components/SubmitForm";
import { TokenGate } from "@/components/TokenGate";

/** Scanning, for people whose home is a role home (the shared token's home is this page). */
export default function ScanPage() {
  return (
    <div className="page">
      <TokenGate>
        <div className="app-head">
          <span className="eyebrow">Scans</span>
          <h1>Scan a codebase</h1>
          <p className="small muted">
            <Link href="/app">Back to your home</Link>
          </p>
        </div>
        <div className="app-grid">
          <SubmitForm />
          <RecentScans />
        </div>
      </TokenGate>
    </div>
  );
}
