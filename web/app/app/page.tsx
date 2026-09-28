"use client";

import Link from "next/link";
import { RecentScans } from "@/components/RecentScans";
import { SubmitForm } from "@/components/SubmitForm";
import { TokenGate } from "@/components/TokenGate";

export default function AppHome() {
  return (
    <div className="page">
      <TokenGate>
        <div className="app-head">
          <span className="eyebrow">Scans</span>
          <h1>Scan a codebase</h1>
          <p className="small muted">
            Looking for a project you&apos;ve already scanned? <Link href="/app/projects">Go to Projects</Link> for the
            new overview screen (verdict, fix-first queue, trend — plan §28.1).
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
