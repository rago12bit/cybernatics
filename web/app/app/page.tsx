"use client";

import Link from "next/link";
import { RecentScans } from "@/components/RecentScans";
import { SubmitForm } from "@/components/SubmitForm";
import { TokenGate } from "@/components/TokenGate";
import { RoleHome } from "@/components/home/RoleHome";

/** A person lands on their role's home (plan §48.2); the shared token -- nobody in particular --
 * and anyone who hasn't picked a role yet see the scan page. */
export default function AppHome() {
  return (
    <div className="page">
      <TokenGate>
        <RoleHome fallback={<ScanHome />} />
      </TokenGate>
    </div>
  );
}

function ScanHome() {
  return (
    <>
        <div className="app-head">
          <span className="eyebrow">Scans</span>
          <h1>Scan a codebase</h1>
          <p className="small muted">
            Looking for a project you&apos;ve already scanned? <Link href="/app/projects">Go to Projects</Link> for its
            verdict, what to fix first, and its trend.
          </p>
        </div>
        <div className="app-grid">
          <SubmitForm />
          <RecentScans />
        </div>
    </>
  );
}
