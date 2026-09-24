"use client";

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
        </div>
        <div className="app-grid">
          <SubmitForm />
          <RecentScans />
        </div>
      </TokenGate>
    </div>
  );
}
