"use client";

import { RecentScans } from "@/components/RecentScans";
import { SubmitForm } from "@/components/SubmitForm";
import { TokenGate } from "@/components/TokenGate";

export default function Home() {
  return (
    <TokenGate>
      <SubmitForm />
      <RecentScans />
    </TokenGate>
  );
}
