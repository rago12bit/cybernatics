import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { EvidenceScreen } from "@/components/EvidenceScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Evidence · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Evidence packs" }]}>
        <EvidenceScreen />
      </AppShell>
    </TokenGate>
  );
}
