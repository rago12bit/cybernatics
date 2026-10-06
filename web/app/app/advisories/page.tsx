import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { AdvisoriesScreen } from "@/components/AdvisoriesScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Advisories · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Advisories" }]}>
        <AdvisoriesScreen />
      </AppShell>
    </TokenGate>
  );
}
