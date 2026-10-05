import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { RiskAcceptancesScreen } from "@/components/RiskAcceptancesScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Risk acceptance · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Risk acceptance" }]}>
        <RiskAcceptancesScreen />
      </AppShell>
    </TokenGate>
  );
}
