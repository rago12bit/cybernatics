import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { CostDashboard } from "@/components/CostDashboard";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Costs · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Costs" }]}>
        <CostDashboard />
      </AppShell>
    </TokenGate>
  );
}
