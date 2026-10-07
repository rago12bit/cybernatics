import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ReportsScreen } from "@/components/reports/ReportsScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Reports · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Reports" }]}>
        <ReportsScreen />
      </AppShell>
    </TokenGate>
  );
}
