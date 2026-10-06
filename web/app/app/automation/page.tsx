import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { AutomationScreen } from "@/components/AutomationScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Automation · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Automation" }]}>
        <AutomationScreen />
      </AppShell>
    </TokenGate>
  );
}
