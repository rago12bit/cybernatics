import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ConnectorsScreen } from "@/components/ConnectorsScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Connectors · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Connectors" }]}>
        <ConnectorsScreen />
      </AppShell>
    </TokenGate>
  );
}
