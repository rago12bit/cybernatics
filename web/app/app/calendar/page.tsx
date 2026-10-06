import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { CalendarScreen } from "@/components/CalendarScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Calendar · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Calendar" }]}>
        <CalendarScreen />
      </AppShell>
    </TokenGate>
  );
}
