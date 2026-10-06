import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { InboxScreen } from "@/components/InboxScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Inbox · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Inbox" }]}>
        <InboxScreen />
      </AppShell>
    </TokenGate>
  );
}
