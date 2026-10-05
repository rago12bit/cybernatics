import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { MentionsScreen } from "@/components/MentionsScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Mentions · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Mentions" }]}>
        <MentionsScreen />
      </AppShell>
    </TokenGate>
  );
}
