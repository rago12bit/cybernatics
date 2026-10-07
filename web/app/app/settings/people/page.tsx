import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { PeopleScreen } from "@/components/identity/PeopleScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "People and access · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Settings", href: "/app/settings" }, { label: "People and access" }]} eyebrow="Settings" title="People and access">
        <PeopleScreen />
      </AppShell>
    </TokenGate>
  );
}
