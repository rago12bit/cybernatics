import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { MyTokens } from "@/components/identity/MyTokens";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "My API tokens · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Settings", href: "/app/settings" }, { label: "My API tokens" }]} eyebrow="Settings" title="My API tokens">
        <MyTokens />
      </AppShell>
    </TokenGate>
  );
}
