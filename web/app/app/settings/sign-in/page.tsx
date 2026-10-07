import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { SignInSettings } from "@/components/identity/SignInSettings";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Sign-in and provisioning · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Settings", href: "/app/settings" }, { label: "Sign-in" }]} eyebrow="Settings" title="Sign-in and provisioning">
        <SignInSettings />
      </AppShell>
    </TokenGate>
  );
}
