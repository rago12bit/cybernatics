import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { NotificationSettings } from "@/components/NotificationSettings";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Notifications · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Settings", href: "/app/settings" }, { label: "Notifications" }]}>
        <NotificationSettings />
      </AppShell>
    </TokenGate>
  );
}
