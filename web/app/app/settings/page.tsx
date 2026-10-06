import type { Metadata } from "next";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { RetentionSettings } from "@/components/RetentionSettings";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Settings · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Settings" }]}>
        <p>
          <Link href="/app/settings/notifications">Notifications</Link>: what reaches you and the team channels, and when.
        </p>
        <RetentionSettings />
      </AppShell>
    </TokenGate>
  );
}
