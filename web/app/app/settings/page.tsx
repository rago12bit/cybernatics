import type { Metadata } from "next";
import Link from "next/link";
import { AppShell } from "@/components/shell/AppShell";
import { RetentionSettings } from "@/components/RetentionSettings";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Settings · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Settings" }]} eyebrow="Settings" title="Settings">
        <ul className="settings-links">
          <li><Link href="/app/settings/people">People and access</Link>: who is here, their roles, and roles on business units or projects.</li>
          <li><Link href="/app/settings/sign-in">Sign-in and provisioning</Link>: single sign-on with your identity provider, and SCIM.</li>
          <li><Link href="/app/settings/tokens">My API tokens</Link>: for CI and scripts; they act as you.</li>
          <li><Link href="/app/settings/notifications">Notifications</Link>: what reaches you and the team channels, and when.</li>
        </ul>
        <RetentionSettings />
      </AppShell>
    </TokenGate>
  );
}
