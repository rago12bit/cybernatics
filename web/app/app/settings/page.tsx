import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { RetentionSettings } from "@/components/RetentionSettings";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Settings · Bulwark" };

export default function Page() {
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Settings" }]}>
        <RetentionSettings />
      </AppShell>
    </TokenGate>
  );
}
