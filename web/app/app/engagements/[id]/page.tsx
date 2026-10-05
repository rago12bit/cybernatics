import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { EngagementScreen } from "@/components/EngagementScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Engagement · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Engagement" }]}>
        <EngagementScreen id={id} />
      </AppShell>
    </TokenGate>
  );
}
