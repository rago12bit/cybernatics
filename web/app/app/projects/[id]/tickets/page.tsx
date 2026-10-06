import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { TicketSettingsScreen } from "@/components/TicketSettingsScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Tickets · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Project", href: `/app/projects/${id}` },
          { label: "Tickets" },
        ]}
      >
        <TicketSettingsScreen assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
