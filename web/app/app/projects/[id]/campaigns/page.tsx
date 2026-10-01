import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { CampaignsView } from "@/components/CampaignsView";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "DAST campaigns · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Campaigns" }]}>
        <CampaignsView assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
