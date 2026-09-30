import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ThreatModelEditor } from "@/components/ThreatModelEditor";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Threat model · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Threat model" }]}>
        <ThreatModelEditor assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
