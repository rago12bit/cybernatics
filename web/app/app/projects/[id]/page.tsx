import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { ProjectOverview } from "@/components/ProjectOverview";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Project overview · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }]}>
        <ProjectOverview assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
