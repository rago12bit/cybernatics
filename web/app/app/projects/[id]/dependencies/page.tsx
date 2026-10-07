import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { DependenciesView } from "@/components/DependenciesView";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Dependencies · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Dependencies" }]} eyebrow="Project" title="Dependencies">
        <DependenciesView assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
