import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { IssuesTable } from "@/components/IssuesTable";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Issues · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell crumbs={[{ label: "Projects", href: "/app/projects" }, { label: "Issues" }]} eyebrow="Project" title="Issues">
        <IssuesTable assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
