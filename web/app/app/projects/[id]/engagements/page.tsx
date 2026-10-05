import type { Metadata } from "next";
import { AppShell } from "@/components/shell/AppShell";
import { EngagementsScreen } from "@/components/EngagementsScreen";
import { TokenGate } from "@/components/TokenGate";

export const metadata: Metadata = { title: "Engagements · Bulwark" };

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <TokenGate>
      <AppShell
        crumbs={[
          { label: "Projects", href: "/app/projects" },
          { label: "Project", href: `/app/projects/${id}` },
          { label: "Engagements" },
        ]}
      >
        <EngagementsScreen assetId={id} />
      </AppShell>
    </TokenGate>
  );
}
